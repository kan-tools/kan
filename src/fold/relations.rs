//! Projections over domain relation claims.
//!
//! Relation claims are stored exactly as asserted: directed, attributed, and
//! carrying whatever they cite. Reading them back symmetrically — or
//! transitively, or weighted — is a **projection**, computed on demand and
//! swappable, never something the store has already collapsed. That is this
//! repo's `telos/raw-data-and-projections`, and it is the same rule
//! `docs/SPEC.md` §4.3 applies to identity: the raw `SameAs` witnesses are
//! retained and M(A,B) is derived over them under a viewer-chosen base.
//!
//! Today these projections are flat — an edge either was asserted or was
//! not. Deriving a *magnitude* (how sharply two subjects pull against each
//! other, how hard something blocks) means composing over the witnesses
//! under an enriching base, exactly as §4.3 derives identity confidence.
//! That is issue #72, and it is deliberately not faked here with a stored
//! number: a degree in the data would assert a fold output as input and
//! foreclose every other base.

use std::collections::BTreeSet;

use atproto_dasl::Cid;

use crate::claim::v1::{Claim, ClaimBody, RelationKind, SubjectRef};

/// One asserted relation, kept in the direction it was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edge {
    /// The claim asserting it — the witness, and the route to its `cites`.
    pub cid: Cid,
    pub from: SubjectRef,
    pub to: SubjectRef,
    pub kind: RelationKind,
}

/// Every relation of `kind` asserted anywhere in `claims`, undirected-ness
/// **not** applied: `a → b` and `b → a` remain distinct edges here.
pub fn edges(claims: &[(Cid, Claim)], kind: RelationKind) -> Vec<Edge> {
    claims
        .iter()
        .filter_map(|(cid, claim)| match &claim.content.body {
            ClaimBody::Relation { kind: k, target } if *k == kind => Some(Edge {
                cid: cid.clone(),
                from: claim.content.subject.clone(),
                to: target.clone(),
                kind,
            }),
            _ => None,
        })
        .collect()
}

/// The symmetric projection: every subject `subject` is in tension with,
/// regardless of which side asserted it.
///
/// Tension is symmetric in what it *means* — if A pulls against B then B
/// pulls against A — while the *grounds* for it are perspectival, since two
/// actors can hold the same pair in tension for different reasons. So the
/// assertions stay directed in the store and symmetry is applied here, on
/// read. Collapsing at write time would discard which side observed what,
/// which is precisely the raw data a frames-aware reader needs.
pub fn in_tension_with(claims: &[(Cid, Claim)], subject: &SubjectRef) -> Vec<SubjectRef> {
    let mut seen = BTreeSet::new();
    let mut refs = Vec::new();
    for edge in edges(claims, RelationKind::InTensionWith) {
        let other = if &edge.from == subject {
            edge.to
        } else if &edge.to == subject {
            edge.from
        } else {
            continue;
        };
        // Deduplicated by rendering rather than by `Ord`, which `SubjectRef`
        // does not implement; sorted for the same reason the fold is
        // deterministic everywhere else.
        if seen.insert(format!("{other:?}")) {
            refs.push(other);
        }
    }
    refs.sort_by_key(|r| format!("{r:?}"));
    refs
}

/// Every claim asserting tension between this pair, in either direction —
/// the witnesses behind [`in_tension_with`], and where a reader goes for the
/// *why* (each edge's claim carries its own `cites`).
pub fn tension_witnesses(claims: &[(Cid, Claim)], a: &SubjectRef, b: &SubjectRef) -> Vec<Edge> {
    edges(claims, RelationKind::InTensionWith)
        .into_iter()
        .filter(|e| (&e.from == a && &e.to == b) || (&e.from == b && &e.to == a))
        .collect()
}

/// Walk `Supersedes` forward from `subject` and return the **frontier**: the
/// subjects reachable from it that nothing further supersedes (#116).
///
/// Returns `[subject]` when nothing supersedes it, so callers have one shape
/// for "this is live" and "this was replaced by that".
///
/// **A frontier, not a tip.** A subject superseded by two different subjects
/// has genuinely forked, and answering with one of them would be the store
/// resolving something the claims do not resolve. The fork is visible instead,
/// which is the same call `in_tension_with` makes in refusing to collapse
/// perspectival edges at write time.
///
/// **Cycle-safe.** `a supersedes b supersedes a` is expressible — nothing
/// stops two authors asserting it, and non-destruction means neither
/// assertion can be removed — so the walk tracks what it has seen. A cycle
/// has no frontier by definition; every member is returned, which reports the
/// state rather than hanging or inventing an ordering.
pub fn live_members(claims: &[(Cid, Claim)], subject: &SubjectRef) -> Vec<SubjectRef> {
    let all = edges(claims, RelationKind::Supersedes);
    let mut seen = BTreeSet::new();
    let mut frontier = Vec::new();
    let mut queue = vec![subject.clone()];
    seen.insert(format!("{subject:?}"));

    while let Some(current) = queue.pop() {
        // Everything `current` supersedes points *backward*; what supersedes
        // `current` is what we follow.
        let successors: Vec<&Edge> = all.iter().filter(|e| e.to == current).collect();
        if successors.is_empty() {
            frontier.push(current);
            continue;
        }
        let mut advanced = false;
        for edge in successors {
            if seen.insert(format!("{:?}", edge.from)) {
                queue.push(edge.from.clone());
                advanced = true;
            }
        }
        // Every successor already visited: this sits inside a cycle, and is
        // itself part of the answer.
        if !advanced {
            frontier.push(current);
        }
    }

    frontier.sort_by_key(|r| format!("{r:?}"));
    frontier.dedup_by_key(|r| format!("{r:?}"));
    frontier
}

/// Every subject something supersedes — the retired set, kept readable.
pub fn superseded(claims: &[(Cid, Claim)]) -> Vec<SubjectRef> {
    unique_targets(edges(claims, RelationKind::Supersedes))
}

/// Every subject something refutes: the **refuted register** (#116).
///
/// The point of it being a projection rather than a hand-kept file is that
/// dead claims stay dead without anyone maintaining the list — it is derived
/// from the same claims everything else is, so it cannot drift from them.
pub fn refuted(claims: &[(Cid, Claim)]) -> Vec<SubjectRef> {
    unique_targets(edges(claims, RelationKind::Refutes))
}

/// The claims refuting `subject` — the witnesses behind [`refuted`], and
/// where a reader goes for the substance: each edge's claim carries its own
/// `cites`, which is what names the specific claim refuted.
pub fn refutation_witnesses(claims: &[(Cid, Claim)], subject: &SubjectRef) -> Vec<Edge> {
    edges(claims, RelationKind::Refutes)
        .into_iter()
        .filter(|e| &e.to == subject)
        .collect()
}

/// Deduplicated, deterministically ordered edge targets. Sorting is by
/// rendering rather than by `Ord`, which `SubjectRef` does not implement —
/// the same reason `in_tension_with` does it that way.
fn unique_targets(edges: Vec<Edge>) -> Vec<SubjectRef> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for edge in edges {
        if seen.insert(format!("{:?}", edge.to)) {
            out.push(edge.to);
        }
    }
    out.sort_by_key(|r| format!("{r:?}"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claim::v1::{Anchor, AuthorId, ClaimContent};

    pub(super) fn subject(name: &str) -> SubjectRef {
        SubjectRef::Local(name.to_string())
    }

    pub(super) fn relation(from: &str, to: &str, kind: RelationKind) -> (Cid, Claim) {
        let content = ClaimContent {
            author: AuthorId {
                did: format!("did:key:z{from}{to}"),
                agent: None,
            },
            workspace: Anchor::Workspace("g".into()),
            subject: subject(from),
            body: ClaimBody::Relation {
                kind,
                target: subject(to),
            },
            cites: vec![],
            artifacts: vec![],
            recorded_at: None,
        };
        let cid = crate::cid::content_cid(&content).unwrap();
        (
            cid,
            Claim {
                content,
                sig: vec![],
            },
        )
    }

    #[test]
    fn tension_reads_symmetrically_from_a_directed_assertion() {
        let claims = vec![relation(
            "legibility",
            "enforcement",
            RelationKind::InTensionWith,
        )];

        assert_eq!(
            in_tension_with(&claims, &subject("legibility")),
            vec![subject("enforcement")],
            "the asserting side sees it"
        );
        assert_eq!(
            in_tension_with(&claims, &subject("enforcement")),
            vec![subject("legibility")],
            "and so does the other side, without a second claim"
        );
    }

    #[test]
    fn the_store_keeps_both_directions_distinct() {
        // Two actors assert the same pair from opposite sides, for their own
        // reasons. The projection is symmetric; the raw edges are not merged.
        let claims = vec![
            relation("a", "b", RelationKind::InTensionWith),
            relation("b", "a", RelationKind::InTensionWith),
        ];
        assert_eq!(
            edges(&claims, RelationKind::InTensionWith).len(),
            2,
            "both assertions are retained -- which side observed what is raw data"
        );
        assert_eq!(in_tension_with(&claims, &subject("a")), vec![subject("b")]);
        assert_eq!(
            tension_witnesses(&claims, &subject("a"), &subject("b")).len(),
            2,
            "both are witnesses for the same projected tension"
        );
    }

    #[test]
    fn other_relation_kinds_are_not_swept_in() {
        let claims = vec![
            relation("a", "b", RelationKind::Blocks),
            relation("c", "d", RelationKind::InTensionWith),
        ];
        assert!(in_tension_with(&claims, &subject("a")).is_empty());
        assert_eq!(in_tension_with(&claims, &subject("c")), vec![subject("d")]);
    }

    #[test]
    fn a_subject_with_no_tension_projects_to_nothing() {
        let claims = vec![relation("a", "b", RelationKind::InTensionWith)];
        assert!(in_tension_with(&claims, &subject("unrelated")).is_empty());
    }
}

#[cfg(test)]
mod supersession_tests {
    use super::tests::{relation, subject};
    use super::*;

    fn names(refs: Vec<SubjectRef>) -> Vec<String> {
        refs.iter()
            .map(|r| match r {
                SubjectRef::Local(n) => n.clone(),
                other => format!("{other:?}"),
            })
            .collect()
    }

    #[test]
    fn an_unsuperseded_subject_is_its_own_live_member() {
        let claims = vec![relation("b", "a", RelationKind::Supersedes)];
        assert_eq!(names(live_members(&claims, &subject("b"))), vec!["b"]);
    }

    #[test]
    fn a_chain_walks_forward_to_its_tip() {
        // c supersedes b supersedes a — asking about any member finds c.
        let claims = vec![
            relation("b", "a", RelationKind::Supersedes),
            relation("c", "b", RelationKind::Supersedes),
        ];
        assert_eq!(names(live_members(&claims, &subject("a"))), vec!["c"]);
        assert_eq!(names(live_members(&claims, &subject("b"))), vec!["c"]);
    }

    /// A fork is reported, not resolved. Two subjects superseding the same
    /// one is a thing the claims genuinely say, and picking a winner here
    /// would be the fold deciding what the data left open.
    #[test]
    fn a_forked_chain_returns_every_tip() {
        let claims = vec![
            relation("b", "a", RelationKind::Supersedes),
            relation("c", "a", RelationKind::Supersedes),
        ];
        assert_eq!(names(live_members(&claims, &subject("a"))), vec!["b", "c"]);
    }

    /// Non-destruction means a cycle cannot be deleted once asserted, so the
    /// walk has to survive one rather than assume it away.
    #[test]
    fn a_cycle_terminates_instead_of_hanging() {
        let claims = vec![
            relation("b", "a", RelationKind::Supersedes),
            relation("a", "b", RelationKind::Supersedes),
        ];
        let live = names(live_members(&claims, &subject("a")));
        assert!(!live.is_empty(), "a cycle must still report something");
        assert!(
            live.iter().all(|n| n == "a" || n == "b"),
            "unexpected members: {live:?}"
        );
    }

    #[test]
    fn superseded_lists_the_retired_and_refuted_lists_the_dead() {
        let claims = vec![
            relation("b", "a", RelationKind::Supersedes),
            relation("result", "conjecture", RelationKind::Refutes),
        ];
        assert_eq!(names(superseded(&claims)), vec!["a"]);
        assert_eq!(names(refuted(&claims)), vec!["conjecture"]);
        // The kinds do not leak into each other.
        assert!(refuted(&claims)
            .iter()
            .all(|r| !matches!(r, SubjectRef::Local(n) if n == "a")));
    }

    #[test]
    fn refutation_witnesses_are_the_route_to_the_substance() {
        let claims = vec![
            relation("result", "conjecture", RelationKind::Refutes),
            relation("other", "conjecture", RelationKind::Refutes),
            relation("result", "unrelated", RelationKind::Refutes),
        ];
        let w = refutation_witnesses(&claims, &subject("conjecture"));
        assert_eq!(w.len(), 2, "expected both refutations: {w:?}");
        assert!(w.iter().all(|e| e.to == subject("conjecture")));
    }

    /// Determinism is a property the whole fold is held to, and these are new
    /// entry points into it.
    #[test]
    fn projections_are_order_independent() {
        let a = vec![
            relation("b", "a", RelationKind::Supersedes),
            relation("c", "b", RelationKind::Supersedes),
            relation("x", "a", RelationKind::Refutes),
        ];
        let mut b = a.clone();
        b.reverse();
        assert_eq!(
            names(live_members(&a, &subject("a"))),
            names(live_members(&b, &subject("a")))
        );
        assert_eq!(names(refuted(&a)), names(refuted(&b)));
    }
}

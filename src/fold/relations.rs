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

use crate::claim::{Claim, ClaimBody, RelationKind, SubjectRef};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claim::{Anchor, AuthorId, ClaimContent};

    fn subject(name: &str) -> SubjectRef {
        SubjectRef::Local(name.to_string())
    }

    fn relation(from: &str, to: &str, kind: RelationKind) -> (Cid, Claim) {
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

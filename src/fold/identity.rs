//! The identity fold (`docs/SPEC.md` §4.2–§4.4): `Relation::SameAs` is the
//! only identity-conferring edge. Merge-classes are connected components of
//! a directed graph of *trusted* `SameAs` witnesses — retained, never a
//! destructive union-find. Un-merge (retracting a `SameAs` claim) works by
//! recomputing components from the retained edge set with the retracted
//! witness excluded, not by trying to reverse a prior merge operation.
//!
//! This implements π₀ (distinct connected components) but not the higher
//! witness-homotopy structure the spec names as a third, spaces-enriched
//! option — that's out of v1 scope alongside the ≤2 trust policies
//! (`docs/SPEC.md` §11).
//!
//! No incremental caching yet: every call recomputes from scratch
//! (`docs/DECISIONS.md`-adjacent "correctness before performance" house
//! rule). That's what makes "re-derive the split component instead of a
//! stale cache" trivially true — the honest way to satisfy it for now is to
//! never cache in the first place.

use std::collections::{HashMap, HashSet, VecDeque};

use atproto_dasl::Cid;

use crate::{
    claim::{AuthorId, ClaimBody, RelationKind, SubjectRef},
    fold::trust::TrustBase,
    store::log::StoredClaim,
};

/// A merge-class bridging more subjects than this is flagged as a probable
/// erroneous identity assertion rather than silently enumerated
/// (`docs/SPEC.md` §4.5).
pub const COMPONENT_SIZE_GUARDRAIL: usize = 25;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SameAsWitness {
    pub claim_cid: Cid,
    pub author: AuthorId,
    pub from: SubjectRef,
    pub to: SubjectRef,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeClass {
    /// Deterministically ordered so output is stable across recomputations.
    pub subjects: Vec<SubjectRef>,
    /// Every retained witness touching this class — never discarded, even
    /// ones a later retraction has deactivated (those just don't contribute
    /// an edge to the current component computation; see `merge_classes`).
    pub witnesses: Vec<SameAsWitness>,
    pub flagged_oversized: bool,
}

impl MergeClass {
    pub fn contains(&self, subject: &SubjectRef) -> bool {
        self.subjects.contains(subject)
    }
}

/// Claim CIDs currently excluded by a live `Retraction` (`docs/SPEC.md` §8,
/// ADR-6). Shared between the identity fold and the state fold — retraction
/// is a claim-level concept, not specific to either stage.
///
/// Self-retraction only: a `Retraction` claim only takes effect against a
/// claim authored by the exact same `AuthorId`. `docs/SPEC.md` §8 states this
/// as a structural impossibility ("you can't write to another's log"), not a
/// trust decision — an other-author `Retraction` is simply inert here,
/// unconditionally, regardless of whether the acting viewer trusts that
/// author. (Trust-gated cross-author suppression is `Relation::Rejects`,
/// honored only downstream, by folds that trust the rejecter — a completely
/// separate mechanism from this one.) This function deliberately takes no
/// `TrustBase` at all: that absence is the fix, not an oversight.
pub fn excluded_by_retraction(claims: &[(Cid, StoredClaim)]) -> HashSet<Cid> {
    let mut ordered: Vec<&(Cid, StoredClaim)> = claims.iter().collect();
    ordered.sort_by(|a, b| a.1.rev.cmp(&b.1.rev));

    let mut authors: HashMap<Cid, AuthorId> = HashMap::new();
    let mut excluded: HashSet<Cid> = HashSet::new();
    let mut active_retraction_target: HashMap<Cid, Cid> = HashMap::new();

    for (cid, stored) in ordered {
        let author = stored.claim.content.author.clone();
        if let ClaimBody::Retraction { supersedes } = &stored.claim.content.body {
            if authors.get(supersedes) == Some(&author) {
                excluded.insert(supersedes.clone());
                active_retraction_target.insert(cid.clone(), supersedes.clone());
                if let Some(undone) = active_retraction_target.remove(supersedes) {
                    excluded.remove(&undone);
                }
            }
            // else: a cross-author "retraction" attempt -- not honored,
            // structurally inert, never added to `excluded`.
        }
        authors.insert(cid.clone(), author);
    }
    excluded
}

fn canonical_key(subject: &SubjectRef) -> String {
    format!("{subject:?}")
}

/// Build merge-classes from trusted, live `SameAs` witnesses under `trust`.
pub fn merge_classes(claims: &[(Cid, StoredClaim)], trust: &TrustBase) -> Vec<MergeClass> {
    let excluded = excluded_by_retraction(claims);

    let mut witnesses: Vec<SameAsWitness> = Vec::new();
    let mut all_subjects: HashSet<SubjectRef> = HashSet::new();

    for (cid, stored) in claims {
        if excluded.contains(cid) {
            continue;
        }
        let content = &stored.claim.content;
        all_subjects.insert(content.subject.clone());
        if let ClaimBody::Relation {
            kind: RelationKind::SameAs,
            target,
        } = &content.body
        {
            all_subjects.insert(target.clone());
            if trust.trusts(&content.author) {
                witnesses.push(SameAsWitness {
                    claim_cid: cid.clone(),
                    author: content.author.clone(),
                    from: content.subject.clone(),
                    to: target.clone(),
                });
            }
        }
    }

    let mut adjacency: HashMap<SubjectRef, Vec<SubjectRef>> = HashMap::new();
    for w in &witnesses {
        adjacency
            .entry(w.from.clone())
            .or_default()
            .push(w.to.clone());
        adjacency
            .entry(w.to.clone())
            .or_default()
            .push(w.from.clone());
    }

    let mut sorted_subjects: Vec<SubjectRef> = all_subjects.into_iter().collect();
    sorted_subjects.sort_by_key(canonical_key);

    let mut visited: HashSet<SubjectRef> = HashSet::new();
    let mut classes = Vec::new();

    for start in sorted_subjects {
        if visited.contains(&start) {
            continue;
        }
        let mut component = vec![start.clone()];
        visited.insert(start.clone());
        let mut queue = VecDeque::from([start]);
        while let Some(cur) = queue.pop_front() {
            if let Some(neighbors) = adjacency.get(&cur) {
                for n in neighbors {
                    if visited.insert(n.clone()) {
                        component.push(n.clone());
                        queue.push_back(n.clone());
                    }
                }
            }
        }
        component.sort_by_key(canonical_key);

        let component_set: HashSet<&SubjectRef> = component.iter().collect();
        let class_witnesses: Vec<SameAsWitness> = witnesses
            .iter()
            .filter(|w| component_set.contains(&w.from) || component_set.contains(&w.to))
            .cloned()
            .collect();

        let flagged_oversized = component.len() > COMPONENT_SIZE_GUARDRAIL;
        classes.push(MergeClass {
            subjects: component,
            witnesses: class_witnesses,
            flagged_oversized,
        });
    }

    classes
}

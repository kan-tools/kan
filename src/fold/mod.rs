//! The fold (`docs/SPEC.md` §9) — M2 implements only the trivial local-only
//! path: no identity fold (each `SubjectRef` is its own class; real
//! `SameAs`-witnessed merge-classes are `fold::identity`, landing in M4),
//! and a state fold that's just retraction-exclusion plus chronological
//! ordering — no poset/antichain/contest classification yet (also M4). This
//! is deliberately the "one log, all subjects Local, no SameAs, latest-wins"
//! case from `CLAUDE.md`'s smell test, not a partial version of the full
//! fold.

pub mod trust;

use std::collections::{HashMap, HashSet};

use atproto_dasl::Cid;

use crate::{
    claim::{Claim, ClaimBody, SubjectRef},
    store::log::StoredClaim,
};

/// A subject's live (non-retracted) claims, oldest first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectView {
    pub subject: SubjectRef,
    pub claims: Vec<(Cid, Claim)>,
}

#[derive(Debug, Clone, Default)]
pub struct FoldedView {
    pub subjects: HashMap<SubjectRef, SubjectView>,
}

impl FoldedView {
    pub fn subject(&self, subject: &SubjectRef) -> Option<&SubjectView> {
        self.subjects.get(subject)
    }
}

/// Fold `claims` under `SoloTrust`. Retraction handling: a live `Retraction`
/// excludes its `supersedes` target from the result; retracting a
/// `Retraction` un-excludes that target again (ADR-6's undo mechanism —
/// exclusion composes correctly over the strictly-backward `cites`/
/// `supersedes` DAG with no special-casing).
pub fn fold(claims: Vec<(Cid, StoredClaim)>, _trust: &trust::SoloTrust) -> FoldedView {
    let mut ordered = claims;
    ordered.sort_by(|a, b| a.1.rev.cmp(&b.1.rev));

    let mut live: HashSet<Cid> = HashSet::new();
    let mut excluded: HashSet<Cid> = HashSet::new();
    // Maps a currently-active Retraction's CID to the CID it's suppressing,
    // so a later claim retracting *that* retraction can undo its effect.
    let mut active_retraction_target: HashMap<Cid, Cid> = HashMap::new();

    for (cid, stored) in &ordered {
        live.insert(cid.clone());
        if let ClaimBody::Retraction { supersedes } = &stored.claim.content.body {
            if live.contains(supersedes) {
                live.remove(supersedes);
                excluded.insert(supersedes.clone());
                active_retraction_target.insert(cid.clone(), supersedes.clone());
            }
            if let Some(undone) = active_retraction_target.remove(supersedes) {
                live.insert(undone.clone());
                excluded.remove(&undone);
            }
        }
    }

    let mut subjects: HashMap<SubjectRef, SubjectView> = HashMap::new();
    for (cid, stored) in ordered {
        if !live.contains(&cid) {
            continue;
        }
        let subject = stored.claim.content.subject.clone();
        subjects
            .entry(subject.clone())
            .or_insert_with(|| SubjectView {
                subject,
                claims: Vec::new(),
            })
            .claims
            .push((cid, stored.claim));
    }

    FoldedView { subjects }
}

//! The fold (`docs/SPEC.md` §9): identity fold first, then group each
//! merge-class's live, trusted claims — chronological order, retraction
//! handled once (shared with the identity fold via
//! `identity::excluded_by_retraction`). This stage treats every live claim
//! as a flat append-only log, which is correct for the narrative kinds
//! (`Observation`/`Plan`/`Decision`/…) regardless; `state` (M4b) layers the
//! poset -> antichain -> `Settled | Confirmed | Contested` classification
//! on top, specifically over each class's `Status`-kind claims, since only
//! those assert something that can conflict.

pub mod identity;
pub mod state;
pub mod trust;

use atproto_dasl::Cid;

use crate::{
    claim::{Claim, SubjectRef},
    store::log::StoredClaim,
};
pub use identity::SameAsWitness;
pub use trust::TrustBase;

/// One merge-class's live, trusted claims, oldest first. `subjects` has more
/// than one entry once a trusted `SameAs` has merged distinct `SubjectRef`s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectView {
    pub subjects: Vec<SubjectRef>,
    pub claims: Vec<(Cid, Claim)>,
    /// Set when this class bridges more than
    /// `identity::COMPONENT_SIZE_GUARDRAIL` subjects — a probable erroneous
    /// `SameAs` assertion rather than a real large merge (`docs/SPEC.md`
    /// §4.5). Surfaced, not silently enumerated: callers should warn on
    /// this rather than just rendering a big class as if it were normal.
    pub flagged_oversized: bool,
    /// Every retained `SameAs` witness (author, direction, claim CID) that
    /// justified this merge-class, threaded through from
    /// `identity::MergeClass::witnesses` — `docs/SPEC.md` §4.3's HARD
    /// requirement that "the fold must carry its factorization + witness
    /// set," previously discarded in this exact conversion (REQ-18).
    pub witnesses: Vec<SameAsWitness>,
}

#[derive(Debug, Clone, Default)]
pub struct FoldedView {
    pub classes: Vec<SubjectView>,
}

impl FoldedView {
    pub fn subject(&self, subject: &SubjectRef) -> Option<&SubjectView> {
        self.classes.iter().find(|c| c.subjects.contains(subject))
    }
}

pub fn fold(claims: Vec<(Cid, StoredClaim)>, trust: &TrustBase) -> FoldedView {
    let excluded = identity::excluded_by_retraction(&claims);
    let classes = identity::merge_classes(&claims, trust);

    let mut ordered = claims;
    ordered.sort_by(|a, b| a.1.rev.cmp(&b.1.rev));

    let mut view_classes = Vec::with_capacity(classes.len());
    for class in classes {
        let mut class_claims = Vec::new();
        for (cid, stored) in &ordered {
            if excluded.contains(cid) {
                continue;
            }
            if !trust.trusts(&stored.claim.content.author) {
                continue;
            }
            if class.contains(&stored.claim.content.subject) {
                class_claims.push((cid.clone(), stored.claim.clone()));
            }
        }
        // A class with subjects but zero trusted live claims (every mention
        // of it came from an untrusted author) isn't meaningfully part of
        // this view.
        if !class_claims.is_empty() {
            view_classes.push(SubjectView {
                subjects: class.subjects,
                claims: class_claims,
                flagged_oversized: class.flagged_oversized,
                witnesses: class.witnesses,
            });
        }
    }

    FoldedView {
        classes: view_classes,
    }
}

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
pub mod relations;
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

/// Live claims dropped **solely** because this trust base does not trust
/// their author, counted per subject as the claim itself names it.
///
/// **Why a count, and why separate from `fold`.** `fold` is the pure
/// reduction and stays so; this is a second pure pass over the same inputs,
/// so nothing about the fold's determinism changes. A count is deliberately
/// all a caller gets: handing back the excluded *content* would ask kan to
/// defeat the trust semantics it was just told to apply
/// (`.design/kan-read-contract.md` REQ-6).
///
/// **Why it is keyed on the claim's own subject rather than a merge class.**
/// A subject whose every claim is untrusted forms no class at all — under
/// `Solo`, `merge_classes` filters by trust too — so there is no
/// `SubjectView` to hang the count on, and that is exactly the case where a
/// consumer most needs to know. `1 live claim(s)` and `no such subject` are
/// both complete-looking answers to a partial read; this is what
/// distinguishes *filtered* from *absent*.
///
/// Retracted and rejected claims are not counted: they are excluded for
/// their own reasons, and reporting them here would attribute a retraction
/// to the trust base.
pub fn excluded_by_trust(
    claims: &[(Cid, StoredClaim)],
    trust: &TrustBase,
) -> std::collections::HashMap<SubjectRef, usize> {
    let retracted = identity::excluded_by_retraction(claims);
    let rejected = identity::excluded_by_rejection(claims, trust);

    let mut out = std::collections::HashMap::new();
    for (cid, stored) in claims {
        if retracted.contains(cid) || rejected.contains(cid) {
            continue;
        }
        if trust.trusts(&stored.claim.content.author) {
            continue;
        }
        *out.entry(stored.claim.content.subject.clone()).or_insert(0) += 1;
    }
    out
}

pub fn fold(claims: Vec<(Cid, StoredClaim)>, trust: &TrustBase) -> FoldedView {
    let excluded = identity::excluded_by_retraction(&claims);
    let rejected = identity::excluded_by_rejection(&claims, trust);
    let classes = identity::merge_classes(&claims, trust);

    let mut ordered = claims;
    // `(rev, cid)`, not `rev` alone. `rev` is a per-log TID, so two claims
    // from different logs — once `.claims/` ingestion mixes authors' clocks
    // — can collide, and a stable sort then leaves the winner dependent on
    // input order (the MST/CID order `iter_all` happens to return). The CID
    // tiebreak makes the fold a function of the claim *set*, not its
    // enumeration order (review/full-pass-v0.12 F9); it matches the index's
    // `ORDER BY rev, content_cid`, so both read paths agree.
    ordered.sort_by(|a, b| a.1.rev.cmp(&b.1.rev).then_with(|| a.0.to_string().cmp(&b.0.to_string())));

    let mut view_classes = Vec::with_capacity(classes.len());
    for class in classes {
        let mut class_claims = Vec::new();
        for (cid, stored) in &ordered {
            if excluded.contains(cid) || rejected.contains(cid) {
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

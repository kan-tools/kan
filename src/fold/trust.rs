//! Enrichment bases (`docs/SPEC.md` §4.3). v1's scope fence caps this at two
//! reference enrichments — `Solo` (Bool: any trusted path -> flat merge) and
//! `PeerContested` ([0,1]/quantale: trust-weighted) — never the full
//! witness-homotopy-type enrichment the spec names as a third option; that's
//! out of v1 scope (`docs/SPEC.md` §11 caps trust policies at 2).

use std::collections::HashMap;

use crate::claim::AuthorId;

#[derive(Debug, Clone, PartialEq)]
pub enum TrustBase {
    /// Trust exactly one author. Nothing is ever contested — there's only
    /// one timeline.
    Solo { trusted: AuthorId },
    /// Per-author trust weight in `[0,1]`. An author with no entry (or
    /// weight `0.0`) is untrusted — their claims are invisible under this
    /// enrichment, not merely down-weighted.
    PeerContested { weights: HashMap<AuthorId, f64> },
}

impl TrustBase {
    pub fn solo(trusted: AuthorId) -> Self {
        Self::Solo { trusted }
    }

    /// Whether `author`'s claims are visible at all under this trust base.
    pub fn trusts(&self, author: &AuthorId) -> bool {
        match self {
            TrustBase::Solo { trusted } => author == trusted,
            TrustBase::PeerContested { weights } => weights.get(author).is_some_and(|w| *w > 0.0),
        }
    }
}

//! Enrichment bases (`docs/SPEC.md` §4.3). v1's scope fence caps this at two
//! reference enrichments — `Solo` (Bool: any trusted path -> flat merge) and
//! `PeerContested` ([0,1]/quantale: trust-weighted) — never the full
//! witness-homotopy-type enrichment the spec names as a third option; that's
//! out of v1 scope (`docs/SPEC.md` §11 caps trust policies at 2).
//!
//! `PeerContested` is fully implemented and tested (`tests/state_fold.rs`,
//! `tests/identity_fold.rs`) but intentionally unreachable from the CLI/MCP
//! surface today — every `crate::actions` read hardcodes
//! `Workspace::solo_trust()`. Not an oversight: v1's real scope is "one
//! human, one-or-more local agents" (`docs/HANDOFF.md`), where the human
//! operating the CLI/MCP locally has no occasion to construct a
//! multi-weighted trust policy for themselves — there's no second human to
//! weigh against. A CLI/MCP surface for selecting `PeerContested` (which
//! authors, what weights) is real design work belonging to whatever
//! multi-actor feature actually needs it, not a speculative flag added
//! ahead of a concrete use case.

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

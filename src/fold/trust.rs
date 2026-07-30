//! Enrichment bases (`docs/SPEC.md` §4.3). v1's scope fence caps this at two
//! reference enrichments — `Solo` (Bool: any trusted path -> flat merge) and
//! `PeerContested` ([0,1]/quantale: trust-weighted) — never the full
//! witness-homotopy-type enrichment the spec names as a third option; that's
//! out of v1 scope (`docs/SPEC.md` §11 caps trust policies at 2).
//!
//! `PeerContested` was fully implemented and tested (`tests/state_fold.rs`,
//! `tests/identity_fold.rs`) but unreachable from the CLI/MCP surface until
//! v0.8 (`.design/v0.8-milestone.md` REQ-3): every `crate::actions` read
//! hardcoded `Workspace::solo_trust()`. The concrete use case the old comment
//! here said it was waiting for arrived — process roles in one workspace
//! (#115), where a `Solo` read shows a role only its own claims — so
//! `TrustSpec` below is that surface.
//!
//! **Weights, not a membership set.** An author with no entry is invisible
//! rather than down-weighted, and the consumer driving this (day's frames,
//! `.design/kan-read-contract.md`) expresses a role hierarchy — "verdict
//! claims authoritative only from the director's key" — which is a weighting.
//! A surface accepting only a set of authors would be a narrower thing
//! wearing the same name.

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

/// The literal a `--trust` argument accepts in place of a DID, resolved
/// against the workspace's own identity. Saves a caller shelling out to
/// `kan identity did` just to name itself in its own frame — which the
/// multi-role case (#115) does constantly, since a role almost always wants
/// itself plus its peers.
pub const SELF_ALIAS: &str = "me";

/// One parsed `--trust` argument: who, and how much.
#[derive(Debug, Clone, PartialEq)]
pub struct TrustEntry {
    /// A `did:key:…`, or [`SELF_ALIAS`] for the local identity. Unresolved
    /// here — `fold` knows nothing about which identity is running.
    pub did: String,
    pub weight: f64,
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum SpecError {
    #[error("trust weight in `{spec}` is not a number: {found}")]
    WeightNotNumeric { spec: String, found: String },
    #[error("trust weight {weight} in `{spec}` is outside [0,1]")]
    WeightOutOfRange { spec: String, weight: f64 },
    #[error(
        "`{spec}` does not name an author -- expected `did:key:...`, \
         `did:key:...=<weight>`, or `me`"
    )]
    NotAnAuthor { spec: String },
}

/// Parses `did:key:z...`, `did:key:z...=0.5`, `me`, or `me=0.5`. An omitted
/// weight is `1.0` — full trust, the common case.
///
/// A malformed spec is an error rather than a skipped entry, and that is the
/// point: silently dropping one `--trust` argument would hand back a view
/// narrower than the one asked for, with an exit code saying it succeeded.
/// That is the failure this whole surface exists to end (`ContextJson`'s
/// `omitted_claims` doc, and `.design/kan-read-contract.md` REQ-4).
pub fn parse_entry(spec: &str) -> Result<TrustEntry, SpecError> {
    let (did, weight) = match spec.split_once('=') {
        Some((did, raw)) => {
            let weight: f64 = raw
                .trim()
                .parse()
                .map_err(|_| SpecError::WeightNotNumeric {
                    spec: spec.to_string(),
                    found: raw.to_string(),
                })?;
            if !(0.0..=1.0).contains(&weight) {
                return Err(SpecError::WeightOutOfRange {
                    spec: spec.to_string(),
                    weight,
                });
            }
            (did.trim(), weight)
        }
        None => (spec.trim(), 1.0),
    };

    if did != SELF_ALIAS && !did.starts_with("did:") {
        return Err(SpecError::NotAnAuthor {
            spec: spec.to_string(),
        });
    }
    Ok(TrustEntry {
        did: did.to_string(),
        weight,
    })
}

impl TrustBase {
    pub fn solo(trusted: AuthorId) -> Self {
        Self::Solo { trusted }
    }

    pub fn peer_contested(weights: HashMap<AuthorId, f64>) -> Self {
        Self::PeerContested { weights }
    }

    /// The authors this base names, with their weights, in a stable order
    /// (by DID) so a rendered or serialized view is reproducible. `Solo`
    /// reports its one author at weight `1.0`, so a consumer reads both
    /// variants the same way.
    ///
    /// This exists so a *response* can state the trust base that produced
    /// it. A view that does not say which frame it was folded under is one
    /// a consumer cannot honestly label — it has to assume kan honoured
    /// what it asked for rather than reading that it did
    /// (`.design/kan-read-contract.md` REQ-3).
    pub fn authors(&self) -> Vec<(AuthorId, f64)> {
        let mut out: Vec<(AuthorId, f64)> = match self {
            TrustBase::Solo { trusted } => vec![(trusted.clone(), 1.0)],
            TrustBase::PeerContested { weights } => {
                weights.iter().map(|(a, w)| (a.clone(), *w)).collect()
            }
        };
        out.sort_by(|a, b| a.0.did.cmp(&b.0.did));
        out
    }

    /// `"Solo"` or `"PeerContested"` — the variant name as a stable string
    /// for the machine surface, not a `Debug` rendering.
    pub fn name(&self) -> &'static str {
        match self {
            TrustBase::Solo { .. } => "Solo",
            TrustBase::PeerContested { .. } => "PeerContested",
        }
    }

    /// Whether `author`'s claims are visible at all under this trust base.
    pub fn trusts(&self, author: &AuthorId) -> bool {
        match self {
            TrustBase::Solo { trusted } => author == trusted,
            TrustBase::PeerContested { weights } => weights.get(author).is_some_and(|w| *w > 0.0),
        }
    }
}

//! Enrichment bases (`docs/SPEC.md` §4.3). v1's scope fence caps this at two
//! reference *enrichments* — `Solo` (Bool: any trusted path -> flat merge)
//! and `PeerContested` ([0,1]/quantale: trust-weighted) — never the full
//! witness-homotopy-type enrichment the spec names as a third option; that's
//! out of v1 scope (`docs/SPEC.md` §11).
//!
//! There are **three** `TrustBase` variants, not two, and that is not a
//! breach of the cap: `Local` (the default since v0.11, ADR-83) is not a new
//! enrichment but `PeerContested` populated from "every author in this log".
//! Two enrichments; three ways to build a base over them. The fence counts
//! enrichments (`docs/SPEC.md` §11's own note says so).
//!
//! NOTE: `PeerContested` weights below 1.0 are accepted and validated but
//! not yet folded — `trusts` is membership (`weight > 0.0`), and the
//! magnitude is unused. Weighted composition (§4.3's tropical merge) is a
//! future enrichment; `Workspace::trust_from_detailed` warns when a caller
//! supplies a weight, so the surface does not imply a capability the fold
//! lacks (review/full-pass-v0.12 F6).
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

use crate::claim::v1::AuthorId;

#[derive(Debug, Clone, PartialEq)]
pub enum TrustBase {
    /// Trust exactly one author. Nothing is ever contested — there's only
    /// one timeline.
    Solo { trusted: AuthorId },
    /// Trust every author that has written a claim into `.kan/log` — **the
    /// default** since v0.11 (`.design/identity-surface.md` REQ-1).
    ///
    /// **Why this is the default and `Solo` is not.** `Solo`'s member is
    /// "me", so every default read had to resolve an identity in order to
    /// know whom to trust — which is why a read minted one (#149), why an
    /// upgrade that re-minted took the whole log out of every read (#90),
    /// and why two role identities in one workspace could not see each
    /// other (#121). `Local` is defined over the claim set instead, so a
    /// read needs no identity at all and those stop being separate defects.
    ///
    /// **Membership is computed from the log, never the overlay.**
    ///
    /// Note the level: this makes an author a member or not. It does NOT
    /// keep that author's *`.claims/`-borne* claims out of the view -- a
    /// per-author predicate cannot express that, and v0.11 ships without
    /// it. #164 makes the fold origin-aware in v0.12; until then a
    /// collaborator who has written here can put claims into the default
    /// view via a merged pull request.
    /// The log is what was
    /// written *through* this workspace; the overlay is what *arrived at* it
    /// as a committed `.claims/` file (RQ-2). Foreign claims already arrive
    /// without sync, so folding "everything present" would let a merged pull
    /// request inject a stranger's claims into the maintainer's default
    /// view. The set is therefore computed by `Workspace` from
    /// `Index::log_authors` and carried here, rather than derived from
    /// whatever claims a caller happens to pass to `fold` — `fold` sees log
    /// and overlay claims together and could not tell them apart.
    ///
    /// For a single-author workspace this and `Solo` coincide exactly,
    /// which is what makes the change behavioural rather than a break
    /// (AC-1).
    Local {
        authors: std::collections::HashSet<AuthorId>,
    },
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

/// The literal expanding to every identity this workspace **declared** —
/// resolved by `Workspace`, which is the only layer that knows what a
/// workspace has on disk. `fold` never reads a file.
///
/// **A narrowing since v0.11, not a widening.** ADR-61 made this include the
/// active identity, because omitting it gave the wrong answer to the obvious
/// question — "show me everything this workspace's own identities wrote"
/// would quietly drop the caller's own claims. Under `Local` the *default*
/// answers that question, so `roles` is free to mean exactly what its name
/// says: only the identities somebody declared.
///
/// That is what makes `local` minus `roles` meaningful: the authors present
/// in this log but never declared — the #90/#136 anomaly as data rather than
/// as an absence (`.design/identity-surface.md` RQ-3, REQ-9).
pub const ROLES_ALIAS: &str = "roles";

/// The literal for the default base itself: every author with a claim in
/// `.kan/log`. Spelling it explicitly matters for composition — `--trust
/// local --trust did:key:...` is "everyone who has written here, plus this
/// one stranger", which is otherwise unsayable.
pub const LOCAL_ALIAS: &str = "local";

/// Prefix naming **one** declared role: `role:director`.
///
/// Roles are declared with a human name, and the workspace's own
/// `RoleDeclaration` claims are the only binding from that name to a
/// `did:key:...`. Without this, framing a read around one role means pasting a
/// 56-character DID that the workspace already knows the name of.
///
/// *Said `.kan/roles` until v0.12, which is the drift class REQ-3's own
/// architecture note exists to catch: prose describing a mechanism that has
/// been replaced. A first cold review swept it out of `undeclared_log_authors`
/// and a second found it still here, on the constant this milestone
/// re-implemented.*
pub const ROLE_PREFIX: &str = "role:";

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
         `did:key:...=<weight>`, `me`, `local`, `roles`, or `role:<name>`"
    )]
    NotAnAuthor { spec: String },
    #[error(
        "`{spec}`: `{alias}` expands to a set of authors and takes no weight. \
         Name the DIDs individually to weight them differently."
    )]
    SetTakesNoWeight { spec: String, alias: String },
    #[error("`{spec}` names no role. Declared roles: {declared}")]
    NoSuchRole { spec: String, declared: String },
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

    // The set-valued aliases are resolved by `Workspace` before they ever
    // reach here, so seeing one at this point means it arrived with a weight
    // (`roles=0.5`), which has no meaning: they expand to a set, not to one
    // author.
    for alias in [ROLES_ALIAS, LOCAL_ALIAS] {
        if did == alias {
            return Err(SpecError::SetTakesNoWeight {
                spec: spec.to_string(),
                alias: alias.to_string(),
            });
        }
    }
    if did.starts_with(ROLE_PREFIX) {
        // Also `Workspace`'s to resolve -- it is the only layer that can see
        // the log the declarations live in -- but a weight on it is
        // meaningful, since it names exactly one author.
        return Ok(TrustEntry {
            did: did.to_string(),
            weight,
        });
    }
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

    /// Every author that has written into this workspace's log.
    pub fn local(authors: impl IntoIterator<Item = AuthorId>) -> Self {
        Self::Local {
            authors: authors.into_iter().collect(),
        }
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
    /// `Local` reports every log author at weight `1.0`, exactly as `Solo`
    /// reports its single author, so the envelope shape is unchanged and a
    /// consumer reads all three variants the same way
    /// (`.design/identity-surface.md` RQ-4).
    pub fn authors(&self) -> Vec<(AuthorId, f64)> {
        let mut out: Vec<(AuthorId, f64)> = match self {
            TrustBase::Solo { trusted } => vec![(trusted.clone(), 1.0)],
            TrustBase::Local { authors } => authors.iter().map(|a| (a.clone(), 1.0)).collect(),
            TrustBase::PeerContested { weights } => {
                weights.iter().map(|(a, w)| (a.clone(), *w)).collect()
            }
        };
        // Sorted on the whole `AuthorId`, not just the DID. Both `Local` and
        // `PeerContested` collect out of a hash container, whose iteration
        // order is not stable between runs, and a DID-only comparison leaves
        // two legacy `agent` variants of one DID tied — so a rendered or
        // serialized view could reorder them run to run for no reason a
        // reader could see.
        out.sort_by(|a, b| (&a.0.did, &a.0.agent).cmp(&(&b.0.did, &b.0.agent)));
        out
    }

    /// `"Solo"`, `"Local"` or `"PeerContested"` — the variant name as a
    /// stable string for the machine surface, not a `Debug` rendering.
    pub fn name(&self) -> &'static str {
        match self {
            TrustBase::Solo { .. } => "Solo",
            TrustBase::Local { .. } => "Local",
            TrustBase::PeerContested { .. } => "PeerContested",
        }
    }

    /// Whether `author`'s claims are visible at all under this trust base.
    pub fn trusts(&self, author: &AuthorId) -> bool {
        match self {
            TrustBase::Solo { trusted } => author == trusted,
            // Whole-`AuthorId` membership, so a legacy `agent: Some(h)`
            // author is trusted for having written here rather than for
            // resembling a DID that did (REQ-7).
            TrustBase::Local { authors } => authors.contains(author),
            TrustBase::PeerContested { weights } => weights.get(author).is_some_and(|w| *w > 0.0),
        }
    }
}

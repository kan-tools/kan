//! RFC 1 identity judgments and compatibility evaluation.
//!
//! This module is the compatibility-first seam between kan's legacy
//! repository-local `did:key` claims and RFC 1's identity system. It does not
//! resolve identity or governance history, select a signer, or write state.
//! Instead it gives those future resolvers a closed vocabulary and composes
//! their evidence using RFC 1's ordered admission table.

use serde::{Deserialize, Serialize};

use crate::{claim::Claim, fold::TrustBase};

pub mod control;

/// Whether the claim's bytes and exact signing authority authenticate it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CryptographicValidity {
    Valid,
    Invalid,
    Unsupported,
    Unknown,
}

/// Standing of the exact identity state cited by an act.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IdentityStateStanding {
    Active,
    Superseded,
    Contested,
    Unknown,
    Static,
}

/// Whether an authentic act was authorized to reach this repository scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RepositoryAdmission {
    Admitted,
    Unadmitted,
    Contested,
    Unknown,
    NotApplicable,
}

/// The consumer-selected fold-time treatment of authentic material.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ViewTrust {
    Included,
    Excluded,
    Weighted(f64),
}

/// The four judgments every RFC 1 structured claim read keeps distinct.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimJudgments {
    pub cryptographic_validity: CryptographicValidity,
    pub identity_state_standing: IdentityStateStanding,
    pub repository_admission: RepositoryAdmission,
    pub view_trust: ViewTrust,
}

/// Result of resolving repository governance evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovernanceResolution {
    Active,
    Invalid,
    Unsupported,
    UnknownHistory,
    Contested,
}

/// Whether admission required a trusted instant and, if so, whether one was
/// supplied. Author-attested claim time is not trusted time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustedTime {
    NotRequired,
    Available,
    Unavailable,
}

/// Effect of all revocations that could cover the evaluated capability path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationStanding {
    Clear,
    Unknown,
    Contested,
}

/// Completeness and result of capability-path evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityEvidence {
    Missing,
    CompleteWithoutCoveringPath,
    CompleteWithCoveringPath,
}

/// Facts consumed by RFC 1's ordered repository-admission table.
///
/// Upstream resolvers establish these facts; this reducer deliberately does
/// not fetch, infer, or mutate anything. `identity_checkpoint` means the actor
/// directly cited a `did:kan` genesis or recovery event, which can control
/// later identity state but cannot itself exercise repository reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionFacts {
    pub repository_scoped: bool,
    pub cryptographic_validity: CryptographicValidity,
    pub identity_standing: IdentityStateStanding,
    pub identity_checkpoint: bool,
    pub governance: GovernanceResolution,
    pub trusted_time: TrustedTime,
    pub revocation: RevocationStanding,
    pub capability: CapabilityEvidence,
}

/// Apply RFC 1's repository-admission decision table in normative order.
pub fn repository_admission(facts: AdmissionFacts) -> RepositoryAdmission {
    if !facts.repository_scoped {
        return RepositoryAdmission::NotApplicable;
    }

    match facts.cryptographic_validity {
        CryptographicValidity::Invalid => return RepositoryAdmission::Unadmitted,
        CryptographicValidity::Unsupported | CryptographicValidity::Unknown => {
            return RepositoryAdmission::Unknown;
        }
        CryptographicValidity::Valid => {}
    }

    match facts.identity_standing {
        IdentityStateStanding::Unknown => return RepositoryAdmission::Unknown,
        IdentityStateStanding::Contested => return RepositoryAdmission::Contested,
        IdentityStateStanding::Active
        | IdentityStateStanding::Superseded
        | IdentityStateStanding::Static => {}
    }

    if facts.identity_checkpoint || facts.identity_standing == IdentityStateStanding::Superseded {
        return RepositoryAdmission::Unadmitted;
    }

    match facts.governance {
        GovernanceResolution::UnknownHistory | GovernanceResolution::Unsupported => {
            return RepositoryAdmission::Unknown;
        }
        GovernanceResolution::Contested => return RepositoryAdmission::Contested,
        // Invalid governance cannot confer reach. It is a negative result,
        // not missing evidence, so fail closed without calling it unknown.
        GovernanceResolution::Invalid => return RepositoryAdmission::Unadmitted,
        GovernanceResolution::Active => {}
    }

    if facts.trusted_time == TrustedTime::Unavailable {
        return RepositoryAdmission::Unknown;
    }

    match facts.revocation {
        RevocationStanding::Unknown => return RepositoryAdmission::Unknown,
        RevocationStanding::Contested => return RepositoryAdmission::Contested,
        RevocationStanding::Clear => {}
    }

    match facts.capability {
        CapabilityEvidence::Missing => RepositoryAdmission::Unknown,
        CapabilityEvidence::CompleteWithoutCoveringPath => RepositoryAdmission::Unadmitted,
        CapabilityEvidence::CompleteWithCoveringPath => RepositoryAdmission::Admitted,
    }
}

/// Evaluate a preserved pre-RFC1 claim without inventing modern identity or
/// governance evidence.
///
/// Legacy claims sign their content CID with the `AuthorId.did` key and cite
/// no identity version. A supported `did:key` therefore has static standing.
/// The legacy workspace anchor is repository-scoped, but it is not RFC 1
/// repository inception or governance evidence, so a valid legacy claim's
/// admission is honestly `unknown`. This classification does not alter the
/// existing fold; it makes the compatibility state available to later typed
/// read surfaces.
pub fn evaluate_legacy_claim(claim: &Claim, trust: &TrustBase) -> ClaimJudgments {
    let did = &claim.content.author.did;
    let (cryptographic_validity, identity_state_standing) = if did.starts_with("did:key:") {
        match atrium_crypto::did::parse_did_key(did) {
            Ok((atrium_crypto::Algorithm::P256, _)) => {
                let validity = crate::cid::content_cid(&claim.content)
                    .ok()
                    .filter(|cid| crate::sign::verify(did, &cid.to_bytes(), &claim.sig))
                    .map_or(CryptographicValidity::Invalid, |_| {
                        CryptographicValidity::Valid
                    });
                (validity, IdentityStateStanding::Static)
            }
            // RFC 1 does not admit kan's historical secp256k1 support, and
            // the current crypto dependency cannot yet verify RFC 1's
            // Ed25519 did:key form. Preserve either as unsupported rather
            // than pretending its signature is bad.
            Ok((atrium_crypto::Algorithm::Secp256k1, _))
            | Err(atrium_crypto::Error::UnsupportedMultikeyType) => (
                CryptographicValidity::Unsupported,
                IdentityStateStanding::Unknown,
            ),
            Err(_) => (
                CryptographicValidity::Invalid,
                IdentityStateStanding::Unknown,
            ),
        }
    } else if matches!(did_method(did), Some("kan" | "plc" | "web")) {
        (
            CryptographicValidity::Unknown,
            IdentityStateStanding::Unknown,
        )
    } else if did_method(did).is_some() {
        (
            CryptographicValidity::Unsupported,
            IdentityStateStanding::Unknown,
        )
    } else {
        (
            CryptographicValidity::Invalid,
            IdentityStateStanding::Unknown,
        )
    };

    let repository_admission = repository_admission(AdmissionFacts {
        repository_scoped: true,
        cryptographic_validity,
        identity_standing: identity_state_standing,
        identity_checkpoint: false,
        governance: GovernanceResolution::UnknownHistory,
        trusted_time: TrustedTime::NotRequired,
        revocation: RevocationStanding::Clear,
        capability: CapabilityEvidence::Missing,
    });

    let view_trust = trust
        .authors()
        .into_iter()
        .find_map(|(author, weight)| (author == claim.content.author).then_some(weight))
        .map_or(ViewTrust::Excluded, |weight| {
            if weight == 1.0 {
                ViewTrust::Included
            } else if weight <= 0.0 {
                ViewTrust::Excluded
            } else {
                ViewTrust::Weighted(weight)
            }
        });

    ClaimJudgments {
        cryptographic_validity,
        identity_state_standing,
        repository_admission,
        view_trust,
    }
}

fn did_method(did: &str) -> Option<&str> {
    let rest = did.strip_prefix("did:")?;
    let (method, identifier) = rest.split_once(':')?;
    (!method.is_empty() && !identifier.is_empty()).then_some(method)
}

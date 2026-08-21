//! Mixed-codec read projection without rewriting either signed source shape.

use atproto_dasl::Cid;

use super::{
    codec::{DecodedClaim, DecodedRecord, PreservedClaim, SupportedClaim, V1_CODEC, V2_CODEC},
    v1, Claim, ClaimBody, SubjectPath,
};
use crate::{
    fold::TrustBase,
    identity::{
        evaluate_legacy_claim, scope_inception::ScopeId, ClaimJudgments, CryptographicValidity,
        IdentityStateStanding, ScopeAdmission, ViewTrust,
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum ClaimSource {
    V1(v1::Claim),
    Claim(Claim),
    Unsupported(PreservedClaim),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimSubject<'a> {
    V1(&'a v1::SubjectRef),
    Claim {
        scope: ScopeId,
        subject: &'a SubjectPath,
    },
}

#[derive(Debug, Clone, Copy)]
pub enum ClaimBodyRef<'a> {
    V1(&'a v1::ClaimBody),
    Claim(&'a ClaimBody),
}

/// One mixed-codec record plus the four RFC 1 judgments under which it was
/// read. Source bytes remain typed and available; judgments are a projection
/// and never become part of the signed claim.
#[derive(Debug, Clone, PartialEq)]
pub struct ClaimView {
    claim_id: Cid,
    rev: String,
    source: ClaimSource,
    judgments: ClaimJudgments,
}

impl ClaimView {
    pub fn claim_id(&self) -> &Cid {
        &self.claim_id
    }

    pub fn rev(&self) -> &str {
        &self.rev
    }

    pub fn source(&self) -> &ClaimSource {
        &self.source
    }

    pub fn judgments(&self) -> ClaimJudgments {
        self.judgments
    }

    pub fn codec(&self) -> &str {
        match &self.source {
            ClaimSource::V1(_) => V1_CODEC,
            ClaimSource::Claim(_) => V2_CODEC,
            ClaimSource::Unsupported(source) => source.codec(),
        }
    }

    pub fn principal(&self) -> Option<&str> {
        match &self.source {
            ClaimSource::V1(claim) => Some(&claim.content.author.did),
            ClaimSource::Claim(claim) => Some(claim.content().author().principal()),
            ClaimSource::Unsupported(_) => None,
        }
    }

    pub fn subject(&self) -> Option<ClaimSubject<'_>> {
        match &self.source {
            ClaimSource::V1(claim) => Some(ClaimSubject::V1(&claim.content.subject)),
            ClaimSource::Claim(claim) => Some(ClaimSubject::Claim {
                scope: claim.content().scope(),
                subject: claim.content().subject(),
            }),
            ClaimSource::Unsupported(_) => None,
        }
    }

    pub fn body(&self) -> Option<ClaimBodyRef<'_>> {
        match &self.source {
            ClaimSource::V1(claim) => Some(ClaimBodyRef::V1(&claim.content.body)),
            ClaimSource::Claim(claim) => Some(ClaimBodyRef::Claim(claim.content().body())),
            ClaimSource::Unsupported(_) => None,
        }
    }
}

/// Project verified decoder output into source-preserving read views. Legacy
/// judgments are computed by the compatibility rule. Current admission and
/// trust require evidence outside the codec, so the caller supplies them
/// explicitly; contradicting the decoder's successful signature check is a
/// closed error rather than an inconsistent view.
pub fn project(
    records: impl IntoIterator<Item = DecodedRecord>,
    legacy_trust: &TrustBase,
    mut current_judgments: impl FnMut(&Claim) -> ClaimJudgments,
) -> Result<Vec<ClaimView>, Error> {
    records
        .into_iter()
        .map(|record| {
            let rev = record.rev;
            match record.claim {
                DecodedClaim::Supported(SupportedClaim::V1(claim)) => {
                    let claim_id = crate::cid::content_cid(&claim.content)?;
                    let judgments = evaluate_legacy_claim(&claim, legacy_trust);
                    Ok(ClaimView {
                        claim_id,
                        rev,
                        source: ClaimSource::V1(claim),
                        judgments,
                    })
                }
                DecodedClaim::Supported(SupportedClaim::Claim(claim)) => {
                    let claim_id = claim.id()?.cid().clone();
                    let judgments = current_judgments(&claim);
                    if judgments.cryptographic_validity != CryptographicValidity::Valid {
                        return Err(Error::ContradictoryCurrentValidity(
                            judgments.cryptographic_validity,
                        ));
                    }
                    Ok(ClaimView {
                        claim_id,
                        rev,
                        source: ClaimSource::Claim(claim),
                        judgments,
                    })
                }
                DecodedClaim::Unsupported(source) => Ok(ClaimView {
                    claim_id: source.claim_id().clone(),
                    rev,
                    source: ClaimSource::Unsupported(source),
                    judgments: ClaimJudgments {
                        cryptographic_validity: CryptographicValidity::Unsupported,
                        identity_state_standing: IdentityStateStanding::Unknown,
                        scope_admission: ScopeAdmission::Unknown,
                        view_trust: ViewTrust::Excluded,
                    },
                }),
            }
        })
        .collect()
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Cid(#[from] crate::cid::Error),
    #[error(transparent)]
    Claim(#[from] super::Error),
    #[error(
        "current claim decoder verified the signature, but the supplied read judgments called it {0:?}"
    )]
    ContradictoryCurrentValidity(CryptographicValidity),
}

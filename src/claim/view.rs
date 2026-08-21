//! Mixed-codec read projection without rewriting either signed source shape.

use std::collections::HashMap;

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

/// Trust keys preserve the authorship ontology of the source codec. A v1
/// composite author is never collapsed to its DID, and a current principal is
/// never represented as a synthetic v1 `AuthorId`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ClaimAuthor {
    V1(v1::AuthorId),
    Principal(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClaimTrustBase {
    weights: HashMap<ClaimAuthor, f64>,
}

impl ClaimTrustBase {
    pub fn new(entries: impl IntoIterator<Item = (ClaimAuthor, f64)>) -> Result<Self, Error> {
        let mut weights = HashMap::new();
        for (author, weight) in entries {
            if !weight.is_finite() || !(0.0..=1.0).contains(&weight) {
                return Err(Error::TrustWeight(weight));
            }
            if weights.insert(author.clone(), weight).is_some() {
                return Err(Error::DuplicateTrustAuthor(author));
            }
        }
        Ok(Self { weights })
    }

    pub fn local(authors: impl IntoIterator<Item = ClaimAuthor>) -> Self {
        Self {
            weights: authors.into_iter().map(|author| (author, 1.0)).collect(),
        }
    }

    fn view_trust(&self, author: &ClaimAuthor) -> ViewTrust {
        self.weights
            .get(author)
            .copied()
            .map_or(ViewTrust::Excluded, |weight| {
                if weight == 1.0 {
                    ViewTrust::Included
                } else if weight == 0.0 {
                    ViewTrust::Excluded
                } else {
                    ViewTrust::Weighted(weight)
                }
            })
    }
}

/// Current identity and governance evaluation supplied by resolvers outside
/// the codec. Cryptographic validity comes from successful decoding and view
/// trust comes from `ClaimTrustBase`, so neither can be contradicted here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CurrentEvaluation {
    pub identity_state_standing: IdentityStateStanding,
    pub scope_admission: ScopeAdmission,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimSubject<'a> {
    V1(&'a v1::SubjectRef),
    Claim {
        scope: ScopeId,
        subject: &'a SubjectPath,
    },
}

/// Owned fold key. A caller may explicitly map historical local paths into
/// an activated scope; without that input they remain visibly v1-local.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ClaimSubjectId {
    V1Local(v1::Rkey),
    V1Anchor(v1::Anchor),
    Scoped { scope: ScopeId, path: String },
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

    pub fn author(&self) -> Option<ClaimAuthor> {
        match &self.source {
            ClaimSource::V1(claim) => Some(ClaimAuthor::V1(claim.content.author.clone())),
            ClaimSource::Claim(claim) => Some(ClaimAuthor::Principal(
                claim.content().author().principal().to_string(),
            )),
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

    pub fn subject_id(&self, legacy_scope: Option<ScopeId>) -> Option<ClaimSubjectId> {
        match &self.source {
            ClaimSource::V1(claim) => match &claim.content.subject {
                v1::SubjectRef::Local(path) => Some(match legacy_scope {
                    Some(scope) => ClaimSubjectId::Scoped {
                        scope,
                        path: path.clone(),
                    },
                    None => ClaimSubjectId::V1Local(path.clone()),
                }),
                v1::SubjectRef::Anchor(anchor) => Some(ClaimSubjectId::V1Anchor(anchor.clone())),
            },
            ClaimSource::Claim(claim) => Some(ClaimSubjectId::Scoped {
                scope: claim.content().scope(),
                path: claim.content().subject().as_str().to_string(),
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
/// judgments are computed by the compatibility rule. Current identity
/// standing and admission come from resolvers; validity comes from decoding;
/// trust comes only from the selected mixed-author frame.
pub fn project(
    records: impl IntoIterator<Item = DecodedRecord>,
    trust: &ClaimTrustBase,
    mut current_evaluation: impl FnMut(&Claim) -> CurrentEvaluation,
) -> Result<Vec<ClaimView>, Error> {
    records
        .into_iter()
        .map(|record| {
            let rev = record.rev;
            match record.claim {
                DecodedClaim::Supported(SupportedClaim::V1(claim)) => {
                    let claim_id = crate::cid::content_cid(&claim.content)?;
                    let mut judgments = evaluate_legacy_claim(
                        &claim,
                        &TrustBase::solo(claim.content.author.clone()),
                    );
                    judgments.view_trust =
                        trust.view_trust(&ClaimAuthor::V1(claim.content.author.clone()));
                    Ok(ClaimView {
                        claim_id,
                        rev,
                        source: ClaimSource::V1(claim),
                        judgments,
                    })
                }
                DecodedClaim::Supported(SupportedClaim::Claim(claim)) => {
                    let claim_id = claim.id()?.cid().clone();
                    let evaluation = current_evaluation(&claim);
                    let author =
                        ClaimAuthor::Principal(claim.content().author().principal().to_string());
                    let judgments = ClaimJudgments {
                        cryptographic_validity: CryptographicValidity::Valid,
                        identity_state_standing: evaluation.identity_state_standing,
                        scope_admission: evaluation.scope_admission,
                        view_trust: trust.view_trust(&author),
                    };
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
    #[error("claim trust weight {0} is outside [0,1]")]
    TrustWeight(f64),
    #[error("claim trust frame names {0:?} more than once")]
    DuplicateTrustAuthor(ClaimAuthor),
}

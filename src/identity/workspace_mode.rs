//! Read-only classification of the claim writer a workspace may expose.

use std::path::{Path, PathBuf};

use crate::{
    identity::{scope_store::ScopeIdentityStore, system::ResolvedSystemActor},
    store::log::Log,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyWorkspaceEvidence {
    claim_count: usize,
    principal: Option<String>,
}

impl LegacyWorkspaceEvidence {
    pub fn claim_count(&self) -> usize {
        self.claim_count
    }

    pub fn principal(&self) -> Option<&str> {
        self.principal.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitializationDiagnostic {
    PreReleaseRepositoryState { path: PathBuf },
    PartialScopeState { path: PathBuf },
    SystemIdentityUnavailable { governance_roots: Vec<String> },
    ScopeVerificationFailed { message: String },
    LegacyIdentityUnavailable { evidence: String },
    LogWithoutSupportedV1Claims,
}

#[derive(Debug, Clone, PartialEq)]
pub enum WorkspaceClaimMode {
    Uninitialized,
    V1 {
        evidence: LegacyWorkspaceEvidence,
    },
    Claim {
        scope: Box<super::scope_store::VerifiedScope>,
    },
    Incomplete {
        diagnostics: Vec<InitializationDiagnostic>,
    },
}

/// Classify without creating, repairing, or selecting a writer. A verified
/// scope always wins over historical v1 evidence; partial scope state never
/// falls back to v1.
pub async fn classify(
    root: &Path,
    log: &mut Log,
    actor: Option<&ResolvedSystemActor>,
) -> Result<WorkspaceClaimMode, Error> {
    let kan_dir = root.join(".kan");
    let pre_release = kan_dir.join("repository");
    if exists(&pre_release)? {
        return Ok(WorkspaceClaimMode::Incomplete {
            diagnostics: vec![InitializationDiagnostic::PreReleaseRepositoryState {
                path: pre_release,
            }],
        });
    }

    let scope_dir = kan_dir.join("scope");
    if exists(&scope_dir)? {
        let metadata = std::fs::symlink_metadata(&scope_dir)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Ok(WorkspaceClaimMode::Incomplete {
                diagnostics: vec![InitializationDiagnostic::PartialScopeState { path: scope_dir }],
            });
        }
        let store = ScopeIdentityStore::at(&scope_dir);
        let installed = match store.read() {
            Ok(None) => {
                return Ok(WorkspaceClaimMode::Incomplete {
                    diagnostics: vec![InitializationDiagnostic::PartialScopeState {
                        path: scope_dir,
                    }],
                })
            }
            Err(error) => {
                return Ok(WorkspaceClaimMode::Incomplete {
                    diagnostics: vec![InitializationDiagnostic::ScopeVerificationFailed {
                        message: error.to_string(),
                    }],
                })
            }
            Ok(Some(installed)) => installed,
        };
        let Some(actor) = actor else {
            return Ok(WorkspaceClaimMode::Incomplete {
                diagnostics: vec![InitializationDiagnostic::SystemIdentityUnavailable {
                    governance_roots: installed.inception.governance_roots,
                }],
            });
        };
        return match store.read_verified_did_kan(actor.state()) {
            Ok(Some(scope)) => Ok(WorkspaceClaimMode::Claim {
                scope: Box::new(scope),
            }),
            Ok(None) => Ok(WorkspaceClaimMode::Incomplete {
                diagnostics: vec![InitializationDiagnostic::PartialScopeState { path: scope_dir }],
            }),
            Err(error) => Ok(WorkspaceClaimMode::Incomplete {
                diagnostics: vec![InitializationDiagnostic::ScopeVerificationFailed {
                    message: error.to_string(),
                }],
            }),
        };
    }

    let claims = log.iter_all().await?;
    let claim_count = claims.len();
    let identity_evidence = crate::sign::identity_evidence(&kan_dir);
    let principal = match crate::sign::workspace_identity(&kan_dir) {
        Ok(identity) => identity.map(|identity| identity.did().to_string()),
        Err(error) if identity_evidence.is_some() => {
            return Ok(WorkspaceClaimMode::Incomplete {
                diagnostics: vec![InitializationDiagnostic::LegacyIdentityUnavailable {
                    evidence: format!("{}: {error}", identity_evidence.unwrap_or_default()),
                }],
            })
        }
        Err(error) => return Err(error.into()),
    };
    if claim_count > 0 || principal.is_some() {
        return Ok(WorkspaceClaimMode::V1 {
            evidence: LegacyWorkspaceEvidence {
                claim_count,
                principal,
            },
        });
    }
    if let Some(evidence) = identity_evidence {
        return Ok(WorkspaceClaimMode::Incomplete {
            diagnostics: vec![InitializationDiagnostic::LegacyIdentityUnavailable {
                evidence: evidence.to_string(),
            }],
        });
    }
    if log.current_root().is_some() {
        return Ok(WorkspaceClaimMode::Incomplete {
            diagnostics: vec![InitializationDiagnostic::LogWithoutSupportedV1Claims],
        });
    }
    Ok(WorkspaceClaimMode::Uninitialized)
}

fn exists(path: &Path) -> Result<bool, std::io::Error> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Log(#[from] crate::store::log::Error),
    #[error(transparent)]
    Sign(#[from] crate::sign::Error),
}

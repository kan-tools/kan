//! RFC 1 current claim-author identity and exact-state signature verification.
//!
//! This module deliberately implements the normative `Author` value before
//! changing claim storage. Legacy `AuthorId` bytes remain owned by
//! `crate::claim`; current claim content and migration can now depend on one
//! closed author shape without making a role or legacy agent representable.

use atproto_dasl::Cid;
use serde::{Deserialize, Serialize};

use super::{
    control::{verify_resolved_method_signature, IdentityVersion},
    did_kan::{validate_did, validate_did_url, VerificationPurpose},
    did_kan_update::ResolvedDidKanState,
    CryptographicValidity,
};

/// Stable principal plus the exact method and identity state used to speak.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, try_from = "AuthorWire")]
pub struct Author {
    principal: String,
    verification_method: String,
    identity_version: IdentityVersion,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AuthorWire {
    principal: String,
    verification_method: String,
    identity_version: IdentityVersion,
}

impl TryFrom<AuthorWire> for Author {
    type Error = Error;

    fn try_from(value: AuthorWire) -> Result<Self, Self::Error> {
        Self::new(
            value.principal,
            value.verification_method,
            value.identity_version,
        )
    }
}

impl Author {
    pub fn new(
        principal: String,
        verification_method: String,
        identity_version: IdentityVersion,
    ) -> Result<Self, Error> {
        let author = Self {
            principal,
            verification_method,
            identity_version,
        };
        author.validate()?;
        Ok(author)
    }

    pub fn validate(&self) -> Result<(), Error> {
        validate_did(&self.principal)?;
        validate_did_url(&self.verification_method)?;
        let method_principal = self
            .verification_method
            .split_once('#')
            .map(|(did, _)| did)
            .ok_or_else(|| Error::MethodPrincipalMismatch {
                principal: self.principal.clone(),
                method: self.verification_method.clone(),
            })?;
        if method_principal != self.principal {
            return Err(Error::MethodPrincipalMismatch {
                principal: self.principal.clone(),
                method: self.verification_method.clone(),
            });
        }
        let expected = match self.principal.split(':').nth(1) {
            Some("key") => "static",
            Some("kan") => "event",
            Some("plc") => "versionId",
            Some("web") => "documentCid",
            _ => return Err(Error::UnsupportedPrincipal(self.principal.clone())),
        };
        let actual = identity_version_kind(&self.identity_version);
        if actual != expected {
            return Err(Error::IdentityVersionKind {
                principal: self.principal.clone(),
                expected,
                actual,
            });
        }
        if matches!(self.identity_version, IdentityVersion::Static) {
            let fingerprint = self
                .principal
                .strip_prefix("did:key:")
                .ok_or_else(|| Error::UnsupportedPrincipal(self.principal.clone()))?;
            if self.verification_method != format!("{}#{fingerprint}", self.principal) {
                return Err(Error::StaticMethod(self.verification_method.clone()));
            }
        }
        Ok(())
    }

    pub fn principal(&self) -> &str {
        &self.principal
    }

    pub fn verification_method(&self) -> &str {
        &self.verification_method
    }

    pub fn identity_version(&self) -> &IdentityVersion {
        &self.identity_version
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        Ok(atproto_dasl::to_vec(self)?)
    }

    /// Verify a current claim against the currently active `did:kan` state.
    /// A later historical-state resolver can supply the same checks for an
    /// active ancestor; this boundary never substitutes the current method
    /// for the exact event cited by the author.
    pub fn verify_active_did_kan_claim(
        &self,
        claim_cid: &Cid,
        signature: &[u8],
        state: &ResolvedDidKanState,
    ) -> AuthorshipVerification {
        self.verify_active_did_kan_message(&claim_cid.to_bytes(), signature, state)
    }

    /// Verify domain-separated current-claim bytes against the exact identity
    /// event and method named by this author.
    pub fn verify_active_did_kan_message(
        &self,
        message: &[u8],
        signature: &[u8],
        state: &ResolvedDidKanState,
    ) -> AuthorshipVerification {
        if self.validate().is_err() || self.principal != state.did {
            return AuthorshipVerification::invalid();
        }
        let IdentityVersion::Event(event) = &self.identity_version else {
            return AuthorshipVerification::invalid();
        };
        if event != &state.active_event {
            return AuthorshipVerification::invalid();
        }
        let Some(method) = state
            .verification_methods
            .iter()
            .find(|method| method.id == self.verification_method)
        else {
            return AuthorshipVerification::invalid();
        };
        if method.controller != self.principal
            || !method.purposes.contains(&VerificationPurpose::Assertion)
        {
            return AuthorshipVerification::invalid();
        }
        let cryptographic_validity = verify_resolved_method_signature(message, signature, method);
        AuthorshipVerification {
            scope_invocation: cryptographic_validity == CryptographicValidity::Valid
                && method
                    .purposes
                    .contains(&VerificationPurpose::CapabilityInvocation),
            cryptographic_validity,
        }
    }
}

fn identity_version_kind(version: &IdentityVersion) -> &'static str {
    match version {
        IdentityVersion::Static => "static",
        IdentityVersion::Event(_) => "event",
        IdentityVersion::VersionId(_) => "versionId",
        IdentityVersion::DocumentCid(_) => "documentCid",
    }
}

/// Signature validity and the independent permission to exercise scope
/// reach. Missing `capabilityInvocation` never turns authentic speech into an
/// invalid signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorshipVerification {
    pub cryptographic_validity: CryptographicValidity,
    pub scope_invocation: bool,
}

impl AuthorshipVerification {
    fn invalid() -> Self {
        Self {
            cryptographic_validity: CryptographicValidity::Invalid,
            scope_invocation: false,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unsupported current author principal: {0}")]
    UnsupportedPrincipal(String),
    #[error("verification method `{method}` does not belong to principal `{principal}`")]
    MethodPrincipalMismatch { principal: String, method: String },
    #[error("principal `{principal}` requires identity version `{expected}`, not `{actual}`")]
    IdentityVersionKind {
        principal: String,
        expected: &'static str,
        actual: &'static str,
    },
    #[error("static did:key author method must use its complete fingerprint fragment: {0}")]
    StaticMethod(String),
    #[error("current author DID is invalid: {0}")]
    Did(#[from] super::did_kan::Error),
    #[error("current author DAG-CBOR encoding failed: {0}")]
    Encode(#[from] atproto_dasl::EncodeError),
}

//! RFC 1 scope inception and self-certifying scope identifiers.

use std::{cmp::Ordering, collections::BTreeSet, fmt, str::FromStr};

use atproto_dasl::Ipld;
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use sha2::{Digest, Sha256};

use super::{
    control::{
        verify_resolved_method_proof, verify_static_did_key_proof, ControlEvent, IdentityVersion,
        Proof, SigningInput,
    },
    did_kan::{validate_did, VerificationPurpose},
    did_kan_update::ResolvedDidKanState,
    CryptographicValidity,
};

pub const INCEPTION_DOMAIN: &str = "tools.kan.scope.inception.v1";
pub const INCEPTION_EVENT_TYPE: &str = "inception";

const SHA2_256_MULTIHASH_PREFIX: [u8; 2] = [0x12, 0x20];
const SCOPE_ID_LENGTH: usize = 34;

/// A self-certifying scope identifier.
///
/// Canonical DAG-CBOR represents this value as exactly 34 bytes containing a
/// sha2-256 multihash. Human-facing text is canonical base32lower multibase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScopeId([u8; SCOPE_ID_LENGTH]);

impl ScopeId {
    pub fn from_bytes(bytes: [u8; SCOPE_ID_LENGTH]) -> Result<Self, Error> {
        if bytes[..2] != SHA2_256_MULTIHASH_PREFIX {
            return Err(Error::InvalidScopeId(atrium_crypto::multibase::encode(
                atrium_crypto::multibase::Base::Base32Lower,
                bytes,
            )));
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; SCOPE_ID_LENGTH] {
        &self.0
    }
}

impl fmt::Display for ScopeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&atrium_crypto::multibase::encode(
            atrium_crypto::multibase::Base::Base32Lower,
            self.0,
        ))
    }
}

impl FromStr for ScopeId {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (base, bytes) = atrium_crypto::multibase::decode(value)
            .map_err(|_| Error::InvalidScopeId(value.to_string()))?;
        if base != atrium_crypto::multibase::Base::Base32Lower
            || bytes.len() != SCOPE_ID_LENGTH
            || bytes[..2] != SHA2_256_MULTIHASH_PREFIX
            || atrium_crypto::multibase::encode(base, &bytes) != value
        {
            return Err(Error::InvalidScopeId(value.to_string()));
        }
        let bytes: [u8; SCOPE_ID_LENGTH] = bytes
            .try_into()
            .map_err(|_| Error::InvalidScopeId(value.to_string()))?;
        Ok(Self(bytes))
    }
}

impl Serialize for ScopeId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for ScopeId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ScopeIdVisitor;

        impl<'de> Visitor<'de> for ScopeIdVisitor {
            type Value = ScopeId;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a 34-byte sha2-256 multihash scope identifier")
            }

            fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
                let bytes: [u8; SCOPE_ID_LENGTH] = value
                    .try_into()
                    .map_err(|_| E::invalid_length(value.len(), &self))?;
                ScopeId::from_bytes(bytes).map_err(E::custom)
            }

            fn visit_byte_buf<E: de::Error>(self, value: Vec<u8>) -> Result<Self::Value, E> {
                self.visit_bytes(&value)
            }
        }

        deserializer.deserialize_bytes(ScopeIdVisitor)
    }
}

/// The two value kinds admitted by an RFC 1 substrate anchor.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum AnchorValue {
    Bytes(Vec<u8>),
    Text(String),
}

impl Serialize for AnchorValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Bytes(bytes) => serializer.serialize_bytes(bytes),
            Self::Text(text) => serializer.serialize_str(text),
        }
    }
}

impl<'de> Deserialize<'de> for AnchorValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct AnchorValueVisitor;

        impl<'de> Visitor<'de> for AnchorValueVisitor {
            type Value = AnchorValue;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("DAG-CBOR bytes or text")
            }

            fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
                Ok(AnchorValue::Bytes(value.to_vec()))
            }

            fn visit_byte_buf<E: de::Error>(self, value: Vec<u8>) -> Result<Self::Value, E> {
                Ok(AnchorValue::Bytes(value))
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(AnchorValue::Text(value.to_string()))
            }

            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(AnchorValue::Text(value))
            }
        }

        deserializer.deserialize_any(AnchorValueVisitor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubstrateAnchor {
    #[serde(rename = "type")]
    pub anchor_type: String,
    pub value: AnchorValue,
}

/// Unsigned scope inception payload. Its canonical bytes derive the scope
/// identifier; proofs are deliberately outside that identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScopeInception {
    pub v: u64,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    pub names: Vec<String>,
    pub governance_roots: Vec<String>,
    pub anchors: Vec<SubstrateAnchor>,
}

impl ScopeInception {
    pub fn new(
        nonce: [u8; 32],
        mut names: Vec<String>,
        mut governance_roots: Vec<String>,
        mut anchors: Vec<SubstrateAnchor>,
    ) -> Result<Self, Error> {
        reject_duplicates(&names, "names")?;
        reject_duplicates(&governance_roots, "governanceRoots")?;
        reject_duplicates(&anchors, "anchors")?;
        sort_canonical(&mut names)?;
        sort_canonical(&mut governance_roots)?;
        sort_canonical(&mut anchors)?;
        let inception = Self {
            v: 1,
            nonce: nonce.to_vec(),
            names,
            governance_roots,
            anchors,
        };
        inception.validate()?;
        Ok(inception)
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.v != 1 {
            return Err(Error::UnsupportedVersion(self.v));
        }
        if self.nonce.len() != 32 {
            return Err(Error::NonceLength(self.nonce.len()));
        }
        validate_canonical_order(&self.names, "names")?;
        validate_canonical_order(&self.governance_roots, "governanceRoots")?;
        validate_canonical_order(&self.anchors, "anchors")?;
        if self.governance_roots.is_empty() {
            return Err(Error::NoGovernanceRoots);
        }
        for root in &self.governance_roots {
            validate_did(root)?;
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        Ok(atproto_dasl::to_vec(self)?)
    }

    pub fn scope_id(&self) -> Result<ScopeId, Error> {
        let digest = Sha256::digest(self.canonical_bytes()?);
        let mut multihash = [0u8; SCOPE_ID_LENGTH];
        multihash[..2].copy_from_slice(&SHA2_256_MULTIHASH_PREFIX);
        multihash[2..].copy_from_slice(&digest);
        ScopeId::from_bytes(multihash)
    }

    pub fn signing_input(&self) -> Result<SigningInput, Error> {
        self.validate()?;
        let payload: Ipld = atproto_dasl::from_reader(&self.canonical_bytes()?[..])?;
        Ok(SigningInput::new(
            INCEPTION_DOMAIN,
            INCEPTION_EVENT_TYPE,
            payload,
        )?)
    }

    /// Produce the supported v1 inception event when a listed static P-256
    /// `did:key` governance root proves the signing input. Rotatable roots are
    /// preserved by the common envelope but require their method resolver.
    pub fn proved_event(&self, proofs: Vec<Proof>) -> Result<ControlEvent, Error> {
        let input = self.signing_input()?;
        let authorized = proofs.iter().any(|proof| {
            let controller = proof.method.split_once('#').map(|(did, _)| did);
            controller.is_some_and(|did| {
                self.governance_roots.iter().any(|root| root == did)
                    && verify_static_did_key_proof(&input, proof) == CryptographicValidity::Valid
            })
        });
        if !authorized {
            return Err(Error::NoGovernanceProof);
        }
        Ok(ControlEvent::new(input, proofs)?)
    }

    /// Produce inception governed by one exact active `did:kan` state. This
    /// is the bridge used by a system identity's daily device: the principal,
    /// method, historical state, purpose, and signature must all agree.
    pub fn proved_event_with_did_kan_state(
        &self,
        state: &ResolvedDidKanState,
        proofs: Vec<Proof>,
    ) -> Result<ControlEvent, Error> {
        let input = self.signing_input()?;
        let expected_state = IdentityVersion::Event(state.active_event.clone());
        let authorized = self.governance_roots.iter().any(|root| root == &state.did)
            && proofs.iter().any(|proof| {
                state.verification_methods.iter().any(|method| {
                    method.controller == state.did
                        && method
                            .purposes
                            .contains(&VerificationPurpose::CapabilityDelegation)
                        && verify_resolved_method_proof(&input, proof, method, &expected_state)
                            == CryptographicValidity::Valid
                })
            });
        if !authorized {
            return Err(Error::NoGovernanceProof);
        }
        Ok(ControlEvent::new(input, proofs)?)
    }
}

fn canonical_key<T: Serialize>(value: &T) -> Result<Vec<u8>, atproto_dasl::EncodeError> {
    atproto_dasl::to_vec(value)
}

fn sort_canonical<T: Clone + Serialize>(values: &mut [T]) -> Result<(), Error> {
    let mut keyed = values
        .iter()
        .cloned()
        .map(|value| Ok((canonical_key(&value)?, value)))
        .collect::<Result<Vec<_>, atproto_dasl::EncodeError>>()?;
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    for (slot, (_, value)) in values.iter_mut().zip(keyed) {
        *slot = value;
    }
    Ok(())
}

fn validate_canonical_order<T: Serialize>(values: &[T], field: &'static str) -> Result<(), Error> {
    let mut prior: Option<Vec<u8>> = None;
    for value in values {
        let key = canonical_key(value)?;
        if prior
            .as_ref()
            .is_some_and(|previous| previous.as_slice().cmp(&key) != Ordering::Less)
        {
            return Err(Error::NotSortedUnique(field));
        }
        prior = Some(key);
    }
    Ok(())
}

fn reject_duplicates<T: Ord + Clone>(values: &[T], field: &'static str) -> Result<(), Error> {
    let mut seen = BTreeSet::new();
    if values.iter().any(|value| !seen.insert(value.clone())) {
        return Err(Error::Duplicate(field));
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unsupported scope inception version {0}")]
    UnsupportedVersion(u64),
    #[error("scope inception nonce must be exactly 32 bytes, found {0}")]
    NonceLength(usize),
    #[error("scope inception requires at least one governance root")]
    NoGovernanceRoots,
    #[error("{0} must be sorted by canonical encoded value and duplicate-free")]
    NotSortedUnique(&'static str),
    #[error("{0} contains a duplicate")]
    Duplicate(&'static str),
    #[error("scope inception needs a valid proof from a listed governance root")]
    NoGovernanceProof,
    #[error("invalid canonical scope identifier: {0}")]
    InvalidScopeId(String),
    #[error(transparent)]
    Identity(#[from] super::did_kan::Error),
    #[error(transparent)]
    Encode(#[from] atproto_dasl::EncodeError),
    #[error(transparent)]
    Decode(#[from] atproto_dasl::DecodeError),
    #[error(transparent)]
    Control(#[from] super::control::Error),
}

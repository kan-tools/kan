//! RFC 1 repository inception and self-certifying repository identifiers.

use std::{cmp::Ordering, collections::BTreeSet};

use atproto_dasl::Ipld;
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use sha2::{Digest, Sha256};

use super::{
    control::{verify_static_did_key_proof, ControlEvent, Proof, SigningInput},
    did_kan::validate_did,
    CryptographicValidity,
};

pub const INCEPTION_DOMAIN: &str = "kan.repository.inception.v1";
pub const INCEPTION_EVENT_TYPE: &str = "inception";

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

/// Unsigned repository inception payload. Its canonical bytes derive the
/// repository identifier; proofs are deliberately outside that identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepositoryInception {
    pub v: u64,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    pub names: Vec<String>,
    pub governance_roots: Vec<String>,
    pub anchors: Vec<SubstrateAnchor>,
}

impl RepositoryInception {
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

    pub fn repository_id(&self) -> Result<String, Error> {
        let digest = Sha256::digest(self.canonical_bytes()?);
        let mut multihash = Vec::with_capacity(34);
        multihash.extend_from_slice(&[0x12, 0x20]);
        multihash.extend_from_slice(&digest);
        let encoded = atrium_crypto::multibase::encode(
            atrium_crypto::multibase::Base::Base32Lower,
            multihash,
        );
        Ok(format!("kan-repo:{encoded}"))
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
    #[error("unsupported repository inception version {0}")]
    UnsupportedVersion(u64),
    #[error("repository inception nonce must be exactly 32 bytes, found {0}")]
    NonceLength(usize),
    #[error("repository inception requires at least one governance root")]
    NoGovernanceRoots,
    #[error("{0} must be sorted by canonical encoded value and duplicate-free")]
    NotSortedUnique(&'static str),
    #[error("{0} contains a duplicate")]
    Duplicate(&'static str),
    #[error("repository inception needs a valid proof from a listed governance root")]
    NoGovernanceProof,
    #[error(transparent)]
    Identity(#[from] super::did_kan::Error),
    #[error(transparent)]
    Encode(#[from] atproto_dasl::EncodeError),
    #[error(transparent)]
    Decode(#[from] atproto_dasl::DecodeError),
    #[error(transparent)]
    Control(#[from] super::control::Error),
}

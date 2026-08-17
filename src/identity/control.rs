//! RFC 1 control-event envelope and canonical identifiers.
//!
//! Identity and repository-control events are lower-level siblings of claims.
//! They share DAG-CBOR and CID machinery with claims, but sign a
//! domain-separated [`SigningInput`] and keep proofs outside the logical event
//! identifier. This module implements that common envelope without yet
//! assigning identity or governance transition semantics to its payload.

use std::collections::BTreeSet;

use atproto_dasl::{Cid, Ipld};
use serde::{ser::SerializeMap, Deserialize, Serialize};

use super::CryptographicValidity;

pub const CONTROL_EVENT_VERSION: u64 = 1;

/// Exact historical identity state named by a proof or modern claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityVersion {
    Static,
    Event(Cid),
    VersionId(String),
    DocumentCid(Cid),
}

impl Serialize for IdentityVersion {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(2))?;
        match self {
            IdentityVersion::Static => {
                map.serialize_entry("kind", "static")?;
                map.serialize_entry("value", &Option::<u8>::None)?;
            }
            IdentityVersion::Event(cid) => {
                map.serialize_entry("kind", "event")?;
                map.serialize_entry("value", cid)?;
            }
            IdentityVersion::VersionId(id) => {
                map.serialize_entry("kind", "versionId")?;
                map.serialize_entry("value", id)?;
            }
            IdentityVersion::DocumentCid(cid) => {
                map.serialize_entry("kind", "documentCid")?;
                map.serialize_entry("value", cid)?;
            }
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for IdentityVersion {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            kind: String,
            value: Ipld,
        }

        let wire = Wire::deserialize(deserializer)?;
        match (wire.kind.as_str(), wire.value) {
            ("static", Ipld::Null) => Ok(IdentityVersion::Static),
            ("event", Ipld::Link(cid)) => Ok(IdentityVersion::Event(cid)),
            ("versionId", Ipld::String(id)) if !id.is_empty() => Ok(IdentityVersion::VersionId(id)),
            ("documentCid", Ipld::Link(cid)) => Ok(IdentityVersion::DocumentCid(cid)),
            (kind, _) => Err(serde::de::Error::custom(format!(
                "invalid value for identity version kind `{kind}`"
            ))),
        }
    }
}

/// One detached proof over a control event's signing input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Proof {
    pub method: String,
    pub controller_state: IdentityVersion,
    pub alg: String,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

/// The exact bytes proofs sign and the logical event CID addresses.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningInput {
    pub v: u64,
    pub domain: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub payload: Ipld,
}

impl SigningInput {
    pub fn new(
        domain: impl Into<String>,
        event_type: impl Into<String>,
        payload: Ipld,
    ) -> Result<Self, Error> {
        let input = Self {
            v: CONTROL_EVENT_VERSION,
            domain: domain.into(),
            event_type: event_type.into(),
            payload,
        };
        input.validate()?;
        Ok(input)
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.v != CONTROL_EVENT_VERSION {
            return Err(Error::UnsupportedVersion(self.v));
        }
        if self.domain.is_empty() {
            return Err(Error::EmptyDomain);
        }
        if self.event_type.is_empty() {
            return Err(Error::EmptyEventType);
        }
        if !matches!(self.payload, Ipld::Map(_)) {
            return Err(Error::PayloadNotMap);
        }
        if contains_float(&self.payload) {
            return Err(Error::FloatNotAllowed);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        Ok(atproto_dasl::to_vec(self)?)
    }

    pub fn logical_cid(&self) -> Result<Cid, Error> {
        self.validate()?;
        Ok(crate::cid::content_cid(self)?)
    }
}

/// A proved RFC 1 control event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlEvent {
    pub v: u64,
    pub domain: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub payload: Ipld,
    pub proofs: Vec<Proof>,
}

impl ControlEvent {
    /// Build a canonical event, sorting proofs and refusing duplicate proof
    /// identities. Sorting is producer convenience; [`Self::validate`]
    /// remains strict for decoded or manually assembled events.
    pub fn new(input: SigningInput, mut proofs: Vec<Proof>) -> Result<Self, Error> {
        input.validate()?;
        for proof in &proofs {
            validate_method(&proof.method)?;
        }
        let mut keyed = proofs
            .drain(..)
            .map(|proof| Ok((proof_sort_key(&proof)?, proof)))
            .collect::<Result<Vec<_>, Error>>()?;
        keyed.sort_by(|left, right| left.0.cmp(&right.0));
        proofs = keyed.into_iter().map(|(_, proof)| proof).collect();
        let event = Self {
            v: input.v,
            domain: input.domain,
            event_type: input.event_type,
            payload: input.payload,
            proofs,
        };
        event.validate()?;
        Ok(event)
    }

    pub fn signing_input(&self) -> SigningInput {
        SigningInput {
            v: self.v,
            domain: self.domain.clone(),
            event_type: self.event_type.clone(),
            payload: self.payload.clone(),
        }
    }

    pub fn validate(&self) -> Result<(), Error> {
        self.signing_input().validate()?;
        if self.proofs.is_empty() {
            return Err(Error::NoProofs);
        }

        let mut identities = BTreeSet::new();
        let mut previous_key = None;
        for proof in &self.proofs {
            validate_method(&proof.method)?;
            if proof.alg.is_empty() {
                return Err(Error::EmptyAlgorithm);
            }
            let key = proof_sort_key(proof)?;
            let identity = (key.0.clone(), key.1.clone(), key.2.clone());
            if !identities.insert(identity) {
                return Err(Error::DuplicateProof);
            }
            if previous_key.as_ref().is_some_and(|prior| prior > &key) {
                return Err(Error::UnsortedProofs);
            }
            previous_key = Some(key);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        Ok(atproto_dasl::to_vec(self)?)
    }

    pub fn logical_cid(&self) -> Result<Cid, Error> {
        self.signing_input().logical_cid()
    }

    pub fn proved_cid(&self) -> Result<Cid, Error> {
        self.validate()?;
        Ok(crate::cid::content_cid(self)?)
    }
}

/// Verify the intrinsic signature of a static `did:key` proof.
///
/// Controller/history authorization for rotatable DIDs belongs to the future
/// resolver. Unsupported algorithms and key codecs remain distinct from a bad
/// signature.
pub fn verify_static_did_key_proof(input: &SigningInput, proof: &Proof) -> CryptographicValidity {
    if input.validate().is_err() || proof.controller_state != IdentityVersion::Static {
        return CryptographicValidity::Invalid;
    }
    let Some((did, fragment)) = proof.method.split_once('#') else {
        return CryptographicValidity::Invalid;
    };
    let Some(fingerprint) = did.strip_prefix("did:key:") else {
        return CryptographicValidity::Unknown;
    };
    if fragment.is_empty() || fragment != fingerprint {
        return CryptographicValidity::Invalid;
    }
    if proof.alg != "P256" {
        return CryptographicValidity::Unsupported;
    }
    let did = did.to_string();
    match atrium_crypto::did::parse_did_key(&did) {
        Ok((atrium_crypto::Algorithm::P256, _)) => input
            .canonical_bytes()
            .ok()
            .filter(|bytes| crate::sign::verify(&did, bytes, &proof.sig))
            .map_or(CryptographicValidity::Invalid, |_| {
                CryptographicValidity::Valid
            }),
        Ok((atrium_crypto::Algorithm::Secp256k1, _))
        | Err(atrium_crypto::Error::UnsupportedMultikeyType) => CryptographicValidity::Unsupported,
        Err(_) => CryptographicValidity::Invalid,
    }
}

type ProofSortKey = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

fn proof_sort_key(proof: &Proof) -> Result<ProofSortKey, atproto_dasl::EncodeError> {
    Ok((
        proof.method.as_bytes().to_vec(),
        atproto_dasl::to_vec(&proof.controller_state)?,
        proof.alg.as_bytes().to_vec(),
        proof.sig.clone(),
    ))
}

fn validate_method(method: &str) -> Result<(), Error> {
    let Some((did, fragment)) = method.split_once('#') else {
        return Err(Error::InvalidMethod(method.to_string()));
    };
    if !did.starts_with("did:") || fragment.is_empty() || fragment.contains('#') {
        return Err(Error::InvalidMethod(method.to_string()));
    }
    Ok(())
}

fn contains_float(value: &Ipld) -> bool {
    match value {
        Ipld::Float(_) => true,
        Ipld::List(values) => values.iter().any(contains_float),
        Ipld::Map(values) => values.values().any(contains_float),
        _ => false,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unsupported control-event version {0}")]
    UnsupportedVersion(u64),
    #[error("control-event domain must not be empty")]
    EmptyDomain,
    #[error("control-event type must not be empty")]
    EmptyEventType,
    #[error("control-event payload must be a map")]
    PayloadNotMap,
    #[error("control-event values must not contain floats")]
    FloatNotAllowed,
    #[error("control event must carry at least one proof")]
    NoProofs,
    #[error("proof method is not an absolute DID URL with one non-empty fragment: {0}")]
    InvalidMethod(String),
    #[error("proof algorithm must not be empty")]
    EmptyAlgorithm,
    #[error("duplicate proof method/controller-state/algorithm tuple")]
    DuplicateProof,
    #[error("proof array is not in canonical order")]
    UnsortedProofs,
    #[error(transparent)]
    Encode(#[from] atproto_dasl::EncodeError),
    #[error(transparent)]
    Cid(#[from] crate::cid::Error),
}

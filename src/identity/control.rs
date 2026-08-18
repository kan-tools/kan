//! RFC 1 control-event envelope and canonical identifiers.
//!
//! Identity and repository-control events are lower-level siblings of claims.
//! They share DAG-CBOR and CID machinery with claims, but sign a
//! domain-separated [`SigningInput`] and keep proofs outside the logical event
//! identifier. This module implements that common envelope without yet
//! assigning identity or governance transition semantics to its payload.

use std::collections::BTreeSet;

use atproto_dasl::{Cid, Ipld};
use ed25519_dalek::{Signature, VerifyingKey};
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

/// A canonical control event retained at the lossless protocol boundary.
///
/// `raw` includes fields this build does not understand. Such an event is
/// reported as unsupported, but its bytes and both identifiers remain
/// available; an older reader never re-encodes it through a narrower struct.
#[derive(Debug, Clone, PartialEq)]
pub struct PreservedControlEvent {
    raw: Ipld,
    signing_input: Ipld,
    canonical_bytes: Vec<u8>,
    unsupported_fields: Vec<String>,
}

impl PreservedControlEvent {
    pub fn raw(&self) -> &Ipld {
        &self.raw
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn unsupported_fields(&self) -> &[String] {
        &self.unsupported_fields
    }

    pub fn is_supported(&self) -> bool {
        self.unsupported_fields.is_empty() && self.typed().is_some()
    }

    pub fn typed(&self) -> Option<ControlEvent> {
        let bytes = atproto_dasl::to_vec(&self.raw).ok()?;
        atproto_dasl::from_reader(&bytes[..]).ok()
    }

    pub fn logical_cid(&self) -> Result<Cid, crate::cid::Error> {
        crate::cid::content_cid(&self.signing_input)
    }

    pub fn proved_cid(&self) -> Result<Cid, crate::cid::Error> {
        crate::cid::content_cid(&self.raw)
    }
}

/// Decode a canonical control event without discarding fields unknown to this
/// build. Common-envelope defects are invalid; additive fields are preserved
/// and disclosed as unsupported.
pub fn decode_preserving(bytes: &[u8]) -> Result<PreservedControlEvent, DecodeError> {
    let raw: Ipld = atproto_dasl::from_reader(bytes)?;
    let canonical_bytes = atproto_dasl::to_vec(&raw)?;
    if canonical_bytes != bytes {
        return Err(DecodeError::NonCanonical);
    }
    let Ipld::Map(entries) = &raw else {
        return Err(DecodeError::Malformed("event is not a map"));
    };

    match entries.get("v") {
        Some(Ipld::Integer(v)) if *v == CONTROL_EVENT_VERSION as i128 => {}
        Some(Ipld::Integer(v)) => {
            return Err(DecodeError::UnsupportedVersion(*v));
        }
        _ => return Err(DecodeError::Malformed("v is not an unsigned integer")),
    }
    require_nonempty_string(entries, "domain")?;
    require_nonempty_string(entries, "type")?;
    let payload = entries
        .get("payload")
        .ok_or(DecodeError::Malformed("payload is missing"))?;
    if !matches!(payload, Ipld::Map(_)) {
        return Err(DecodeError::Malformed("payload is not a map"));
    }
    if contains_float(payload) {
        return Err(DecodeError::Malformed("payload contains a float"));
    }
    let Some(Ipld::List(proofs)) = entries.get("proofs") else {
        return Err(DecodeError::Malformed("proofs is not a list"));
    };
    if proofs.is_empty() {
        return Err(DecodeError::Malformed("proofs is empty"));
    }

    let known_event_fields = ["v", "domain", "type", "payload", "proofs"];
    let mut unsupported_fields: Vec<String> = entries
        .keys()
        .filter(|key| !known_event_fields.contains(&key.as_str()))
        .map(|key| key.to_string())
        .collect();
    let mut proof_identities = BTreeSet::new();
    let mut previous_key = None;
    for (index, proof) in proofs.iter().enumerate() {
        let Ipld::Map(fields) = proof else {
            return Err(DecodeError::Malformed("proof is not a map"));
        };
        let method = require_nonempty_string(fields, "method")?;
        validate_method(method).map_err(|_| DecodeError::Malformed("invalid proof method"))?;
        let controller = fields
            .get("controllerState")
            .ok_or(DecodeError::Malformed("controllerState is missing"))?;
        let alg = require_nonempty_string(fields, "alg")?;
        let Some(Ipld::Bytes(sig)) = fields.get("sig") else {
            return Err(DecodeError::Malformed("proof sig is not bytes"));
        };
        let known_proof_fields = ["method", "controllerState", "alg", "sig"];
        unsupported_fields.extend(
            fields
                .keys()
                .filter(|key| !known_proof_fields.contains(&key.as_str()))
                .map(|key| format!("proofs[{index}].{key}")),
        );

        let controller_bytes = atproto_dasl::to_vec(controller)?;
        let key = (
            method.as_bytes().to_vec(),
            controller_bytes,
            alg.as_bytes().to_vec(),
            sig.clone(),
        );
        let identity = (key.0.clone(), key.1.clone(), key.2.clone());
        if !proof_identities.insert(identity) {
            return Err(DecodeError::DuplicateProof);
        }
        if previous_key.as_ref().is_some_and(|prior| prior > &key) {
            return Err(DecodeError::UnsortedProofs);
        }
        previous_key = Some(key);
    }

    unsupported_fields.sort();
    let mut signing_entries = entries.clone();
    signing_entries.remove("proofs");
    let signing_input = Ipld::Map(signing_entries);
    let preserved = PreservedControlEvent {
        raw,
        signing_input,
        canonical_bytes,
        unsupported_fields,
    };
    if preserved.typed().is_none() && preserved.unsupported_fields.is_empty() {
        preserved_with_shape_marker(preserved)
    } else {
        Ok(preserved)
    }
}

fn preserved_with_shape_marker(
    mut preserved: PreservedControlEvent,
) -> Result<PreservedControlEvent, DecodeError> {
    preserved
        .unsupported_fields
        .push("unsupported-control-shape".to_string());
    Ok(preserved)
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
    let Ok(bytes) = input.canonical_bytes() else {
        return CryptographicValidity::Invalid;
    };
    match proof.alg.as_str() {
        "P256" => {
            let did = did.to_string();
            match atrium_crypto::did::parse_did_key(&did) {
                Ok((atrium_crypto::Algorithm::P256, _)) => {
                    if crate::sign::verify(&did, &bytes, &proof.sig) {
                        CryptographicValidity::Valid
                    } else {
                        CryptographicValidity::Invalid
                    }
                }
                Ok((atrium_crypto::Algorithm::Secp256k1, _)) => CryptographicValidity::Unsupported,
                Err(atrium_crypto::Error::UnsupportedMultikeyType)
                    if is_ed25519_fingerprint(fingerprint) =>
                {
                    CryptographicValidity::Invalid
                }
                Err(atrium_crypto::Error::UnsupportedMultikeyType) => {
                    CryptographicValidity::Unsupported
                }
                Err(_) => CryptographicValidity::Invalid,
            }
        }
        "Ed25519" => verify_ed25519_did_key(fingerprint, &bytes, &proof.sig),
        _ => CryptographicValidity::Unsupported,
    }
}

/// Verify a proof against one exact resolved verification method and identity
/// state. The caller remains responsible for establishing that `method` is
/// authorized at `controller_state`; this function binds the proof bytes to
/// all three facts without treating the method's key as the principal.
pub fn verify_resolved_method_proof(
    input: &SigningInput,
    proof: &Proof,
    method: &super::did_kan::VerificationMethod,
    controller_state: &IdentityVersion,
) -> CryptographicValidity {
    if input.validate().is_err()
        || super::did_kan::validate_verification_method(method).is_err()
        || proof.method != method.id
        || proof.alg != method.alg
        || &proof.controller_state != controller_state
    {
        return CryptographicValidity::Invalid;
    }
    let Ok(bytes) = input.canonical_bytes() else {
        return CryptographicValidity::Invalid;
    };
    match method.alg.as_str() {
        "P256" => {
            let Ok(key_did) = atrium_crypto::did::format_did_key(
                atrium_crypto::Algorithm::P256,
                &method.public_key,
            ) else {
                return CryptographicValidity::Invalid;
            };
            if crate::sign::verify(&key_did, &bytes, &proof.sig) {
                CryptographicValidity::Valid
            } else {
                CryptographicValidity::Invalid
            }
        }
        "Ed25519" => {
            let mut multikey = Vec::with_capacity(34);
            multikey.extend_from_slice(&[0xed, 0x01]);
            multikey.extend_from_slice(&method.public_key);
            let fingerprint = atrium_crypto::multibase::encode(
                atrium_crypto::multibase::Base::Base58Btc,
                &multikey,
            );
            verify_ed25519_did_key(&fingerprint, &bytes, &proof.sig)
        }
        _ => CryptographicValidity::Unsupported,
    }
}

fn is_ed25519_fingerprint(fingerprint: &str) -> bool {
    atrium_crypto::multibase::decode(fingerprint)
        .ok()
        .is_some_and(|(base, multikey)| {
            base == atrium_crypto::multibase::Base::Base58Btc
                && multikey.len() == 34
                && multikey.starts_with(&[0xed, 0x01])
                && atrium_crypto::multibase::encode(base, &multikey) == fingerprint
        })
}

/// Verify RFC 1's canonical Ed25519 `did:key` form. `verify_strict` rejects
/// weak public keys, small-order R components, and non-canonical signatures;
/// the explicit multicodec parse also prevents algorithm/key substitution.
fn verify_ed25519_did_key(
    fingerprint: &str,
    message: &[u8],
    signature: &[u8],
) -> CryptographicValidity {
    let Ok((base, multikey)) = atrium_crypto::multibase::decode(fingerprint) else {
        return CryptographicValidity::Invalid;
    };
    if base != atrium_crypto::multibase::Base::Base58Btc
        || atrium_crypto::multibase::encode(base, &multikey) != fingerprint
    {
        return CryptographicValidity::Invalid;
    }
    // unsigned-varint(0xed) followed by the canonical 32-byte public key.
    let Ok(public_key) = <&[u8; 32]>::try_from(multikey.strip_prefix(&[0xed, 0x01]).unwrap_or(&[]))
    else {
        return if multikey.starts_with(&[0x80, 0x24]) || multikey.starts_with(&[0xe7, 0x01]) {
            CryptographicValidity::Invalid
        } else {
            CryptographicValidity::Unsupported
        };
    };
    let Ok(key) = VerifyingKey::from_bytes(public_key) else {
        return CryptographicValidity::Invalid;
    };
    let Ok(signature) = Signature::from_slice(signature) else {
        return CryptographicValidity::Invalid;
    };
    if key.verify_strict(message, &signature).is_ok() {
        CryptographicValidity::Valid
    } else {
        CryptographicValidity::Invalid
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

fn require_nonempty_string<'a>(
    entries: &'a std::collections::BTreeMap<String, Ipld>,
    field: &'static str,
) -> Result<&'a str, DecodeError> {
    match entries.get(field) {
        Some(Ipld::String(value)) if !value.is_empty() => Ok(value),
        _ => Err(DecodeError::Malformed(
            "required text field is missing or empty",
        )),
    }
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

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("control event is not canonical DAG-CBOR")]
    NonCanonical,
    #[error("unsupported control-event version {0}")]
    UnsupportedVersion(i128),
    #[error("malformed control event: {0}")]
    Malformed(&'static str),
    #[error("duplicate proof method/controller-state/algorithm tuple")]
    DuplicateProof,
    #[error("proof array is not in canonical order")]
    UnsortedProofs,
    #[error(transparent)]
    Decode(#[from] atproto_dasl::DecodeError),
    #[error(transparent)]
    Encode(#[from] atproto_dasl::EncodeError),
}

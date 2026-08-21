//! Closed claim-codec dispatch with byte-preserving future-codec handling.

use std::{collections::BTreeMap, str::FromStr};

use atproto_dasl::{Cid, Ipld};

use super::{v1, Claim, ClaimContent};

pub const V1_CODEC: &str = "kan-claim-v1";
pub const V2_CODEC: &str = super::CODEC;
pub const V1_CONTENT_TYPE: &str = "tools.kan.defs#claimContent";
pub const V2_CONTENT_TYPE: &str = "tools.kan.defs#claimContentV2";
pub const ENVELOPE_TYPE: &str = "tools.kan.claim";

const MAX_RECORD_BYTES: usize = 1_000_000;
const ENVELOPE_FIELDS: [&str; 6] = ["$type", "claimCid", "codec", "content", "rev", "signature"];

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum DecodedClaim {
    Supported(SupportedClaim),
    Unsupported(PreservedClaim),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupportedClaim {
    Claim(Claim),
    V1(v1::Claim),
}

/// Canonical source retained without attempting to interpret a future codec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreservedClaim {
    claim_id: Cid,
    codec: String,
    content_type: String,
    canonical_bytes: Vec<u8>,
}

impl PreservedClaim {
    pub fn claim_id(&self) -> &Cid {
        &self.claim_id
    }

    pub fn codec(&self) -> &str {
        &self.codec
    }

    pub fn content_type(&self) -> &str {
        &self.content_type
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

/// The identity evidence available while decoding a current claim.
#[derive(Clone, Copy)]
pub enum VerificationContext<'a> {
    StaticDidKey,
    ActiveDidKan(&'a crate::identity::did_kan_update::ResolvedDidKanState),
    /// Resolve each current claim from its own typed author. Static
    /// `did:key` authors verify intrinsically; `did:kan` authors select the
    /// state whose DID and exact event both match. Other identity-version
    /// arms remain explicitly unsupported until their resolvers exist.
    ResolvedIdentities {
        did_kan: &'a [crate::identity::did_kan_update::ResolvedDidKanState],
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedRecord {
    pub claim: DecodedClaim,
    pub rev: String,
}

/// Encode a verified current claim into the common mixed-codec envelope.
pub fn encode_claim(claim: &Claim, rev: &str) -> Result<Vec<u8>, EncodeError> {
    validate_rev(rev).map_err(EncodeError::InvalidRev)?;
    let claim_id = claim.id()?;
    let content = typed_content(claim.content(), V2_CONTENT_TYPE)?;
    encode_envelope(
        claim_id.cid(),
        V2_CODEC,
        content,
        claim.signature().as_bytes(),
        rev,
    )
}

/// Encode a released v1 claim without changing its content or signature rules.
pub fn encode_v1(claim: v1::Claim, rev: String) -> Result<Vec<u8>, EncodeError> {
    let record = crate::at_claim::Record::from_claim(claim, rev)?;
    let claim_id = Cid::from_str(&record.claim_cid).map_err(|_| EncodeError::InvalidCid)?;
    let content = typed_content(&record.content, V1_CONTENT_TYPE)?;
    encode_envelope(&claim_id, V1_CODEC, content, &record.signature, &record.rev)
}

/// Re-encode one already-decoded record without changing its codec arm or
/// signed content. Preserved future records return their original canonical
/// envelope byte-for-byte.
pub fn encode_decoded(record: &DecodedRecord) -> Result<Vec<u8>, EncodeError> {
    match &record.claim {
        DecodedClaim::Supported(SupportedClaim::V1(claim)) => {
            encode_v1(claim.clone(), record.rev.clone())
        }
        DecodedClaim::Supported(SupportedClaim::Claim(claim)) => encode_claim(claim, &record.rev),
        DecodedClaim::Unsupported(claim) => Ok(claim.canonical_bytes().to_vec()),
    }
}

/// Decode canonical common-envelope bytes. Unknown codec/arm pairs are
/// preserved only when both sides are unknown; every contradictory pair is
/// invalid.
pub fn decode(
    bytes: &[u8],
    verification: VerificationContext<'_>,
) -> Result<DecodedClaim, DecodeError> {
    Ok(decode_record(bytes, verification)?.claim)
}

pub fn decode_record(
    bytes: &[u8],
    verification: VerificationContext<'_>,
) -> Result<DecodedRecord, DecodeError> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(DecodeError::RecordTooLarge(bytes.len()));
    }
    let raw: Ipld = match atproto_dasl::from_reader(bytes) {
        Ok(raw) => raw,
        Err(
            atproto_dasl::DecodeError::NonCanonicalEncoding { .. }
            | atproto_dasl::DecodeError::MapKeysNotSorted
            | atproto_dasl::DecodeError::NonCanonicalFloat,
        ) => return Err(DecodeError::NonCanonical),
        Err(error) => return Err(error.into()),
    };
    if atproto_dasl::to_vec(&raw)? != bytes {
        return Err(DecodeError::NonCanonical);
    }
    let Ipld::Map(fields) = &raw else {
        return Err(DecodeError::Malformed("claim envelope is not a map"));
    };
    if fields.len() != ENVELOPE_FIELDS.len()
        || fields
            .keys()
            .any(|field| !ENVELOPE_FIELDS.contains(&field.as_str()))
    {
        return Err(DecodeError::Malformed(
            "claim envelope has unknown or missing fields",
        ));
    }
    if require_string(fields, "$type")? != ENVELOPE_TYPE {
        return Err(DecodeError::Malformed("invalid claim envelope $type"));
    }
    let codec = require_string(fields, "codec")?;
    validate_codec(codec)?;
    let claim_id =
        Cid::from_str(require_string(fields, "claimCid")?).map_err(|_| DecodeError::InvalidCid)?;
    let rev = require_string(fields, "rev")?;
    validate_rev(rev).map_err(DecodeError::InvalidRev)?;
    let Some(Ipld::Bytes(signature)) = fields.get("signature") else {
        return Err(DecodeError::Malformed("signature is not bytes"));
    };
    if signature.is_empty() || signature.len() > 256 {
        return Err(DecodeError::Malformed("invalid signature length"));
    }
    let Some(Ipld::Map(content_fields)) = fields.get("content") else {
        return Err(DecodeError::Malformed("content is not a map"));
    };
    let content_type = require_string(content_fields, "$type")?;
    let known_codec = matches!(codec, V1_CODEC | V2_CODEC);
    let known_content = matches!(content_type, V1_CONTENT_TYPE | V2_CONTENT_TYPE);
    let expected = match codec {
        V1_CODEC => Some(V1_CONTENT_TYPE),
        V2_CODEC => Some(V2_CONTENT_TYPE),
        _ => None,
    };
    if expected.is_some_and(|value| value != content_type) || (!known_codec && known_content) {
        return Err(DecodeError::CodecContentMismatch {
            codec: codec.to_string(),
            content_type: content_type.to_string(),
        });
    }
    if !known_codec {
        return Ok(DecodedRecord {
            claim: DecodedClaim::Unsupported(PreservedClaim {
                claim_id,
                codec: codec.to_string(),
                content_type: content_type.to_string(),
                canonical_bytes: bytes.to_vec(),
            }),
            rev: rev.to_string(),
        });
    }

    let mut domain_fields = content_fields.clone();
    domain_fields.remove("$type");
    let domain_bytes = atproto_dasl::to_vec(&Ipld::Map(domain_fields))?;
    match codec {
        V1_CODEC => {
            let content: crate::at_claim::Content = atproto_dasl::from_reader(&domain_bytes[..])?;
            let record = crate::at_claim::Record {
                claim_cid: claim_id.to_string(),
                codec: V1_CODEC.to_string(),
                content,
                signature: signature.clone(),
                rev: rev.to_string(),
            };
            Ok(DecodedRecord {
                claim: DecodedClaim::Supported(SupportedClaim::V1(record.verify()?)),
                rev: rev.to_string(),
            })
        }
        V2_CODEC => {
            let content: ClaimContent = atproto_dasl::from_reader(&domain_bytes[..])?;
            if content.canonical_bytes()? != domain_bytes {
                return Err(DecodeError::NonCanonicalDomainContent);
            }
            if content.id()?.cid() != &claim_id {
                return Err(DecodeError::CidMismatch);
            }
            let claim = match verification {
                VerificationContext::StaticDidKey => {
                    Claim::verify_static(content, signature.clone())?
                }
                VerificationContext::ActiveDidKan(state) => {
                    Claim::verify_active_did_kan(content, signature.clone(), state)?
                }
                VerificationContext::ResolvedIdentities { did_kan } => {
                    verify_with_resolved_identities(content, signature.clone(), did_kan)?
                }
            };
            Ok(DecodedRecord {
                claim: DecodedClaim::Supported(SupportedClaim::Claim(claim)),
                rev: rev.to_string(),
            })
        }
        _ => unreachable!("known codec dispatch is closed above"),
    }
}

fn verify_with_resolved_identities(
    content: ClaimContent,
    signature: Vec<u8>,
    did_kan: &[crate::identity::did_kan_update::ResolvedDidKanState],
) -> Result<Claim, super::Error> {
    use crate::identity::control::IdentityVersion;

    let author = content.author();
    match author.identity_version() {
        IdentityVersion::Static => Claim::verify_static(content, signature),
        IdentityVersion::Event(event) => {
            let state = did_kan
                .iter()
                .find(|state| state.did == author.principal() && &state.active_event == event);
            match state {
                Some(state) => Claim::verify_active_did_kan(content, signature, state),
                None => Err(super::Error::UnsupportedIdentityResolver(
                    author.principal().to_string(),
                )),
            }
        }
        IdentityVersion::VersionId(_) | IdentityVersion::DocumentCid(_) => Err(
            super::Error::UnsupportedIdentityResolver(author.principal().to_string()),
        ),
    }
}

fn typed_content<T: serde::Serialize>(value: &T, content_type: &str) -> Result<Ipld, EncodeError> {
    let bytes = atproto_dasl::to_vec(value)?;
    let Ipld::Map(mut fields) = atproto_dasl::from_reader(&bytes[..])? else {
        return Err(EncodeError::ContentNotMap);
    };
    if fields
        .insert("$type".to_string(), Ipld::String(content_type.to_string()))
        .is_some()
    {
        return Err(EncodeError::ContentTypeCollision);
    }
    Ok(Ipld::Map(fields))
}

fn encode_envelope(
    claim_id: &Cid,
    codec: &str,
    content: Ipld,
    signature: &[u8],
    rev: &str,
) -> Result<Vec<u8>, EncodeError> {
    let raw = Ipld::Map(BTreeMap::from([
        ("$type".to_string(), Ipld::String(ENVELOPE_TYPE.to_string())),
        ("claimCid".to_string(), Ipld::String(claim_id.to_string())),
        ("codec".to_string(), Ipld::String(codec.to_string())),
        ("content".to_string(), content),
        ("rev".to_string(), Ipld::String(rev.to_string())),
        ("signature".to_string(), Ipld::Bytes(signature.to_vec())),
    ]));
    let bytes = atproto_dasl::to_vec(&raw)?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(EncodeError::RecordTooLarge(bytes.len()));
    }
    Ok(bytes)
}

fn require_string<'a>(
    fields: &'a BTreeMap<String, Ipld>,
    field: &'static str,
) -> Result<&'a str, DecodeError> {
    match fields.get(field) {
        Some(Ipld::String(value)) if !value.is_empty() => Ok(value),
        _ => Err(DecodeError::Malformed(field)),
    }
}

fn validate_codec(codec: &str) -> Result<(), DecodeError> {
    if codec.len() > 128
        || !codec
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || !codec.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        || !codec
            .as_bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        return Err(DecodeError::InvalidCodec(codec.to_string()));
    }
    Ok(())
}

fn validate_rev(rev: &str) -> Result<(), String> {
    if rev.len() != 13
        || !rev
            .as_bytes()
            .first()
            .is_some_and(|byte| matches!(byte, b'2'..=b'7' | b'a'..=b'j'))
        || !rev
            .bytes()
            .all(|byte| matches!(byte, b'2'..=b'7' | b'a'..=b'z'))
    {
        return Err(rev.to_string());
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum EncodeError {
    #[error("invalid claim CID")]
    InvalidCid,
    #[error("invalid ATProto revision: {0}")]
    InvalidRev(String),
    #[error("claim content is not a map")]
    ContentNotMap,
    #[error("domain claim content unexpectedly contains $type")]
    ContentTypeCollision,
    #[error("encoded claim record has {0} bytes; maximum is {MAX_RECORD_BYTES}")]
    RecordTooLarge(usize),
    #[error(transparent)]
    Claim(#[from] super::Error),
    #[error(transparent)]
    V1(#[from] crate::at_claim::Error),
    #[error(transparent)]
    Encode(#[from] atproto_dasl::EncodeError),
    #[error(transparent)]
    Decode(#[from] atproto_dasl::DecodeError),
}

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("claim record is not canonical DAG-CBOR")]
    NonCanonical,
    #[error("claim record has {0} bytes; maximum is {MAX_RECORD_BYTES}")]
    RecordTooLarge(usize),
    #[error("malformed claim envelope: {0}")]
    Malformed(&'static str),
    #[error("invalid claim CID")]
    InvalidCid,
    #[error("invalid claim codec: {0}")]
    InvalidCodec(String),
    #[error("invalid ATProto revision: {0}")]
    InvalidRev(String),
    #[error("codec `{codec}` cannot carry content arm `{content_type}`")]
    CodecContentMismatch { codec: String, content_type: String },
    #[error("claim CID does not match canonical content")]
    CidMismatch,
    #[error("decoded domain content did not reproduce its canonical bytes")]
    NonCanonicalDomainContent,
    #[error(transparent)]
    Claim(#[from] super::Error),
    #[error(transparent)]
    V1(#[from] crate::at_claim::Error),
    #[error(transparent)]
    Encode(#[from] atproto_dasl::EncodeError),
    #[error(transparent)]
    Decode(#[from] atproto_dasl::DecodeError),
}

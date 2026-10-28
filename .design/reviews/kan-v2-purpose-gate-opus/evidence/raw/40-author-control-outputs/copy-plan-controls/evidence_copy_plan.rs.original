//! Owner-pinned recipe for a future profile-1 to profile-3 copy.
//!
//! Decoding establishes canonical structure and the archive-ID commitment only.
//! It does not verify a source snapshot, authorize migration, certify historical
//! admission, or create an archive. Execution must independently verify the exact
//! pinned source and all retained signed requests before using this recipe.
use crate::evidence::{self, Error};
use atproto_dasl::{Cid, Ipld};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const MAX_PLAN_BYTES: usize = 4096;
const DOMAIN: &[u8] = b"tools.kan.archive.copy-plan.v1\0";
type Result<T> = std::result::Result<T, Error>;
fn invalid(message: &str) -> Error {
    Error::Schema(message.into())
}
fn map<const N: usize>(fields: [(&str, Ipld); N]) -> Ipld {
    Ipld::Map(
        fields
            .into_iter()
            .map(|(k, v)| (k.into(), v))
            .collect::<BTreeMap<_, _>>(),
    )
}

/// Coordinates and commitments supplied by a separately verified source planner.
/// Constructing this value confers no authority over a legacy archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub through: u64,
    pub tip: Option<Cid>,
    pub digest: [u8; 32],
    pub historical_issuer: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub scope: [u8; 32],
    pub issuer: String,
}
#[derive(Debug, Clone)]
pub struct Plan {
    bytes: Vec<u8>,
    source: Source,
    target: Target,
    nonce: [u8; 32],
    archive: [u8; 32],
}
fn did(value: &Ipld, require_p256: bool) -> Result<String> {
    let did = evidence::string(value, 80)?;
    // Bound before the dependency reads a multikey prefix.
    if !(56..=80).contains(&did.len()) || !did.starts_with("did:key:z") || !did.is_ascii() {
        return Err(invalid("copy-plan issuer encoding"));
    }
    let (algorithm, key) =
        atrium_crypto::did::parse_did_key(did).map_err(|_| invalid("copy-plan issuer key"))?;
    if require_p256 && algorithm != atrium_crypto::Algorithm::P256 {
        return Err(invalid("copy-plan current issuer must use P-256"));
    }
    if atrium_crypto::did::format_did_key(algorithm, &key)
        .map_err(|_| invalid("copy-plan issuer point"))?
        != did
    {
        return Err(invalid("copy-plan issuer must be canonical"));
    }
    crate::evidence_service::author(did).map_err(|_| invalid("copy-plan static issuer"))?;
    Ok(did.into())
}
fn bytes32(value: &Ipld) -> Result<[u8; 32]> {
    Ok(evidence::bytes(value, 32)?
        .try_into()
        .expect("checked size"))
}
impl Plan {
    /// Encode owner inputs; caller must independently establish their truth.
    /// A fresh owner-generated nonce is required for each distinct destination.
    pub fn new(source: Source, target: Target, nonce: [u8; 32]) -> Result<Self> {
        let value = map([
            ("recipe", Ipld::Integer(1)),
            ("sourceProfile", Ipld::Integer(1)),
            ("targetProfile", Ipld::Integer(3)),
            ("sourceThrough", Ipld::Integer(i128::from(source.through))),
            (
                "sourceTip",
                source.tip.map(Ipld::Link).unwrap_or(Ipld::Null),
            ),
            ("sourceDigest", Ipld::Bytes(source.digest.to_vec())),
            ("historicalIssuer", Ipld::String(source.historical_issuer)),
            ("scopeToken", Ipld::Bytes(target.scope.to_vec())),
            ("issuer", Ipld::String(target.issuer)),
            ("nonce", Ipld::Bytes(nonce.to_vec())),
        ]);
        let bytes = atproto_dasl::to_vec(&value).map_err(|_| invalid("copy-plan encoding"))?;
        Self::decode(&bytes)
    }
    /// Verify a bounded canonical recipe. This is not a source-verification result.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let value = evidence::canonical_value(bytes, MAX_PLAN_BYTES)?;
        let b = evidence::closed(
            &value,
            &[
                "recipe",
                "sourceProfile",
                "targetProfile",
                "sourceThrough",
                "sourceTip",
                "sourceDigest",
                "historicalIssuer",
                "scopeToken",
                "issuer",
                "nonce",
            ],
        )?;
        if b["recipe"] != Ipld::Integer(1)
            || b["sourceProfile"] != Ipld::Integer(1)
            || b["targetProfile"] != Ipld::Integer(3)
        {
            return Err(invalid("unsupported copy-plan profile or recipe"));
        }
        let through = evidence::uint(&b["sourceThrough"])? as u64;
        let tip = match &b["sourceTip"] {
            Ipld::Null if through == 0 => None,
            link if through > 0 => Some(evidence::link(link, 0x71)?.clone()),
            _ => return Err(invalid("copy-plan empty source frontier")),
        };
        let source = Source {
            through,
            tip,
            digest: bytes32(&b["sourceDigest"])?,
            historical_issuer: did(&b["historicalIssuer"], false)?,
        };
        let target = Target {
            scope: bytes32(&b["scopeToken"])?,
            issuer: did(&b["issuer"], true)?,
        };
        let nonce = bytes32(&b["nonce"])?;
        let mut hash = Sha256::new();
        hash.update(DOMAIN);
        hash.update(bytes);
        Ok(Self {
            bytes: bytes.to_vec(),
            source,
            target,
            nonce,
            archive: hash.finalize().into(),
        })
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn source(&self) -> &Source {
        &self.source
    }
    pub fn target(&self) -> &Target {
        &self.target
    }
    pub fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }
    pub fn archive_id(&self) -> [u8; 32] {
        self.archive
    }
    /// Compare to an owner pin; never choose the expected value from this plan.
    pub fn check_archive(&self, expected: &[u8; 32]) -> Result<()> {
        if &self.archive != expected {
            return Err(invalid("copy-plan owner archive mismatch"));
        }
        Ok(())
    }
}

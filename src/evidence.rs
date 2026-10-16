//! Experimental RFC 4 reference codec. Pure structure, never proof of authority,
//! signature validity, durability, complete inventory, or decryptability.

use std::collections::{BTreeMap, BTreeSet};

use atproto_dasl::{drisl, Cid, Ipld};

use crate::identity::{authorship::Author, scope_inception::ScopeId};

pub const MAX_RECORD_BYTES: usize = 65_536;
pub const MAX_SAFE_INTEGER: i128 = 9_007_199_254_740_991;

#[derive(Debug, thiserror::Error)]
#[error("invalid evidence record: {0}")]
pub struct Error(pub String);

fn fail(message: &str) -> Error {
    Error(message.into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Capture,
    Manifest,
    Receipt,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Capture => "capture",
            Self::Manifest => "manifest",
            Self::Receipt => "receipt",
        }
    }
}

/// Constructible only by the bounded codec. Validation is syntactic, not trust.
#[derive(Debug, Clone)]
pub struct Record {
    kind: Kind,
    body: BTreeMap<String, Ipld>,
    bytes: Vec<u8>,
    cid: Cid,
}

impl Record {
    pub fn kind(&self) -> Kind {
        self.kind
    }

    pub fn body(&self) -> &BTreeMap<String, Ipld> {
        &self.body
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn cid(&self) -> &Cid {
        &self.cid
    }

    /// Exact bytes for a future signature envelope; no signing or verification.
    pub fn signing_preimage(&self) -> Vec<u8> {
        let value = BTreeMap::from([
            ("domain", Ipld::String("tools.kan.evidence.v1".into())),
            ("kind", Ipld::String(self.kind.as_str().into())),
            ("record", Ipld::Link(self.cid.clone())),
        ]);
        atproto_dasl::to_vec(&value).expect("bounded infallible signing input")
    }
}

#[derive(Debug, Clone)]
pub enum Decoded {
    Known(Record),
    /// Canonical and bounded, but not semantically validated or admissible.
    Unsupported {
        bytes: Vec<u8>,
        cid: Cid,
    },
}

/// Encode through the same validation path as decoding. Input is never repaired.
pub fn encode(value: &Ipld) -> Result<Decoded, Error> {
    scalars(value, 0)?;
    let bytes = atproto_dasl::to_vec(value).map_err(|e| Error(e.to_string()))?;
    decode(&bytes)
}

pub fn decode(bytes: &[u8]) -> Result<Decoded, Error> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(fail("record exceeds 65536 bytes"));
    }
    let config = drisl::DecodeConfig {
        max_depth: 32,
        max_alloc: MAX_RECORD_BYTES,
        max_array_elements: MAX_RECORD_BYTES,
        max_map_entries: MAX_RECORD_BYTES,
        no_floats: true,
        ..Default::default()
    };
    let value: Ipld =
        drisl::from_slice_with_config(bytes, config).map_err(|e| Error(e.to_string()))?;
    scalars(&value, 0)?;
    if atproto_dasl::to_vec(&value).map_err(|e| Error(e.to_string()))? != bytes {
        return Err(fail("noncanonical bytes"));
    }
    let envelope = closed(&value, &["v", "kind", "body"])?;
    let version = uint(&envelope["v"])?;
    if version == 0 {
        return Err(fail("version zero"));
    }
    let name = token(&envelope["kind"])?;
    let body = map(&envelope["body"])?;
    let cid = crate::cid::content_cid(&value).map_err(|e| Error(e.to_string()))?;
    let kind = match (version, name) {
        (1, "capture") => Kind::Capture,
        (1, "manifest") => Kind::Manifest,
        (1, "receipt") => Kind::Receipt,
        _ => {
            return Ok(Decoded::Unsupported {
                bytes: bytes.to_vec(),
                cid,
            })
        }
    };
    match kind {
        Kind::Capture => capture(&envelope["body"]),
        Kind::Manifest => manifest(&envelope["body"]),
        Kind::Receipt => receipt(&envelope["body"]),
    }?;
    Ok(Decoded::Known(Record {
        kind,
        body: body.clone(),
        bytes: bytes.to_vec(),
        cid,
    }))
}

fn scalars(value: &Ipld, depth: usize) -> Result<(), Error> {
    if depth > 32 || (depth == 32 && matches!(value, Ipld::List(_) | Ipld::Map(_))) {
        return Err(fail("nesting exceeds 32"));
    }
    match value {
        Ipld::Integer(_) => {
            uint(value)?;
        }
        Ipld::Float(_) => return Err(fail("floats forbidden")),
        Ipld::List(values) => {
            for value in values {
                scalars(value, depth + 1)?;
            }
        }
        Ipld::Map(values) => {
            for value in values.values() {
                scalars(value, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn map(value: &Ipld) -> Result<&BTreeMap<String, Ipld>, Error> {
    if let Ipld::Map(value) = value {
        Ok(value)
    } else {
        Err(fail("expected map"))
    }
}

fn closed<'a>(value: &'a Ipld, fields: &[&str]) -> Result<&'a BTreeMap<String, Ipld>, Error> {
    let value = map(value)?;
    if value.len() != fields.len() || fields.iter().any(|field| !value.contains_key(*field)) {
        return Err(fail("missing or unknown field"));
    }
    Ok(value)
}

fn uint(value: &Ipld) -> Result<i128, Error> {
    match value {
        Ipld::Integer(n) if (0..=MAX_SAFE_INTEGER).contains(n) => Ok(*n),
        _ => Err(fail("expected unsigned safe integer")),
    }
}

fn bytes(value: &Ipld, length: usize) -> Result<&[u8], Error> {
    match value {
        Ipld::Bytes(value) if value.len() == length => Ok(value),
        _ => Err(fail("wrong byte string length")),
    }
}

fn string(value: &Ipld, max: usize) -> Result<&str, Error> {
    match value {
        Ipld::String(value) if !value.is_empty() && value.len() <= max => Ok(value),
        _ => Err(fail("wrong string length or type")),
    }
}

fn token(value: &Ipld) -> Result<&str, Error> {
    let value = string(value, 64)?;
    if !value.as_bytes()[0].is_ascii_lowercase()
        || !value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
    {
        return Err(fail("invalid protocol token"));
    }
    Ok(value)
}

fn list(value: &Ipld) -> Result<&[Ipld], Error> {
    match value {
        Ipld::List(value) if value.len() <= 128 => Ok(value),
        _ => Err(fail("expected list of at most 128 items")),
    }
}

fn link(value: &Ipld, codec: u8) -> Result<&Cid, Error> {
    if let Ipld::Link(cid) = value {
        let raw = cid.to_bytes();
        if raw.len() == 36 && raw[..4] == [1, codec, 0x12, 0x20] {
            return Ok(cid);
        }
    }
    Err(fail("wrong CID profile"))
}

fn author(value: &Ipld) -> Result<(), Error> {
    let encoded = atproto_dasl::to_vec(value).map_err(|e| Error(e.to_string()))?;
    let _: Author = drisl::from_slice(&encoded).map_err(|e| Error(e.to_string()))?;
    Ok(())
}

fn chain(position: &Ipld, previous: &Ipld) -> Result<(), Error> {
    if uint(position)? == 0 {
        if !matches!(previous, Ipld::Null) {
            return Err(fail("genesis has predecessor"));
        }
    } else {
        link(previous, 0x71)?;
    }
    Ok(())
}

fn capture(value: &Ipld) -> Result<(), Error> {
    let b = closed(
        value,
        &[
            "observer",
            "scope",
            "stream",
            "sequence",
            "previous",
            "occurredAt",
            "eventType",
            "payloads",
            "parents",
            "coverage",
        ],
    )?;
    author(&b["observer"])?;
    let scope: [u8; 34] = bytes(&b["scope"], 34)?.try_into().expect("checked length");
    ScopeId::from_bytes(scope).map_err(|e| Error(e.to_string()))?;
    bytes(&b["stream"], 16)?;
    chain(&b["sequence"], &b["previous"])?;
    uint(&b["occurredAt"])?;
    token(&b["eventType"])?;
    for payload in list(&b["payloads"])? {
        let p = closed(payload, &["sha256", "length", "mediaType"])?;
        bytes(&p["sha256"], 32)?;
        uint(&p["length"])?;
        string(&p["mediaType"], 256)?;
    }
    let mut seen = BTreeSet::new();
    for parent in list(&b["parents"])? {
        if !seen.insert(link(parent, 0x71)?.to_bytes()) {
            return Err(fail("duplicate parent"));
        }
    }
    let coverage = closed(&b["coverage"], &["complete", "missing"])?;
    let missing = list(&coverage["missing"])?;
    let mut previous = None;
    for reason in missing {
        let reason = token(reason)?;
        if previous.is_some_and(|p| p >= reason) {
            return Err(fail("unsorted or duplicate coverage reasons"));
        }
        previous = Some(reason);
    }
    if coverage["complete"] != Ipld::Bool(missing.is_empty()) {
        return Err(fail("inconsistent coverage"));
    }
    Ok(())
}

fn manifest(value: &Ipld) -> Result<(), Error> {
    let b = closed(
        value,
        &[
            "writer",
            "scopeToken",
            "operation",
            "position",
            "previous",
            "entries",
        ],
    )?;
    author(&b["writer"])?;
    bytes(&b["scopeToken"], 32)?;
    bytes(&b["operation"], 16)?;
    chain(&b["position"], &b["previous"])?;
    let entries = list(&b["entries"])?;
    if entries.is_empty() {
        return Err(fail("empty manifest"));
    }
    let mut previous = None;
    for entry in entries {
        let entry = closed(entry, &["slot", "ciphertext", "length"])?;
        let slot = bytes(&entry["slot"], 32)?;
        if previous.is_some_and(|p| p >= slot) {
            return Err(fail("unsorted or duplicate slots"));
        }
        previous = Some(slot);
        link(&entry["ciphertext"], 0x55)?;
        if uint(&entry["length"])? == 0 {
            return Err(fail("empty ciphertext"));
        }
    }
    Ok(())
}

fn receipt(value: &Ipld) -> Result<(), Error> {
    let b = closed(
        value,
        &[
            "issuer",
            "manifest",
            "scopeToken",
            "operation",
            "position",
            "durability",
            "issuedAt",
        ],
    )?;
    author(&b["issuer"])?;
    link(&b["manifest"], 0x71)?;
    bytes(&b["scopeToken"], 32)?;
    bytes(&b["operation"], 16)?;
    uint(&b["position"])?;
    uint(&b["issuedAt"])?;
    if string(&b["durability"], 64)? != "remote-durable" {
        return Err(fail("unknown durability statement"));
    }
    Ok(())
}

/// Structural binding only. This does not validate the issuer or durable commit.
pub fn binds(receipt: &Record, manifest: &Record) -> bool {
    receipt.kind == Kind::Receipt
        && manifest.kind == Kind::Manifest
        && receipt.body["manifest"] == Ipld::Link(manifest.cid.clone())
        && ["scopeToken", "operation", "position"]
            .iter()
            .all(|key| receipt.body[*key] == manifest.body[*key])
}

#[derive(Debug, PartialEq, Eq)]
pub enum Inventory {
    AccessLimited,
    Incomplete,
    Present { matches: Vec<Cid>, complete: bool },
    AbsentAtSnapshot { snapshot: Cid },
}

/// Caller must establish authorization and actual coverage. No trust-filter
/// exclusion input exists: this operates on the authorized source inventory.
pub fn inventory(
    authorized: bool,
    requested: &Cid,
    covered: Option<&Cid>,
    fully_indexed: bool,
    unsupported: usize,
    matches: Vec<Cid>,
) -> Inventory {
    if !authorized {
        return Inventory::AccessLimited;
    }
    if covered != Some(requested) {
        return Inventory::Incomplete;
    }
    let complete = fully_indexed && unsupported == 0;
    if !matches.is_empty() {
        return Inventory::Present { matches, complete };
    }
    if complete {
        Inventory::AbsentAtSnapshot {
            snapshot: requested.clone(),
        }
    } else {
        Inventory::Incomplete
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Operation {
    Unauthorized,
    Duplicate,
    Conflict,
    NewOperation,
}

/// Pure retry model, not an admission/commit API. Existing commitment must come
/// from lookup by the exact (scopeToken, writer principal, operation) key.
pub fn operation(admitted: bool, existing: Option<&Cid>, candidate: &Cid) -> Operation {
    match (admitted, existing) {
        (false, _) => Operation::Unauthorized,
        (true, Some(cid)) if cid == candidate => Operation::Duplicate,
        (true, Some(_)) => Operation::Conflict,
        (true, None) => Operation::NewOperation,
    }
}

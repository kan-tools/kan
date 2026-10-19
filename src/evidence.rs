//! Experimental RFC 4 reference codec. Pure structure, never proof of authority,
//! signature validity, durability, complete inventory, or decryptability.

use std::collections::{BTreeMap, BTreeSet};

use atproto_dasl::{Cid, Ipld};

use crate::identity::{authorship::Author, control::IdentityVersion, scope_inception::ScopeId};

pub const MAX_RECORD_BYTES: usize = 65_536;
pub const MAX_SAFE_INTEGER: i128 = 9_007_199_254_740_991;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid canonical evidence: {0}")]
    Canonical(String),
    #[error("invalid evidence schema: {0}")]
    Schema(String),
}

impl Error {
    pub fn class(&self) -> &'static str {
        match self {
            Self::Canonical(_) => "canonical",
            Self::Schema(_) => "schema",
        }
    }
}

fn canonical(message: &str) -> Error {
    Error::Canonical(message.into())
}

fn fail(message: &str) -> Error {
    Error::Schema(message.into())
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
    let bytes = atproto_dasl::to_vec(value).map_err(|e| Error::Schema(e.to_string()))?;
    decode(&bytes)
}

pub fn decode(bytes: &[u8]) -> Result<Decoded, Error> {
    let value = canonical_value(bytes, MAX_RECORD_BYTES)?;
    let envelope = closed(&value, &["v", "kind", "body"])?;
    let version = uint(&envelope["v"])?;
    if version == 0 {
        return Err(fail("version zero"));
    }
    let name = token(&envelope["kind"])?;
    let body = map(&envelope["body"])?;
    let cid = crate::cid::content_cid(&value).map_err(|e| Error::Schema(e.to_string()))?;
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

/// Shared strict parser for bounded protocol values, preserving byte/link types.
pub(crate) fn canonical_value(bytes: &[u8], maximum: usize) -> Result<Ipld, Error> {
    if bytes.len() > maximum {
        return Err(canonical("value exceeds byte limit"));
    }
    let mut parser = Parser { bytes, offset: 0 };
    let value = parser.item(0)?;
    if parser.offset != bytes.len() {
        return Err(canonical("trailing bytes"));
    }
    scalars(&value, 0)?;
    if atproto_dasl::to_vec(&value).map_err(|e| Error::Schema(e.to_string()))? != bytes {
        return Err(canonical("noncanonical bytes"));
    }
    Ok(value)
}

/// Byte types are determined by CBOR headers, never by payload heuristics.
struct Parser<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Parser<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        if length > self.bytes.len() - self.offset {
            return Err(canonical("truncated value"));
        }
        let start = self.offset;
        self.offset += length;
        Ok(&self.bytes[start..self.offset])
    }

    fn header(&mut self) -> Result<(u8, u64), Error> {
        let byte = self.take(1)?[0];
        let major = byte >> 5;
        let ai = byte & 31;
        let value = match ai {
            0..=23 => u64::from(ai),
            24..=27 => {
                let width = 1 << (ai - 24);
                let value = self
                    .take(width)?
                    .iter()
                    .fold(0u64, |v, b| (v << 8) | u64::from(*b));
                let minimum = [24, 256, 65_536, 4_294_967_296][usize::from(ai - 24)];
                if value < minimum {
                    return Err(canonical("nonminimal header"));
                }
                value
            }
            _ => return Err(canonical("indefinite or reserved header")),
        };
        Ok((major, value))
    }

    fn length(&self, value: u64) -> Result<usize, Error> {
        let n = usize::try_from(value).map_err(|_| canonical("length overflow"))?;
        if n > self.bytes.len() - self.offset {
            return Err(canonical("declared length exceeds remaining input"));
        }
        Ok(n)
    }

    fn item(&mut self, depth: usize) -> Result<Ipld, Error> {
        if depth > 32 {
            return Err(canonical("nesting exceeds 32"));
        }
        let (major, n) = self.header()?;
        match major {
            0 => Ok(Ipld::Integer(i128::from(n))),
            2 => {
                let length = self.length(n)?;
                Ok(Ipld::Bytes(self.take(length)?.to_vec()))
            }
            3 => {
                let length = self.length(n)?;
                let text = std::str::from_utf8(self.take(length)?)
                    .map_err(|_| canonical("invalid UTF-8"))?;
                Ok(Ipld::String(text.into()))
            }
            4 | 5 => {
                if depth == 32 {
                    return Err(canonical("nesting exceeds 32"));
                }
                let count = self.length(n)?;
                if major == 4 {
                    let mut values = Vec::new();
                    for _ in 0..count {
                        values.push(self.item(depth + 1)?);
                    }
                    Ok(Ipld::List(values))
                } else {
                    let mut values = BTreeMap::new();
                    let mut previous: Option<&[u8]> = None;
                    for _ in 0..count {
                        let start = self.offset;
                        let Ipld::String(key) = self.item(depth + 1)? else {
                            return Err(canonical("map key must be text"));
                        };
                        let encoded = &self.bytes[start..self.offset];
                        if previous.is_some_and(|p| p >= encoded) {
                            return Err(canonical("duplicate or unordered map key"));
                        }
                        previous = Some(encoded);
                        values.insert(key, self.item(depth + 1)?);
                    }
                    Ok(Ipld::Map(values))
                }
            }
            6 if n == 42 => {
                // Read the immediate header: maps and nested tags cannot stand in for bytes.
                let (major, length) = self.header()?;
                if major != 2 {
                    return Err(canonical("CID tag requires bytes"));
                }
                let length = self.length(length)?;
                let raw = self.take(length)?;
                if raw.first() != Some(&0) {
                    return Err(canonical("CID requires identity prefix"));
                }
                let cid = Cid::from_bytes(&raw[1..]).map_err(|_| canonical("invalid CID"))?;
                if cid.to_bytes() != raw[1..] {
                    return Err(canonical("noncanonical or trailing CID bytes"));
                }
                Ok(Ipld::Link(cid))
            }
            7 if n == 20 => Ok(Ipld::Bool(false)),
            7 if n == 21 => Ok(Ipld::Bool(true)),
            7 if n == 22 => Ok(Ipld::Null),
            _ => Err(canonical("unsupported scalar or tag")),
        }
    }
}

fn scalars(value: &Ipld, depth: usize) -> Result<(), Error> {
    if depth > 32 || (depth == 32 && matches!(value, Ipld::List(_) | Ipld::Map(_))) {
        return Err(canonical("nesting exceeds 32"));
    }
    match value {
        Ipld::Integer(_) => {
            uint(value).map_err(|_| canonical("integer outside safe unsigned range"))?;
        }
        Ipld::Float(_) => return Err(canonical("floats forbidden")),
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

pub(crate) fn closed<'a>(
    value: &'a Ipld,
    fields: &[&str],
) -> Result<&'a BTreeMap<String, Ipld>, Error> {
    let value = map(value)?;
    if value.len() != fields.len() || fields.iter().any(|field| !value.contains_key(*field)) {
        return Err(fail("missing or unknown field"));
    }
    Ok(value)
}

pub(crate) fn uint(value: &Ipld) -> Result<i128, Error> {
    match value {
        Ipld::Integer(n) if (0..=MAX_SAFE_INTEGER).contains(n) => Ok(*n),
        _ => Err(fail("expected unsigned safe integer")),
    }
}

pub(crate) fn bytes(value: &Ipld, length: usize) -> Result<&[u8], Error> {
    match value {
        Ipld::Bytes(value) if value.len() == length => Ok(value),
        _ => Err(fail("wrong byte string length")),
    }
}

pub(crate) fn string(value: &Ipld, max: usize) -> Result<&str, Error> {
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

pub(crate) fn link(value: &Ipld, codec: u8) -> Result<&Cid, Error> {
    if let Ipld::Link(cid) = value {
        let raw = cid.to_bytes();
        if raw.len() == 36 && raw[..4] == [1, codec, 0x12, 0x20] {
            return Ok(cid);
        }
    }
    Err(fail("wrong CID profile"))
}

pub(crate) fn author(value: &Ipld) -> Result<(), Error> {
    // Preserve the strict parser's types through the identity boundary. Generic
    // drisl IPLD deserialization can reinterpret untagged bytes as a CID.
    let fields = closed(
        value,
        &["principal", "verificationMethod", "identityVersion"],
    )?;
    let version = closed(&fields["identityVersion"], &["kind", "value"])?;
    let identity = match (&version["kind"], &version["value"]) {
        (Ipld::String(kind), Ipld::Null) if kind == "static" => IdentityVersion::Static,
        (Ipld::String(kind), Ipld::Link(cid)) if kind == "event" => {
            IdentityVersion::Event(cid.clone())
        }
        (Ipld::String(kind), Ipld::Link(cid)) if kind == "documentCid" => {
            IdentityVersion::DocumentCid(cid.clone())
        }
        (Ipld::String(kind), Ipld::String(id)) if kind == "versionId" && !id.is_empty() => {
            IdentityVersion::VersionId(id.clone())
        }
        _ => return Err(fail("invalid identity version shape")),
    };
    Author::new(
        string(&fields["principal"], MAX_RECORD_BYTES)?.into(),
        string(&fields["verificationMethod"], MAX_RECORD_BYTES)?.into(),
        identity,
    )
    .map_err(|e| Error::Schema(e.to_string()))?;
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
    ScopeId::from_bytes(scope).map_err(|e| Error::Schema(e.to_string()))?;
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

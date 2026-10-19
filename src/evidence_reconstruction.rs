//! Disposable interpretations of retained capture bytes. No storage or authority.
//!
//! Callers must obtain bytes through an authorized, verified occurrence. Successful
//! decoding does not verify a signature, grant access, or prove capture coverage.
use crate::evidence_capture::{Event, Header, CHUNK};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};
use std::{fmt, ops::Range};

pub const MAX_HEADER: usize = 128 * 1024;
pub const MAX_FRAME: usize = 9 + MAX_HEADER + CHUNK;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unsupported {
    Envelope,
    Version,
    Observer,
    Event,
    Outcome,
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    #[error("capture frame exceeds decoder limits")]
    Limit,
    #[error("malformed capture envelope")]
    Envelope,
    #[error("malformed capture header")]
    Header,
    #[error("capture event contradicts its body shape")]
    Body,
}

#[derive(Debug)]
pub enum Decoded<'a> {
    /// No recognized capture magic; the caller retains its original raw input.
    Opaque,
    /// No semantic interpretation. The caller still retains its original input.
    Unsupported(Unsupported),
    Capture(Frame<'a>),
}

#[derive(Debug)]
pub struct Frame<'a> {
    pub header: Header,
    pub body: &'a [u8],
    /// Exclusive byte coordinates in the original decrypted frame, not characters.
    pub header_span: Range<usize>,
    pub body_span: Range<usize>,
}

/// Decode one complete decrypted frame, never a source-range fragment.
///
/// Bounds apply before JSON allocation. Nested maps reject duplicate keys,
/// including escaped aliases, even in unsupported variants. JSON's nesting limit
/// remains enabled. Unknown variants are retained explicitly; recognized shapes
/// are strict. Event coordinates are claims, not proof of coherent assembly.
/// This type deliberately has no wire Serialize implementation: a later API must
/// encode u64 coordinates without JavaScript rounding.
pub fn decode(bytes: &[u8]) -> Result<Decoded<'_>, Error> {
    if !bytes.starts_with(b"KANC") {
        return Ok(Decoded::Opaque);
    }
    if bytes.len() > MAX_FRAME {
        return Err(Error::Limit);
    }
    let Some(&version) = bytes.get(4) else {
        return Err(Error::Envelope);
    };
    if version != b'2' {
        return Ok(Decoded::Unsupported(Unsupported::Envelope));
    }
    let length: [u8; 4] = bytes.get(5..9).ok_or(Error::Envelope)?.try_into().unwrap();
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_HEADER {
        return Err(Error::Limit);
    }
    let end = 9usize.checked_add(length).ok_or(Error::Envelope)?;
    let json = bytes.get(9..end).ok_or(Error::Envelope)?;
    let body = &bytes[end..];
    if body.len() > CHUNK {
        return Err(Error::Limit);
    }
    let Unique(value) = serde_json::from_slice(json).map_err(|_| Error::Header)?;
    let object = value.as_object().ok_or(Error::Header)?;
    let version = object
        .get("version")
        .and_then(Value::as_u64)
        .ok_or(Error::Header)?;
    if version != 2 {
        return Ok(Decoded::Unsupported(Unsupported::Version));
    }
    let observer = object
        .get("observer")
        .and_then(Value::as_str)
        .ok_or(Error::Header)?;
    if !matches!(observer, "collector" | "gateway") {
        return Ok(Decoded::Unsupported(Unsupported::Observer));
    }
    let event = object
        .get("event")
        .and_then(Value::as_object)
        .ok_or(Error::Header)?;
    let kind = event
        .get("type")
        .and_then(Value::as_str)
        .ok_or(Error::Header)?;
    if !matches!(
        kind,
        "started"
            | "request-chunk"
            | "request-end"
            | "forwarding-intent"
            | "transport-link"
            | "http-metadata-chunk"
            | "http-metadata"
            | "response-head"
            | "response-chunk"
            | "terminal"
    ) {
        return Ok(Decoded::Unsupported(Unsupported::Event));
    }
    if kind == "terminal" {
        let outcome = event
            .get("outcome")
            .and_then(Value::as_str)
            .ok_or(Error::Header)?;
        if !matches!(outcome, "completed" | "outcome-unknown") {
            return Ok(Decoded::Unsupported(Unsupported::Outcome));
        }
    }
    let header: Header = serde_json::from_value(value).map_err(|_| Error::Header)?;
    if !identifier(&header.attempt)
        || matches!(&header.event, Event::TransportLink { exchange } if !identifier(exchange))
        || matches!(&header.event, Event::Started { method, route } if method.len()>32 || route.len()>2048)
    {
        return Err(Error::Header);
    }
    if !body.is_empty()
        && !matches!(
            header.event,
            Event::RequestChunk { .. }
                | Event::ResponseChunk { .. }
                | Event::HttpMetadataChunk { .. }
        )
    {
        return Err(Error::Body);
    }
    Ok(Decoded::Capture(Frame {
        header,
        body,
        header_span: 9..end,
        body_span: end..bytes.len(),
    }))
}

fn identifier(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// Deserialize without JSON map's last-write-wins semantics. Constructing Value
// only after rejecting each duplicate lets variant detection remain forward
// compatible without hiding ambiguous fields inside unknown events.
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Strict;
        impl<'de> Visitor<'de> for Strict {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("unambiguous JSON")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Unique, E> {
                Ok(Unique(Value::Bool(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Unique, E> {
                Ok(Unique(Value::Number(v.into())))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Unique, E> {
                Ok(Unique(Value::Number(v.into())))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Unique, E> {
                Number::from_f64(v)
                    .map(|n| Unique(Value::Number(n)))
                    .ok_or_else(|| E::custom("nonfinite JSON"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Unique, E> {
                Ok(Unique(Value::String(v.into())))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Unique, A::Error> {
                let mut values = Vec::new();
                while let Some(Unique(v)) = seq.next_element()? {
                    values.push(v);
                }
                Ok(Unique(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Unique, A::Error> {
                let mut values = Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom("duplicate JSON key"));
                    }
                    let Unique(value) = map.next_value()?;
                    values.insert(key, value);
                }
                Ok(Unique(Value::Object(values)))
            }
        }
        d.deserialize_any(Strict)
    }
}

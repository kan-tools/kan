//! Canonical signed recovery observations. Authentication is not claim truth.
//!
//! This pure codec neither opens a bundle nor verifies member/output commitments,
//! loss coverage, restoration membership, publication state or durable storage.
//! Those checks belong to the complete bundle verifier before any mutation.
use crate::{
    evidence::{self, Error},
    sign::Identity,
};
use atproto_dasl::{Cid, Ipld};
use std::collections::BTreeMap;

pub const MAX_ENVELOPE: usize = 16 * 1024;
pub const DOMAIN: &str = "tools.kan.recovery.observation.v1";
type Result<T> = std::result::Result<T, Error>;
fn invalid(reason: &str) -> Error {
    Error::Schema(reason.into())
}
fn require(ok: bool, reason: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(invalid(reason))
    }
}
fn map<const N: usize>(fields: [(&str, Ipld); N]) -> Ipld {
    Ipld::Map(fields.into_iter().map(|(k, v)| (k.into(), v)).collect())
}
fn encode(v: &Ipld) -> Result<Vec<u8>> {
    atproto_dasl::to_vec(v).map_err(|e| invalid(&e.to_string()))
}
fn closed<'a>(v: &'a Ipld, keys: &[&str], reason: &str) -> Result<&'a BTreeMap<String, Ipld>> {
    evidence::closed(v, keys).map_err(|_| invalid(reason))
}
fn uint(v: &Ipld, positive: bool, max: u64) -> Result<u64> {
    let n = evidence::uint(v).map_err(|_| invalid("integer"))? as u64;
    require(n >= u64::from(positive) && n <= max, "integer")?;
    Ok(n)
}
fn blob(v: &Ipld, n: usize) -> Result<&[u8]> {
    evidence::bytes(v, n).map_err(|_| invalid("byte-width"))
}
fn link(v: &Ipld, kind: u8) -> Result<&Cid> {
    evidence::link(v, kind).map_err(|_| invalid("link-profile"))
}
fn did(s: &str) -> Result<()> {
    require(
        (56..=80).contains(&s.len()) && s.is_ascii() && s.starts_with("did:key:z"),
        "did-key",
    )?;
    let (algorithm, key) = atrium_crypto::did::parse_did_key(s).map_err(|_| invalid("did-key"))?;
    require(algorithm == atrium_crypto::Algorithm::P256, "did-key")?;
    let canonical =
        atrium_crypto::did::format_did_key(algorithm, &key).map_err(|_| invalid("did-key"))?;
    require(canonical == s, "did-key")
}

/// Independently supplied owner pins; never select these from the envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Context {
    pub bundle: [u8; 32],
    pub profile: u8,
    pub archive: [u8; 32],
    pub scope: [u8; 32],
    pub issuer: String,
    pub observer: String,
}
impl Context {
    fn validate(&self) -> Result<()> {
        require(matches!(self.profile, 2 | 3), "profile")?;
        did(&self.issuer)?;
        did(&self.observer)
    }
}

/// A wire-valid, observer-authenticated claim in a chain under owner pins.
/// This is deliberately not named a verified bundle or a publication proof.
/// Its private fields prevent callers from forging a trusted predecessor.
#[derive(Clone, Debug)]
pub struct Authenticated {
    context: Context,
    bytes: Vec<u8>,
    statement: Vec<u8>,
    value: Ipld,
    cid: Cid,
    sequence: u64,
}
impl Authenticated {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn statement_bytes(&self) -> &[u8] {
        &self.statement
    }
    pub fn statement(&self) -> &Ipld {
        &self.value
    }
    pub fn statement_cid(&self) -> &Cid {
        &self.cid
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn context(&self) -> &Context {
        &self.context
    }
    pub fn signing_preimage(&self) -> Vec<u8> {
        preimage(&self.cid).expect("bounded preimage")
    }
}
fn preimage(cid: &Cid) -> Result<Vec<u8>> {
    encode(&map([
        ("domain", Ipld::String(DOMAIN.into())),
        ("statement", Ipld::Link(cid.clone())),
    ]))
}
fn frontier(v: &Ipld) -> Result<()> {
    let f = closed(
        v,
        &["through", "manifest", "attestation"],
        "frontier-fields",
    )?;
    if uint(&f["through"], false, evidence::MAX_SAFE_INTEGER as u64)? == 0 {
        require(
            f["manifest"] == Ipld::Null && f["attestation"] == Ipld::Null,
            "frontier-empty",
        )
    } else {
        link(&f["manifest"], 0x71)?;
        link(&f["attestation"], 0x71)?;
        Ok(())
    }
}
fn body(event: &str, v: &Ipld) -> Result<()> {
    let fields: &[&str] = match event {
        "created" => &["recipe", "member", "frontier"],
        "unavailable" => &["member", "entries"],
        "restored" => &["member", "cid", "length", "candidate"],
        "publication-intent" => &["attempt", "member", "restorations", "output", "frontier"],
        "publication-observed" => &["attempt", "intent", "output", "frontier"],
        "publication-failed" => &["attempt", "intent", "reason"],
        _ => return Err(invalid("event")),
    };
    let b = closed(v, fields, "body-fields")?;
    if let Some(v) = b.get("member") {
        blob(v, 32)?;
    }
    if let Some(v) = b.get("frontier") {
        frontier(v)?;
    }
    match event {
        "created" => require(b["recipe"] == Ipld::Integer(1), "recipe")?,
        "unavailable" => {
            let Ipld::List(entries) = &b["entries"] else {
                return Err(invalid("entries-bound"));
            };
            require((1..=32).contains(&entries.len()), "entries-bound")?;
            let mut previous = None;
            for entry in entries {
                let e = closed(
                    entry,
                    &["occurrence", "cid", "expectedLength", "state"],
                    "entry-fields",
                )?;
                let occurrence = if e["occurrence"] == Ipld::Null {
                    None
                } else {
                    Some(uint(
                        &e["occurrence"],
                        true,
                        evidence::MAX_SAFE_INTEGER as u64,
                    )?)
                };
                let cid = link(&e["cid"], 0x55)?;
                let length = if e["expectedLength"] == Ipld::Null {
                    None
                } else {
                    Some(uint(&e["expectedLength"], true, 4 * 1024 * 1024)?)
                };
                require(
                    occurrence.is_none() || length.is_some(),
                    "occurrence-length",
                )?;
                require(
                    matches!(&e["state"],Ipld::String(s) if matches!(s.as_str(),"missing"|"corrupt")),
                    "availability",
                )?;
                // Text lexical order is part of the recipe; binary CID order differs.
                let coordinate = (
                    occurrence.is_none(),
                    occurrence.unwrap_or(0),
                    cid.to_string(),
                );
                require(
                    previous.as_ref().is_none_or(|p| p < &coordinate),
                    "entry-order-unique",
                )?;
                previous = Some(coordinate);
            }
        }
        "restored" => {
            link(&b["cid"], 0x55)?;
            link(&b["candidate"], 0x55)?;
            uint(&b["length"], true, 4 * 1024 * 1024)?;
            require(b["cid"] == b["candidate"], "candidate-cid")?;
        }
        "publication-intent" => {
            blob(&b["attempt"], 16)?;
            blob(&b["restorations"], 32)?;
            blob(&b["output"], 32)?;
        }
        "publication-observed" => {
            blob(&b["attempt"], 16)?;
            link(&b["intent"], 0x71)?;
            blob(&b["output"], 32)?;
        }
        "publication-failed" => {
            blob(&b["attempt"], 16)?;
            link(&b["intent"], 0x71)?;
            require(
                matches!(&b["reason"],Ipld::String(s) if matches!(s.as_str(),"source-changed"|"invalid-candidate"|"destination-conflict"|"budget"|"io"|"verification")),
                "failure-reason",
            )?;
        }
        _ => unreachable!(),
    }
    Ok(())
}

/// Authenticate one observation from genesis or an authenticated predecessor.
/// No claim about the member, loss vector, candidates or publication is accepted
/// merely because its observer signed it. Full state replay remains mandatory.
pub fn authenticate(
    bytes: &[u8],
    context: &Context,
    previous: Option<&Authenticated>,
) -> Result<Authenticated> {
    context.validate()?;
    require(bytes.len() <= MAX_ENVELOPE, "envelope-bound")?;
    let env = evidence::canonical_value(bytes, MAX_ENVELOPE)
        .map_err(|_| invalid("envelope-canonical"))?;
    let env = closed(&env, &["statement", "signature"], "envelope-fields")?;
    let Ipld::Bytes(statement) = &env["statement"] else {
        return Err(invalid("statement-bytes"));
    };
    let value = evidence::canonical_value(statement, MAX_ENVELOPE)
        .map_err(|_| invalid("statement-canonical"))?;
    let st = closed(
        &value,
        &[
            "version",
            "domain",
            "bundle",
            "profile",
            "archive",
            "scope",
            "issuer",
            "observer",
            "sequence",
            "previous",
            "sampledAt",
            "event",
            "body",
        ],
        "statement-fields",
    )?;
    require(
        st["version"] == Ipld::Integer(1) && st["domain"] == Ipld::String(DOMAIN.into()),
        "protocol",
    )?;
    for name in ["bundle", "archive", "scope"] {
        blob(&st[name], 32)?;
    }
    for name in ["issuer", "observer"] {
        let s = evidence::string(&st[name], 80).map_err(|_| invalid("did-key"))?;
        did(s)?;
    }
    require(matches!(st["profile"], Ipld::Integer(2 | 3)), "profile")?;
    require(
        st["bundle"] == Ipld::Bytes(context.bundle.to_vec())
            && st["archive"] == Ipld::Bytes(context.archive.to_vec())
            && st["scope"] == Ipld::Bytes(context.scope.to_vec())
            && st["profile"] == Ipld::Integer(context.profile.into())
            && st["issuer"] == Ipld::String(context.issuer.clone())
            && st["observer"] == Ipld::String(context.observer.clone()),
        "context-binding",
    )?;
    let sequence = uint(&st["sequence"], true, evidence::MAX_SAFE_INTEGER as u64)?;
    uint(&st["sampledAt"], false, evidence::MAX_SAFE_INTEGER as u64)?;
    if let Some(previous) = previous {
        require(&previous.context == context, "previous-context")?;
        require(sequence == previous.sequence + 1, "sequence")?;
        require(link(&st["previous"], 0x71)? == &previous.cid, "predecessor")?;
    } else {
        require(sequence == 1 && st["previous"] == Ipld::Null, "genesis")?;
    }
    let event = evidence::string(&st["event"], 32).map_err(|_| invalid("event"))?;
    // Validate the closed variant before its positional rule for useful errors.
    body(event, &st["body"])?;
    require((event == "created") == (sequence == 1), "created-position")?;
    let cid = crate::cid::content_cid(&value).map_err(|_| invalid("statement-cid"))?;
    let signature = blob(&env["signature"], 64)?;
    const ORDER: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc,
        0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
    ];
    const HALF: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0x80, 0, 0, 0, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92,
        0xa8,
    ];
    if signature[..32].iter().all(|b| *b == 0)
        || signature[..32] >= ORDER[..]
        || signature[32..].iter().all(|b| *b == 0)
        || signature[32..] > HALF[..]
    {
        return Err(invalid("signature-range"));
    }
    require(
        crate::sign::verify(&context.observer, &preimage(&cid)?, signature),
        "signature-invalid",
    )?;
    Ok(Authenticated {
        context: context.clone(),
        bytes: bytes.to_vec(),
        statement: statement.clone(),
        value,
        cid,
        sequence,
    })
}

/// Pure signing for an already validated recovery operation. Callers must first
/// establish the semantic truth and allowed transition; this is not a writer API.
/// Encoded input is bounded and canonical before any signature is produced.
pub fn sign_claim(
    statement: &[u8],
    identity: &Identity,
    context: &Context,
    previous: Option<&Authenticated>,
) -> Result<Authenticated> {
    require(identity.did() == context.observer, "signer-context")?;
    let value = evidence::canonical_value(statement, MAX_ENVELOPE)
        .map_err(|_| invalid("statement-canonical"))?;
    let cid = crate::cid::content_cid(&value).map_err(|_| invalid("statement-cid"))?;
    let signature = identity
        .sign(&preimage(&cid)?)
        .map_err(|_| invalid("signing-failed"))?;
    let bytes = encode(&map([
        ("statement", Ipld::Bytes(statement.to_vec())),
        ("signature", Ipld::Bytes(signature)),
    ]))?;
    authenticate(&bytes, context, previous)
}

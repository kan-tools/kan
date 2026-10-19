//! RFC 4 service metadata attestations. A verified proof authenticates an issuer's
//! statement, not retained payload availability, writer signatures, or durability.
use std::collections::BTreeMap;

use crate::{
    evidence::{self, Error, Record},
    evidence_service,
    sign::Identity,
};
use atproto_dasl::{Cid, Ipld};

pub const MAX_ENVELOPE_BYTES: usize = 16 * 1024;
const DOMAIN: &str = "tools.kan.service.attestation.v1";
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
fn encode(value: &Ipld) -> Result<Vec<u8>> {
    atproto_dasl::to_vec(value).map_err(|e| invalid(&e.to_string()))
}
fn cid(value: &Ipld) -> Result<Cid> {
    crate::cid::content_cid(value).map_err(|e| invalid(&e.to_string()))
}
fn optional_link(value: &Option<Cid>) -> Ipld {
    value
        .as_ref()
        .map(|c| Ipld::Link(c.clone()))
        .unwrap_or(Ipld::Null)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Admitted,
    RetainedVerified,
}
impl Purpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::RetainedVerified => "retained-verified",
        }
    }
}
/// Expected predecessor. A caller must obtain non-genesis values from a verified
/// chain or authenticated snapshot; untrusted coordinates confer no authority.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Frontier {
    pub through: u64,
    pub manifest: Option<Cid>,
    pub attestation: Option<Cid>,
    pub archive: Option<[u8; 32]>,
    pub scope: Option<[u8; 32]>,
    pub issuer: Option<String>,
}
impl Frontier {
    fn validate(&self) -> Result<()> {
        if i128::from(self.through) > evidence::MAX_SAFE_INTEGER
            || (self.through == 0) != self.manifest.is_none()
            || (self.through == 0) != self.attestation.is_none()
            || (self.through == 0) != self.archive.is_none()
            || (self.through == 0) != self.scope.is_none()
            || (self.through == 0) != self.issuer.is_none()
        {
            return Err(invalid("inconsistent predecessor"));
        }
        for link in [&self.manifest, &self.attestation].into_iter().flatten() {
            evidence::link(&Ipld::Link(link.clone()), 0x71)?;
        }
        Ok(())
    }
}
/// An issuer-pinned signature over exact records and relative chain coordinates.
/// Chain membership depends on the caller supplying a trusted predecessor or pin;
/// this value alone is not evidence of a complete chain or durable admission.
#[derive(Debug, Clone)]
pub struct Verified {
    bytes: Vec<u8>,
    statement: Vec<u8>,
    frontier: Frontier,
    previous: Frontier,
    purpose: Purpose,
    issued_at: u64,
}
impl Verified {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn statement_bytes(&self) -> &[u8] {
        &self.statement
    }
    pub fn frontier(&self) -> &Frontier {
        &self.frontier
    }
    pub fn previous(&self) -> &Frontier {
        &self.previous
    }
    pub fn purpose(&self) -> Purpose {
        self.purpose
    }
    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }
    pub fn signing_preimage(&self) -> Vec<u8> {
        preimage(
            self.frontier
                .attestation
                .as_ref()
                .expect("verified statement CID"),
        )
    }
}
fn preimage(statement: &Cid) -> Vec<u8> {
    encode(&map([
        ("domain", Ipld::String(DOMAIN.into())),
        ("statement", Ipld::Link(statement.clone())),
    ]))
    .expect("bounded signature preimage")
}
/// Trust configuration supplied by the owner, never selected by the envelope.
pub struct Context<'a> {
    pub issuer: &'a str,
    pub archive: [u8; 32],
    pub scope: [u8; 32],
}
fn author(value: &Ipld) -> Result<&str> {
    let fields = evidence::closed(
        value,
        &["principal", "verificationMethod", "identityVersion"],
    )
    .map_err(|_| invalid("issuer-fields"))?;
    let did = evidence::string(&fields["principal"], 80).map_err(|_| invalid("issuer-encoding"))?;
    // Also bound before the dependency's two-byte multikey prefix indexing.
    if !(56..=80).contains(&did.len()) || !did.starts_with("did:key:z") || !did.is_ascii() {
        return Err(invalid("issuer-encoding"));
    }
    let (algorithm, key) =
        atrium_crypto::did::parse_did_key(did).map_err(|_| invalid("issuer-algorithm"))?;
    if algorithm != atrium_crypto::Algorithm::P256 {
        return Err(invalid("issuer-algorithm"));
    }
    if atrium_crypto::did::format_did_key(algorithm, &key).map_err(|_| invalid("issuer-point"))?
        != did
    {
        return Err(invalid("issuer-encoding"));
    }
    if fields["verificationMethod"] != Ipld::String(format!("{did}#{}", &did[8..])) {
        return Err(invalid("issuer-method"));
    }
    if fields["identityVersion"]
        != map([
            ("kind", Ipld::String("static".into())),
            ("value", Ipld::Null),
        ])
    {
        return Err(invalid("issuer-version"));
    }
    Ok(did)
}
fn record_link(value: &Ipld) -> Result<&Cid> {
    evidence::link(value, 0x71).map_err(|_| invalid("record-cid"))
}
fn uint(value: &Ipld) -> Result<u64> {
    evidence::uint(value)
        .map(|v| v as u64)
        .map_err(|_| invalid("safe-integer"))
}

/// Decode canonical metadata before proof verification; unknown record profiles
/// never fall back to a generic signed value.
pub fn verify_encoded(
    bytes: &[u8],
    context: &Context<'_>,
    manifest: &[u8],
    receipt: &[u8],
    previous: &Frontier,
) -> Result<Verified> {
    let decode =
        |bytes: &[u8], kind: evidence::Kind, canonical: &'static str, profile: &'static str| {
            match evidence::decode(bytes).map_err(|_| invalid(canonical))? {
                evidence::Decoded::Known(record) if record.kind() == kind => Ok(record),
                _ => Err(invalid(profile)),
            }
        };
    let manifest = decode(
        manifest,
        evidence::Kind::Manifest,
        "manifest-canonical",
        "manifest-profile",
    )?;
    let receipt = decode(
        receipt,
        evidence::Kind::Receipt,
        "receipt-canonical",
        "receipt-profile",
    )?;
    verify(bytes, context, &manifest, &receipt, previous)
}

/// Verify exact metadata, issuer, archive, scope and predecessor without payloads.
/// The predecessor must already be trusted by the caller; genesis starts a chain.
pub fn verify(
    bytes: &[u8],
    context: &Context<'_>,
    manifest: &Record,
    receipt: &Record,
    previous: &Frontier,
) -> Result<Verified> {
    previous.validate()?;
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(invalid("envelope-bound"));
    }
    let value = evidence::canonical_value(bytes, MAX_ENVELOPE_BYTES)
        .map_err(|_| invalid("envelope-canonical"))?;
    let envelope = evidence::closed(&value, &["statement", "signature"])
        .map_err(|_| invalid("envelope-fields"))?;
    let Ipld::Bytes(statement) = &envelope["statement"] else {
        return Err(invalid("statement-bytes"));
    };
    let value = evidence::canonical_value(statement, MAX_ENVELOPE_BYTES)
        .map_err(|_| invalid("statement-canonical"))?;
    let outer = evidence::closed(&value, &["v", "kind", "body"])
        .map_err(|_| invalid("statement-fields"))?;
    if outer["v"] != Ipld::Integer(1) || outer["kind"] != Ipld::String("service-attestation".into())
    {
        return Err(invalid("profile"));
    }
    let body = evidence::closed(
        &outer["body"],
        &[
            "issuer",
            "archiveId",
            "scopeToken",
            "sequence",
            "manifest",
            "receipt",
            "previousSequence",
            "previousManifest",
            "previousAttestation",
            "purpose",
            "issuedAt",
        ],
    )
    .map_err(|_| invalid("body-fields"))?;
    let issuer = author(&body["issuer"])?;
    if issuer != context.issuer {
        return Err(invalid("pinned-issuer"));
    }
    let archive = evidence::bytes(&body["archiveId"], 32).map_err(|_| invalid("archive-length"))?;
    let scope = evidence::bytes(&body["scopeToken"], 32).map_err(|_| invalid("scope-length"))?;
    if archive != context.archive {
        return Err(invalid("configured-archive"));
    }
    if scope != context.scope {
        return Err(invalid("configured-scope"));
    }
    let sequence = uint(&body["sequence"])?;
    let previous_sequence = uint(&body["previousSequence"])?;
    let issued_at = uint(&body["issuedAt"])?;
    if sequence == 0 || previous_sequence != sequence - 1 {
        return Err(invalid("sequence"));
    }
    let manifest_cid = record_link(&body["manifest"])?;
    let receipt_cid = record_link(&body["receipt"])?;
    let purpose = match &body["purpose"] {
        Ipld::String(s) if s == "admitted" => Purpose::Admitted,
        Ipld::String(s) if s == "retained-verified" => Purpose::RetainedVerified,
        _ => return Err(invalid("purpose")),
    };
    if previous.through == 0 {
        if sequence != 1
            || body["previousManifest"] != Ipld::Null
            || body["previousAttestation"] != Ipld::Null
        {
            return Err(invalid("genesis"));
        }
    } else {
        record_link(&body["previousManifest"])?;
        record_link(&body["previousAttestation"])?;
        if previous_sequence != previous.through
            || previous.archive != Some(context.archive)
            || previous.scope != Some(context.scope)
            || previous.issuer.as_deref() != Some(context.issuer)
        {
            return Err(invalid("chain-position"));
        }
        if body["previousManifest"] != optional_link(&previous.manifest)
            || body["previousAttestation"] != optional_link(&previous.attestation)
        {
            return Err(invalid("chain-commitments"));
        }
    }
    if manifest_cid != manifest.cid() || receipt_cid != receipt.cid() {
        return Err(invalid("record-binding"));
    }
    if !evidence::binds(receipt, manifest)
        || manifest.body().get("scopeToken") != Some(&Ipld::Bytes(scope.to_vec()))
    {
        return Err(invalid("receipt-binding"));
    }
    if purpose == Purpose::Admitted && receipt.body().get("issuer") != Some(&body["issuer"]) {
        return Err(invalid("admitted-issuer"));
    }
    let statement_cid = cid(&value)?;
    let signature =
        evidence::bytes(&envelope["signature"], 64).map_err(|_| invalid("signature-encoding"))?;
    // Fixed-width scalar range/low-S checks are explicit to pin the wire error
    // class separately from cryptographic failure. The verifier checks them too.
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
    if !crate::sign::verify(issuer, &preimage(&statement_cid), signature) {
        return Err(invalid("signature-invalid"));
    }
    Ok(Verified {
        bytes: bytes.to_vec(),
        statement: statement.clone(),
        frontier: Frontier {
            through: sequence,
            manifest: Some(manifest.cid().clone()),
            attestation: Some(statement_cid),
            archive: Some(context.archive),
            scope: Some(context.scope),
            issuer: Some(context.issuer.into()),
        },
        previous: previous.clone(),
        purpose,
        issued_at,
    })
}

/// Verify one descending row against a trusted snapshot/current frontier.
/// Never call with a frontier taken directly from an unsigned browser cursor.
pub fn verify_at(
    bytes: &[u8],
    context: &Context<'_>,
    manifest: &Record,
    receipt: &Record,
    expected: &Frontier,
) -> Result<Verified> {
    expected.validate()?;
    if expected.through == 0 {
        return Err(invalid("row-after-genesis"));
    }
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(invalid("envelope-bound"));
    }
    let value = evidence::canonical_value(bytes, MAX_ENVELOPE_BYTES)
        .map_err(|_| invalid("envelope-canonical"))?;
    let envelope = evidence::closed(&value, &["statement", "signature"])
        .map_err(|_| invalid("envelope-fields"))?;
    let Ipld::Bytes(statement) = &envelope["statement"] else {
        return Err(invalid("statement-bytes"));
    };
    let value = evidence::canonical_value(statement, MAX_ENVELOPE_BYTES)
        .map_err(|_| invalid("statement-canonical"))?;
    let outer = evidence::closed(&value, &["v", "kind", "body"])
        .map_err(|_| invalid("statement-fields"))?;
    let Ipld::Map(body) = &outer["body"] else {
        return Err(invalid("body-fields"));
    };
    let get = |field| body.get(field).ok_or_else(|| invalid("body-fields"));
    let previous_sequence = uint(get("previousSequence")?)?;
    let previous = if previous_sequence == 0 {
        Frontier::default()
    } else {
        Frontier {
            through: previous_sequence,
            manifest: Some(record_link(get("previousManifest")?)?.clone()),
            attestation: Some(record_link(get("previousAttestation")?)?.clone()),
            archive: Some(context.archive),
            scope: Some(context.scope),
            issuer: Some(context.issuer.into()),
        }
    };
    let verified = verify(bytes, context, manifest, receipt, &previous)?;
    if verified.frontier() != expected {
        return Err(invalid("pinned-frontier"));
    }
    Ok(verified)
}

/// Pure signer, not an admission API. The authenticated service must verify the
/// original request and atomically persist proof and metadata before acknowledging.
pub fn issue(
    identity: &Identity,
    context: &Context<'_>,
    manifest: &Record,
    receipt: &Record,
    previous: &Frontier,
    purpose: Purpose,
    issued_at: u64,
) -> Result<Verified> {
    previous.validate()?;
    let issuer = identity.did().to_string();
    let body = map([
        (
            "issuer",
            evidence_service::author(&issuer).map_err(|_| invalid("issuer-fields"))?,
        ),
        ("archiveId", Ipld::Bytes(context.archive.to_vec())),
        ("scopeToken", Ipld::Bytes(context.scope.to_vec())),
        ("sequence", Ipld::Integer(i128::from(previous.through) + 1)),
        ("manifest", Ipld::Link(manifest.cid().clone())),
        ("receipt", Ipld::Link(receipt.cid().clone())),
        (
            "previousSequence",
            Ipld::Integer(i128::from(previous.through)),
        ),
        ("previousManifest", optional_link(&previous.manifest)),
        ("previousAttestation", optional_link(&previous.attestation)),
        ("purpose", Ipld::String(purpose.as_str().into())),
        ("issuedAt", Ipld::Integer(i128::from(issued_at))),
    ]);
    let statement = map([
        ("v", Ipld::Integer(1)),
        ("kind", Ipld::String("service-attestation".into())),
        ("body", body),
    ]);
    let signature = identity
        .sign(&preimage(&cid(&statement)?))
        .map_err(|_| invalid("signing-failed"))?;
    let bytes = encode(&map([
        ("statement", Ipld::Bytes(encode(&statement)?)),
        ("signature", Ipld::Bytes(signature)),
    ]))?;
    verify(&bytes, context, manifest, receipt, previous)
}

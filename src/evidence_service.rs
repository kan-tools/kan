//! Experimental authenticated opaque partition. No payload decryption or key storage.
use std::collections::BTreeMap;

use atproto_dasl::{Cid, Ipld};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    evidence::{self, Decoded, Record},
    evidence_store::{self, Committed, Ledger, Snapshot},
    sign::{self, Identity},
};

pub const MAX_PAYLOAD: usize = 1024 * 1024;
pub const MAX_REQUEST: usize = 2 * MAX_PAYLOAD + 4096;
const REQUEST_DOMAIN: &[u8] = b"tools.kan.service.request.v1\0";
const REPLY_DOMAIN: &[u8] = b"tools.kan.service.reply.v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Failure {
    Invalid,
    AccessLimited,
    Conflict,
    Missing,
    Corrupt,
    Unavailable,
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Failure {}
impl From<evidence_store::Error> for Failure {
    fn from(value: evidence_store::Error) -> Self {
        match value {
            evidence_store::Error::Invalid(_) | evidence_store::Error::Record(_) => Self::Invalid,
            evidence_store::Error::Conflict(_) => Self::Conflict,
            evidence_store::Error::Erased(_) => Self::AccessLimited,
            evidence_store::Error::Missing(_) | evidence_store::Error::MissingCommit(_) => {
                Self::Missing
            }
            evidence_store::Error::Corrupt(_) => Self::Corrupt,
            _ => Self::Unavailable,
        }
    }
}
type Result<T> = std::result::Result<T, Failure>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u8,
    pub scope: String,
    pub audience: String,
    pub principal: String,
    pub expires: Option<u64>,
    pub command: Command,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Command {
    Append {
        id: String,
        position: u64,
        previous: Option<String>,
        ciphertext: String,
    },
    Snapshot,
    Page {
        through: u64,
        tip: Option<String>,
        after: u64,
        limit: usize,
    },
    Read {
        sequence: u64,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRequest {
    pub request: Request,
    pub signature: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecordView {
    pub sequence: u64,
    pub manifest: String,
    pub receipt: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Output {
    /// Owner-side post-commit completion of one exact initial erasure, including
    /// its archive binding. Ordinary RPC admission cannot produce this variant.
    ErasedCommitted {
        record: RecordView,
        duplicate: bool,
        archive: String,
        erasure: String,
    },
    Committed {
        record: RecordView,
        duplicate: bool,
    },
    Snapshot {
        through: u64,
        tip: Option<String>,
    },
    Page {
        records: Vec<RecordView>,
        complete: bool,
    },
    Evidence {
        record: RecordView,
        signed_request: String,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub version: u8,
    pub request: String,
    pub issuer: String,
    pub result: std::result::Result<Output, Failure>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReply {
    pub reply: Reply,
    pub signature: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub principal: String,
    pub append: bool,
    pub inventory: bool,
}

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(DIGITS[(byte >> 4) as usize] as char);
        text.push(DIGITS[(byte & 15) as usize] as char);
    }
    text
}
pub fn unhex(value: &str, maximum: usize) -> Result<Vec<u8>> {
    if value.len() > maximum.saturating_mul(2) || !value.len().is_multiple_of(2) {
        return Err(Failure::Invalid);
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| {
            let digit = |v| match v {
                b'0'..=b'9' => Ok(v - b'0'),
                b'a'..=b'f' => Ok(v - b'a' + 10),
                _ => Err(Failure::Invalid),
            };
            Ok(digit(c[0])? * 16 + digit(c[1])?)
        })
        .collect()
}
fn exact(value: &str, size: usize) -> Result<Vec<u8>> {
    let bytes = unhex(value, size)?;
    if bytes.len() != size {
        return Err(Failure::Invalid);
    }
    Ok(bytes)
}
fn json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| Failure::Invalid)
}
fn preimage<T: Serialize>(domain: &[u8], value: &T) -> Result<Vec<u8>> {
    let mut bytes = domain.to_vec();
    bytes.extend_from_slice(&Sha256::digest(json(value)?));
    Ok(bytes)
}
pub(crate) fn author(did: &str) -> Result<Ipld> {
    let fingerprint = did.strip_prefix("did:key:").ok_or(Failure::Invalid)?;
    if did.len() > 256 || !did.is_ascii() {
        return Err(Failure::Invalid);
    }
    let method = format!("{did}#{fingerprint}");
    crate::identity::authorship::Author::new(
        did.into(),
        method.clone(),
        crate::identity::control::IdentityVersion::Static,
    )
    .map_err(|_| Failure::Invalid)?;
    Ok(map([
        ("principal", Ipld::String(did.into())),
        ("verificationMethod", Ipld::String(method)),
        (
            "identityVersion",
            map([
                ("kind", Ipld::String("static".into())),
                ("value", Ipld::Null),
            ]),
        ),
    ]))
}
fn map<const N: usize>(values: [(&str, Ipld); N]) -> Ipld {
    Ipld::Map(values.into_iter().map(|(k, v)| (k.into(), v)).collect())
}
fn known(kind: &str, body: Ipld) -> Result<Record> {
    match evidence::encode(&map([
        ("v", Ipld::Integer(1)),
        ("kind", Ipld::String(kind.into())),
        ("body", body),
    ])) {
        Ok(Decoded::Known(record)) => Ok(record),
        _ => Err(Failure::Invalid),
    }
}
fn link(value: &str) -> Result<Cid> {
    let id: Cid = value.parse().map_err(|_| Failure::Invalid)?;
    if id.to_string() != value || value.len() > 128 {
        return Err(Failure::Invalid);
    }
    Ok(id)
}
impl SignedRequest {
    pub fn sign(request: Request, identity: &Identity) -> Result<Self> {
        if identity.did().as_str() != request.principal {
            return Err(Failure::Invalid);
        }
        validate_shape(&request)?;
        let signature = identity
            .sign(&preimage(REQUEST_DOMAIN, &request)?)
            .map_err(|_| Failure::Invalid)?;
        Ok(Self {
            request,
            signature: hex(&signature),
        })
    }
    pub fn bytes(&self) -> Result<Vec<u8>> {
        json(self)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_REQUEST {
            return Err(Failure::Invalid);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| Failure::Invalid)?;
        if value.bytes()? != bytes {
            return Err(Failure::Invalid);
        }
        validate_shape(&value.request)?;
        let signature = exact(&value.signature, 64)?;
        if !sign::verify(
            &value.request.principal,
            &preimage(REQUEST_DOMAIN, &value.request)?,
            &signature,
        ) {
            return Err(Failure::AccessLimited);
        }
        Ok(value)
    }
}
pub(crate) fn validate_shape(request: &Request) -> Result<()> {
    if request.version != 1 {
        return Err(Failure::Invalid);
    }
    exact(&request.scope, 32)?;
    author(&request.principal)?;
    author(&request.audience)?;
    match &request.command {
        Command::Append {
            id,
            position,
            previous,
            ciphertext,
        } => {
            if request.expires.is_some() || *position > evidence::MAX_SAFE_INTEGER as u64 {
                return Err(Failure::Invalid);
            }
            exact(id, 16)?;
            if (*position == 0) != previous.is_none() {
                return Err(Failure::Invalid);
            }
            if let Some(id) = previous {
                link(id)?;
            }
            if unhex(ciphertext, MAX_PAYLOAD)?.is_empty() {
                return Err(Failure::Invalid);
            }
        }
        Command::Page {
            through,
            tip,
            after,
            limit,
        } => {
            if *limit == 0 || *limit > 128 || after > through || (*through == 0) != tip.is_none() {
                return Err(Failure::Invalid);
            }
            if let Some(tip) = tip {
                link(tip)?;
            }
            if request.expires.is_none() {
                return Err(Failure::Invalid);
            }
        }
        _ if request.expires.is_none() => return Err(Failure::Invalid),
        _ => {}
    }
    Ok(())
}
impl SignedReply {
    pub fn bytes(&self) -> Result<Vec<u8>> {
        json(self)
    }
    pub fn verify(&self, request: &[u8], issuer: &str) -> Result<&Reply> {
        self.verify_digest(&hex(&Sha256::digest(request)), issuer)
    }
    fn verify_digest(&self, digest: &str, issuer: &str) -> Result<&Reply> {
        if self.reply.version != 1 || self.reply.issuer != issuer || self.reply.request != digest {
            return Err(Failure::Invalid);
        }
        if !sign::verify(
            issuer,
            &preimage(REPLY_DOMAIN, &self.reply)?,
            &exact(&self.signature, 64)?,
        ) {
            return Err(Failure::AccessLimited);
        }
        Ok(&self.reply)
    }
}
/// Canonical append commitment for exact signed bytes; useful to durable senders.
pub fn append_manifest(bytes: &[u8]) -> Result<Record> {
    manifest(&SignedRequest::decode(bytes)?, bytes)
}

/// Authenticate exact retained request/manifest and structural unsigned receipt binding.
/// This does not authenticate service admission, archive completeness or sequence placement.
pub fn verify_retained_request(record: &Committed, bytes: &[u8]) -> Result<SignedRequest> {
    let request = SignedRequest::decode(bytes).map_err(|_| Failure::Corrupt)?;
    if !evidence::binds(&record.receipt, &record.manifest)
        || record.receipt.body()["issuer"]
            != author(&request.request.audience).map_err(|_| Failure::Corrupt)?
        || manifest(&request, bytes)
            .map_err(|_| Failure::Corrupt)?
            .bytes()
            != record.manifest.bytes()
    {
        return Err(Failure::Corrupt);
    }
    Ok(request)
}

/// Validate destination admission evidence before a sender releases its spool bytes.
pub fn admitted_manifest(request: &[u8], reply: &SignedReply, issuer: &str) -> Result<Record> {
    if SignedRequest::decode(request)?.request.audience != issuer {
        return Err(Failure::AccessLimited);
    }
    let verified = reply.verify(request, issuer)?;
    let Output::Committed { record, .. } = verified.result.as_ref().map_err(Clone::clone)? else {
        return Err(Failure::Invalid);
    };
    if record.sequence == 0 || record.sequence > evidence::MAX_SAFE_INTEGER as u64 {
        return Err(Failure::Corrupt);
    }
    let expected = append_manifest(request)?;
    if unhex(&record.manifest, evidence::MAX_RECORD_BYTES)? != expected.bytes() {
        return Err(Failure::Corrupt);
    }
    let Decoded::Known(receipt) =
        evidence::decode(&unhex(&record.receipt, evidence::MAX_RECORD_BYTES)?)
            .map_err(|_| Failure::Corrupt)?
    else {
        return Err(Failure::Corrupt);
    };
    if !evidence::binds(&receipt, &expected) || receipt.body()["issuer"] != author(issuer)? {
        return Err(Failure::Corrupt);
    }
    Ok(expected)
}

/// Verify a post-commit acknowledgment without retaining its erased request.
/// The independent erasure target binds the same raw SHA256 object commitment.
pub(crate) fn admitted_erased_manifest(
    reply: &SignedReply,
    erasure: &evidence_store::erasure::Record,
    issuer: &str,
) -> Result<Record> {
    let target = erasure.plan.targets.first().ok_or(Failure::Invalid)?;
    if erasure.plan.initial_erasure.is_none() || erasure.plan.targets.len() != 1 {
        return Err(Failure::Invalid);
    }
    let digest = exact(&reply.reply.request, 32)?;
    let mut object = vec![1, 0x55, 0x12, 0x20];
    object.extend(digest);
    if Cid::from_bytes(&object)
        .map_err(|_| Failure::Invalid)?
        .to_string()
        != target.object
    {
        return Err(Failure::Invalid);
    }
    let verified = reply.verify_digest(&reply.reply.request, issuer)?;
    let Output::ErasedCommitted {
        record,
        archive,
        erasure: authorization,
        ..
    } = verified.result.as_ref().map_err(Clone::clone)?
    else {
        return Err(Failure::Invalid);
    };
    if *archive != erasure.plan.archive || *authorization != erasure.id()? {
        return Err(Failure::Invalid);
    }
    if record.sequence != target.sequence {
        return Err(Failure::Invalid);
    }
    let Decoded::Known(manifest) =
        evidence::decode(&unhex(&record.manifest, evidence::MAX_RECORD_BYTES)?)
            .map_err(|_| Failure::Invalid)?
    else {
        return Err(Failure::Invalid);
    };
    let Decoded::Known(receipt) =
        evidence::decode(&unhex(&record.receipt, evidence::MAX_RECORD_BYTES)?)
            .map_err(|_| Failure::Invalid)?
    else {
        return Err(Failure::Invalid);
    };
    if manifest.kind() != evidence::Kind::Manifest
        || manifest.cid().to_string() != target.manifest
        || !evidence::binds(&receipt, &manifest)
        || receipt.body()["issuer"] != author(issuer)?
    {
        return Err(Failure::Invalid);
    }
    Ok(manifest)
}

fn manifest(request: &SignedRequest, bytes: &[u8]) -> Result<Record> {
    let Command::Append {
        id,
        position,
        previous,
        ..
    } = &request.request.command
    else {
        return Err(Failure::Invalid);
    };
    known(
        "manifest",
        map([
            ("writer", author(&request.request.principal)?),
            (
                "scopeToken",
                Ipld::Bytes(exact(&request.request.scope, 32)?),
            ),
            ("operation", Ipld::Bytes(exact(id, 16)?)),
            ("position", Ipld::Integer(i128::from(*position))),
            (
                "previous",
                previous
                    .as_ref()
                    .map(|s| link(s).map(Ipld::Link))
                    .transpose()?
                    .unwrap_or(Ipld::Null),
            ),
            (
                "entries",
                Ipld::List(vec![map([
                    ("slot", Ipld::Bytes(Sha256::digest(exact(id, 16)?).to_vec())),
                    (
                        "ciphertext",
                        Ipld::Link(evidence_store::ciphertext_cid(bytes)),
                    ),
                    ("length", Ipld::Integer(bytes.len() as i128)),
                ])]),
            ),
        ]),
    )
}
pub(crate) fn receipt(manifest: &Record, issuer: &str, now: u64) -> Result<Record> {
    // dispatch accepts Unix seconds for request expiry; RFC 4 stores milliseconds.
    let now = now.checked_mul(1000).ok_or(Failure::Invalid)?;
    if now > evidence::MAX_SAFE_INTEGER as u64 {
        return Err(Failure::Invalid);
    }
    known(
        "receipt",
        map([
            ("issuer", author(issuer)?),
            ("manifest", Ipld::Link(manifest.cid().clone())),
            ("scopeToken", manifest.body()["scopeToken"].clone()),
            ("operation", manifest.body()["operation"].clone()),
            ("position", manifest.body()["position"].clone()),
            ("durability", Ipld::String("remote-durable".into())),
            ("issuedAt", Ipld::Integer(i128::from(now))),
        ]),
    )
}
fn view(record: &Committed) -> RecordView {
    RecordView {
        sequence: record.sequence,
        manifest: hex(record.manifest.bytes()),
        receipt: hex(record.receipt.bytes()),
    }
}

/// Explicit profile-2 ingest. Read operations use the separate proof endpoint;
/// the durable delivery request/reply format remains compatible with the spool.
pub struct AdmittingService {
    indexed: bool,
    erasure_history: Option<crate::evidence_erasure_history::Access>,
    policy: Option<crate::evidence_policy::Access>,
    archive: crate::evidence_store::attested::Archive,
    signer: Identity,
    grants: BTreeMap<String, Grant>,
}
impl AdmittingService {
    pub fn new(
        archive: crate::evidence_store::attested::Archive,
        signer: Identity,
        grants: Vec<Grant>,
    ) -> Result<Self> {
        if archive.binding().issuer != signer.did().as_str() {
            return Err(Failure::AccessLimited);
        }
        archive.verify()?;
        Self::configured(archive, signer, grants, false)
    }
    /// Use an explicitly initialized index for archive metadata/append work.
    /// External policy/custody are still checked under their existing leases.
    pub fn new_indexed(
        archive: crate::evidence_store::attested::Archive,
        signer: Identity,
        grants: Vec<Grant>,
        current_erasure_tip: Option<&str>,
    ) -> Result<Self> {
        if archive.binding().issuer != signer.did().as_str() {
            return Err(Failure::AccessLimited);
        }
        archive.indexed_frontier(current_erasure_tip)?;
        Self::configured(archive, signer, grants, true)
    }
    fn configured(
        archive: crate::evidence_store::attested::Archive,
        signer: Identity,
        grants: Vec<Grant>,
        indexed: bool,
    ) -> Result<Self> {
        let mut service = Self {
            indexed,
            erasure_history: None,
            policy: None,
            archive,
            signer,
            grants: BTreeMap::new(),
        };
        service.replace_grants(grants)?;
        Ok(service)
    }
    pub fn with_erasure_history(
        mut self,
        history: crate::evidence_erasure_history::Access,
    ) -> Result<Self> {
        if history.binding.profile != crate::evidence_proof_service::Profile::Admitted
            || history.binding.owner_binding()? != *self.archive.binding()
        {
            return Err(Failure::Invalid);
        }
        let current = history.serving(self.indexed)?;
        if self.indexed {
            self.archive
                .indexed_frontier(current.storage_tip()?.as_deref())?;
        } else {
            current.check_package(&self.archive.erasure_history()?)?;
        }
        drop(current);
        self.erasure_history = Some(history);
        Ok(self)
    }
    pub fn with_policy(mut self, policy: crate::evidence_policy::Access) -> Result<Self> {
        let binding = self.archive.binding();
        if policy.binding.profile != crate::evidence_proof_service::Profile::Admitted
            || policy.binding.owner_binding()? != *binding
        {
            return Err(Failure::Invalid);
        }
        self.replace_grants(policy.current()?.grants()?)?;
        self.policy = Some(policy);
        Ok(self)
    }
    pub fn issuer(&self) -> String {
        self.signer.did().to_string()
    }
    pub fn replace_grants(&mut self, grants: Vec<Grant>) -> Result<()> {
        let mut selected = BTreeMap::new();
        for grant in grants {
            author(&grant.principal)?;
            if selected.insert(grant.principal.clone(), grant).is_some() {
                return Err(Failure::Invalid);
            }
        }
        self.grants = selected;
        Ok(())
    }
    pub fn dispatch(&mut self, bytes: &[u8], now: u64) -> Result<SignedReply> {
        if bytes.len() > MAX_REQUEST {
            return Err(Failure::Invalid);
        }
        let custody = self
            .erasure_history
            .as_ref()
            .map(|history| history.serving(self.indexed))
            .transpose()?;
        let storage_tip = custody
            .as_ref()
            .map(|current| current.storage_tip())
            .transpose()?
            .flatten();
        if let Some(current) = &custody {
            if self.indexed {
                self.archive.indexed_frontier(storage_tip.as_deref())?;
            } else {
                current.check_package(&self.archive.erasure_history()?)?;
            }
        }
        // Keep the shared policy lease through admission, so revocation commits
        // after earlier authorized work and before later work can authorize.
        let policy = self
            .policy
            .as_ref()
            .map(crate::evidence_policy::Access::current)
            .transpose()?;
        if let Some(snapshot) = &policy {
            self.replace_grants(snapshot.grants()?)?;
        }
        let result = self.append(bytes, now, storage_tip.as_deref());
        let reply = Reply {
            version: 1,
            request: hex(&Sha256::digest(bytes)),
            issuer: self.issuer(),
            result,
        };
        let signature = hex(&self
            .signer
            .sign(&preimage(REPLY_DOMAIN, &reply)?)
            .map_err(|_| Failure::Unavailable)?);
        Ok(SignedReply { reply, signature })
    }
    /// Owner-side cancellation completion, never exposed as an ordinary RPC.
    /// Independent custody must already contain this exact initial erasure.
    /// The signed acknowledgment is created only after the atomic archive commit.
    pub fn admit_erased(
        &mut self,
        bytes: &[u8],
        erasure: &evidence_store::erasure::Record,
        history: &crate::evidence_erasure_history::Access,
    ) -> Result<SignedReply> {
        if history.binding.profile != crate::evidence_proof_service::Profile::Admitted
            || history.binding.owner_binding()? != *self.archive.binding()
            || erasure.plan.initial_erasure.is_none()
        {
            return Err(Failure::Invalid);
        }
        let current = history.current()?;
        let id = erasure.id()?;
        if !current
            .history
            .iter()
            .filter_map(|r| r.change.erasure.as_ref())
            .any(|r| r.id().ok().as_ref() == Some(&id))
        {
            return Err(Failure::AccessLimited);
        }
        let policy = self
            .policy
            .as_ref()
            .map(crate::evidence_policy::Access::current)
            .transpose()?;
        if let Some(snapshot) = &policy {
            self.replace_grants(snapshot.grants()?)?;
        }
        let request = SignedRequest::decode(bytes)?;
        let grant = self
            .grants
            .get(&request.request.principal)
            .ok_or(Failure::AccessLimited)?;
        let admitted = self
            .archive
            .admit_erased(bytes, &self.signer, grant, erasure)?;
        let reply = Reply {
            version: 1,
            request: hex(&Sha256::digest(bytes)),
            issuer: self.issuer(),
            result: Ok(Output::ErasedCommitted {
                archive: erasure.plan.archive.clone(),
                erasure: erasure.id()?,
                record: view(&admitted.record),
                duplicate: admitted.record.duplicate,
            }),
        };
        let signature = hex(&self
            .signer
            .sign(&preimage(REPLY_DOMAIN, &reply)?)
            .map_err(|_| Failure::Unavailable)?);
        Ok(SignedReply { reply, signature })
    }
    fn append(
        &mut self,
        bytes: &[u8],
        now: u64,
        current_erasure_tip: Option<&str>,
    ) -> Result<Output> {
        let signed = SignedRequest::decode(bytes)?;
        let request = &signed.request;
        let grant = self
            .grants
            .get(&request.principal)
            .ok_or(Failure::AccessLimited)?;
        if !grant.append
            || !matches!(request.command, Command::Append { .. })
            || request.scope != hex(&self.archive.binding().scope)
            || request.audience != self.issuer()
        {
            return Err(Failure::AccessLimited);
        }
        let admitted = if self.indexed {
            self.archive
                .admit_indexed(bytes, &self.signer, grant, now, current_erasure_tip)?
        } else {
            self.archive.admit(bytes, &self.signer, grant, now)?
        };
        Ok(Output::Committed {
            record: view(&admitted.record),
            duplicate: admitted.record.duplicate,
        })
    }
}

pub struct Service {
    ledger: Ledger,
    scope: String,
    signer: Identity,
    grants: BTreeMap<String, Grant>,
    // Disposable process-local evidence of an audited append-only prefix.
    audited: Snapshot,
}
impl Service {
    /// Audits only the declared service profile; never auto-converts a raw ledger.
    pub fn new(
        ledger: Ledger,
        scope: [u8; 32],
        signer: Identity,
        grants: Vec<Grant>,
    ) -> Result<Self> {
        let mut permissions = BTreeMap::new();
        for grant in grants {
            author(&grant.principal)?;
            if permissions.insert(grant.principal.clone(), grant).is_some() {
                return Err(Failure::Invalid);
            }
        }
        let mut service = Self {
            ledger,
            scope: hex(&scope),
            signer,
            grants: permissions,
            audited: Snapshot {
                through: 0,
                tip: None,
            },
        };
        service.audit_suffix()?;
        Ok(service)
    }
    fn audit_suffix(&mut self) -> Result<()> {
        let snapshot = self.ledger.snapshot()?;
        if snapshot.through < self.audited.through
            || (snapshot.through == self.audited.through && snapshot.tip != self.audited.tip)
        {
            return Err(Failure::Corrupt);
        }
        // Check the prior pin even if another writer has appended since then.
        self.ledger
            .page(&self.audited, self.audited.through, 1)
            .map_err(|error| match error {
                evidence_store::Error::Invalid(_) => Failure::Corrupt,
                other => other.into(),
            })?;
        let mut after = self.audited.through;
        while after < snapshot.through {
            let page = self.ledger.page(&snapshot, after, 128)?;
            if page.is_empty() {
                return Err(Failure::Corrupt);
            }
            for record in page {
                if record.sequence != after + 1 {
                    return Err(Failure::Corrupt);
                }
                self.read_signed(&record)?;
                after = record.sequence;
                // This entire contiguous prefix is verified even if a later
                // record fails. Never advance across the failing record.
                self.audited = Snapshot {
                    through: after,
                    tip: Some(record.manifest.cid().clone()),
                };
            }
        }
        Ok(())
    }
    pub fn issuer(&self) -> String {
        self.signer.did().to_string()
    }
    /// `now` is Unix seconds; stored receipt timestamps use Unix milliseconds.
    pub fn dispatch(&mut self, bytes: &[u8], now: u64) -> Result<SignedReply> {
        // Transport adapters must enforce this before buffering; the library also
        // refuses oversized input before hashing it or parsing JSON.
        if bytes.len() > MAX_REQUEST {
            return Err(Failure::Invalid);
        }
        let result = self.execute(bytes, now);
        let reply = Reply {
            version: 1,
            request: hex(&Sha256::digest(bytes)),
            issuer: self.issuer(),
            result,
        };
        let signature = self
            .signer
            .sign(&preimage(REPLY_DOMAIN, &reply)?)
            .map_err(|_| Failure::Unavailable)?;
        Ok(SignedReply {
            reply,
            signature: hex(&signature),
        })
    }
    fn execute(&mut self, bytes: &[u8], now: u64) -> Result<Output> {
        let signed = SignedRequest::decode(bytes)?;
        let request = &signed.request;
        if request.scope != self.scope || request.audience != self.issuer() {
            return Err(Failure::AccessLimited);
        }
        let grant = self
            .grants
            .get(&request.principal)
            .ok_or(Failure::AccessLimited)?;
        let append = matches!(request.command, Command::Append { .. });
        if (append && !grant.append) || (!append && !grant.inventory) {
            return Err(Failure::AccessLimited);
        }
        if !append
            && !request
                .expires
                .is_some_and(|e| e >= now && e.saturating_sub(now) <= 300)
        {
            return Err(Failure::AccessLimited);
        }
        self.audit_suffix()?;
        self.execute_audited(&signed, bytes, now)
    }
    // Private post-authorization/audit phase. Separating this permits tests to
    // schedule a concurrent raw append precisely between audit and execution.
    fn execute_audited(
        &mut self,
        signed: &SignedRequest,
        bytes: &[u8],
        now: u64,
    ) -> Result<Output> {
        match &signed.request.command {
            Command::Append { .. } => {
                let manifest = manifest(signed, bytes)?;
                let receipt = receipt(&manifest, self.issuer().as_str(), now)?;
                self.ledger.stage(bytes)?;
                let record = self.ledger.commit_partition_at(
                    manifest.bytes(),
                    receipt.bytes(),
                    &self.audited,
                )?;
                if !record.duplicate {
                    self.audited = Snapshot {
                        through: record.sequence,
                        tip: Some(record.manifest.cid().clone()),
                    };
                }
                Ok(Output::Committed {
                    record: view(&record),
                    duplicate: record.duplicate,
                })
            }
            Command::Snapshot => {
                if self.audited.through > 0 {
                    let tip = self
                        .ledger
                        .page(&self.audited, self.audited.through - 1, 1)?
                        .pop()
                        .ok_or(Failure::Corrupt)?;
                    self.read_signed(&tip)?;
                }
                Ok(Output::Snapshot {
                    through: self.audited.through,
                    tip: self.audited.tip.as_ref().map(ToString::to_string),
                })
            }
            Command::Page {
                through,
                tip,
                after,
                limit,
            } => {
                if *through > self.audited.through {
                    return Err(Failure::Invalid);
                }
                let snapshot = Snapshot {
                    through: *through,
                    tip: tip.as_ref().map(|c| link(c)).transpose()?,
                };
                let page = self.ledger.page(&snapshot, *after, *limit)?;
                // A privileged raw-ledger writer may have changed the partition
                // after startup. Never return foreign or unauthenticated records.
                for record in &page {
                    self.read_signed(record)?;
                }
                let last = page.last().map_or(*after, |r| r.sequence);
                if last < *through && page.is_empty() {
                    return Err(Failure::Corrupt);
                }
                Ok(Output::Page {
                    records: page.iter().map(view).collect(),
                    complete: last == *through,
                })
            }
            Command::Read { sequence } => {
                let snapshot = &self.audited;
                if *sequence == 0 || *sequence > snapshot.through {
                    return Err(Failure::Missing);
                }
                let mut page = self.ledger.page(snapshot, sequence - 1, 1)?;
                let record = page
                    .pop()
                    .filter(|r| r.sequence == *sequence)
                    .ok_or(Failure::Corrupt)?;
                let bytes = self.read_signed(&record)?;
                Ok(Output::Evidence {
                    record: view(&record),
                    signed_request: hex(&bytes),
                })
            }
        }
    }
    fn read_signed(&self, record: &Committed) -> Result<Vec<u8>> {
        let Ipld::List(entries) = &record.manifest.body()["entries"] else {
            return Err(Failure::Corrupt);
        };
        if entries.len() != 1 {
            return Err(Failure::Corrupt);
        }
        let Ipld::Map(entry) = &entries[0] else {
            return Err(Failure::Corrupt);
        };
        let Ipld::Link(id) = &entry["ciphertext"] else {
            return Err(Failure::Corrupt);
        };
        let bytes = self.ledger.read_object(id).map_err(|e| match e {
            evidence_store::Error::Missing(_) => Failure::Corrupt,
            other => other.into(),
        })?;
        let request = verify_retained_request(record, &bytes)?;
        if request.request.scope != self.scope {
            return Err(Failure::Corrupt);
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod audit_tests {
    use super::*;

    fn setup(root: &std::path::Path, writer: &Identity) -> Service {
        Service::new(
            Ledger::create(root).unwrap(),
            [1; 32],
            Identity::generate(),
            vec![Grant {
                principal: writer.did().to_string(),
                append: true,
                inventory: true,
            }],
        )
        .unwrap()
    }
    fn signed(service: &Service, writer: &Identity, command: Command) -> SignedRequest {
        let expires = if matches!(command, Command::Append { .. }) {
            None
        } else {
            Some(1100)
        };
        SignedRequest::sign(
            Request {
                version: 1,
                scope: service.scope.clone(),
                audience: service.issuer(),
                principal: writer.did().to_string(),
                expires,
                command,
            },
            writer,
        )
        .unwrap()
    }
    fn raw_append(
        service: &mut Service,
        writer: &Identity,
        position: u64,
        previous: Option<String>,
        valid: bool,
    ) -> (Vec<u8>, Committed) {
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&position.to_be_bytes());
        let mut request = signed(
            service,
            writer,
            Command::Append {
                id: hex(&id),
                position,
                previous,
                ciphertext: hex(b"opaque"),
            },
        );
        if !valid {
            request.signature = "00".repeat(64);
        }
        let bytes = request.bytes().unwrap();
        let m = manifest(&request, &bytes).unwrap();
        let r = receipt(&m, &service.issuer(), 1000).unwrap();
        service.ledger.stage(&bytes).unwrap();
        let committed = service.ledger.commit(m.bytes(), r.bytes()).unwrap();
        (bytes, committed)
    }

    #[test]
    fn owner_preparation_fences_admission_and_selects_unpublished_or_existing_requests() {
        use crate::{
            evidence_erasure_history as custody,
            evidence_store::{attested, erasure},
        };
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("archive");
        #[cfg(unix)]
        let custody_directory = {
            use std::os::unix::fs::PermissionsExt;
            tempfile::Builder::new()
                .permissions(std::fs::Permissions::from_mode(0o700))
                .tempdir_in(temp.path())
                .unwrap()
        };
        #[cfg(not(unix))]
        let custody_directory = tempfile::tempdir_in(temp.path()).unwrap();
        let directory = custody_directory.path().to_path_buf();
        let owner = Identity::generate();
        let issuer = Identity::generate();
        let writer = Identity::generate();
        let binding = attested::Binding {
            archive: [2; 32],
            scope: [1; 32],
            issuer: issuer.did().to_string(),
        };
        let archive = attested::Archive::create(&root, binding.clone()).unwrap();
        let mut history = custody::Access {
            directory,
            binding: crate::evidence_proof_service::Binding {
                profile: crate::evidence_proof_service::Profile::Admitted,
                archive: hex(&binding.archive),
                scope: hex(&binding.scope),
                issuer: binding.issuer.clone(),
            },
            owner: owner.did().to_string(),
            minimum: None,
        };
        history.initialize().unwrap();
        let genesis =
            custody::Record::sign(history.preview(None, "a".repeat(64)).unwrap(), &owner).unwrap();
        let minimum = genesis.id().unwrap();
        history.append(genesis).unwrap();
        history.minimum = Some(minimum);
        let mut service = AdmittingService::new(
            archive,
            issuer,
            vec![Grant {
                principal: writer.did().to_string(),
                append: true,
                inventory: true,
            }],
        )
        .unwrap()
        .with_erasure_history(history.clone())
        .unwrap();
        let mut previous = None;
        for n in 0..2u8 {
            let raw = SignedRequest::sign(
                Request {
                    version: 1,
                    scope: hex(&binding.scope),
                    audience: binding.issuer.clone(),
                    principal: writer.did().to_string(),
                    expires: None,
                    command: Command::Append {
                        id: hex(&[n + 1; 16]),
                        position: n as u64,
                        previous,
                        ciphertext: hex(b"synthetic ciphertext"),
                    },
                },
                &writer,
            )
            .unwrap()
            .bytes()
            .unwrap();
            if n == 1 {
                assert!(service.dispatch(&raw, 100).unwrap().reply.result.is_ok());
            }
            let record = history
                .append_prepared(|snapshot| {
                    let plan = attested::Archive::open(&root, binding.clone())
                        .unwrap()
                        .preview_request_erasure(&raw, hex(&[n + 2; 32]), 101)
                        .unwrap();
                    assert_eq!(plan.initial_erasure.is_some(), n == 0);
                    assert!(
                        matches!(service.dispatch(&raw, 100), Err(Failure::Unavailable)),
                        "managed ingest cannot run during owner preparation"
                    );
                    let erasure = erasure::Record::sign(plan, &service.signer).unwrap();
                    custody::Record::sign(
                        custody::Change {
                            version: 1,
                            binding: history.binding.clone(),
                            owner: history.owner.clone(),
                            sequence: snapshot.history.len().to_string(),
                            previous: snapshot.tip.clone(),
                            nonce: hex(&[n + 4; 32]),
                            recorded_at: "101".into(),
                            erasure: Some(erasure),
                        },
                        &owner,
                    )
                })
                .unwrap();
            assert!(
                service.dispatch(&raw, 100).is_err(),
                "published custody fences old ordinary admission before cleanup"
            );
            if n == 0 {
                assert!(matches!(
                    service
                        .admit_erased(&raw, record.change.erasure.as_ref().unwrap(), &history)
                        .unwrap()
                        .reply
                        .result,
                    Ok(Output::ErasedCommitted { .. })
                ));
            } else {
                history.reconcile_archive(&root).unwrap();
            }
            previous = Some(append_manifest(&raw).unwrap().cid().to_string());
        }
        assert_eq!(
            attested::Archive::verify_file(&root.join("archive.sqlite"), binding)
                .unwrap()
                .erased_objects,
            2
        );
    }

    #[test]
    fn reads_cannot_cross_audited_frontier_when_raw_append_arrives_after_audit() {
        let temp = tempfile::tempdir().unwrap();
        let writer = Identity::generate();
        let mut service = setup(temp.path(), &writer);
        service.audit_suffix().unwrap();
        assert_eq!(service.audited.through, 0);
        // Precisely schedule the competing commit after audit, before execution.
        let (_, record) = raw_append(&mut service, &writer, 0, None, true);
        let tip = record.manifest.cid().to_string();
        let commands = [
            (Command::Read { sequence: 1 }, Err(Failure::Missing)),
            (
                Command::Page {
                    through: 1,
                    tip: Some(tip),
                    after: 0,
                    limit: 1,
                },
                Err(Failure::Invalid),
            ),
            (
                Command::Snapshot,
                Ok(Output::Snapshot {
                    through: 0,
                    tip: None,
                }),
            ),
        ];
        for (command, expected) in commands {
            let request = signed(&service, &writer, command);
            assert_eq!(
                service.execute_audited(&request, &request.bytes().unwrap(), 1000),
                expected
            );
        }
        // The same evidence becomes readable through normal dispatch after audit.
        let read = signed(&service, &writer, Command::Read { sequence: 1 })
            .bytes()
            .unwrap();
        assert!(matches!(
            service.dispatch(&read, 1000).unwrap().reply.result,
            Ok(Output::Evidence { .. })
        ));
        assert_eq!(service.audited.through, 1);
    }

    #[test]
    fn verified_prefix_is_retained_without_skipping_a_later_invalid_record() {
        let temp = tempfile::tempdir().unwrap();
        let writer = Identity::generate();
        let mut service = setup(temp.path(), &writer);
        let mut previous = None;
        for position in 0..130 {
            let (_, record) = raw_append(&mut service, &writer, position, previous, true);
            previous = Some(record.manifest.cid().to_string());
        }
        raw_append(&mut service, &writer, 130, previous.clone(), false);
        for _ in 0..3 {
            let request = signed(&service, &writer, Command::Snapshot)
                .bytes()
                .unwrap();
            assert_eq!(
                service.dispatch(&request, 1000).unwrap().reply.result,
                Err(Failure::Corrupt)
            );
            assert_eq!(
                service.audited,
                Snapshot {
                    through: 130,
                    tip: Some(previous.as_ref().unwrap().parse().unwrap())
                }
            );
            assert_eq!(service.ledger.snapshot().unwrap().through, 131);
        }
    }

    #[test]
    fn exact_retry_does_not_discard_audited_progress() {
        let temp = tempfile::tempdir().unwrap();
        let writer = Identity::generate();
        let mut service = setup(temp.path(), &writer);
        let (first, record) = raw_append(&mut service, &writer, 0, None, true);
        raw_append(
            &mut service,
            &writer,
            1,
            Some(record.manifest.cid().to_string()),
            true,
        );
        service.audit_suffix().unwrap();
        let before = service.audited.clone();
        assert!(matches!(
            service.dispatch(&first, 1000).unwrap().reply.result,
            Ok(Output::Committed {
                duplicate: true,
                ..
            })
        ));
        assert_eq!(service.audited, before);
    }
}

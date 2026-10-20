//! Explicit authenticated metadata reads. Payload loss never grants write authority.
use crate::{
    evidence,
    evidence_attestation::Frontier,
    evidence_service::{self as service, Failure, Grant},
    evidence_store::{attested, inventory},
    sign::{self, Identity},
};
use atproto_dasl::{Cid, Ipld};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::PathBuf, time::Instant};

pub const PROTOCOL: &str = "kan-proof-reader/1";
pub const MAX_REQUEST: usize = 32 * 1024;
pub const MAX_REPLY: usize = 12 * 1024 * 1024;
pub const PAGE_LIMIT: usize = 40;
pub const READ_BATCH_LIMIT: usize = 8;
const READ_BATCH_BYTES: usize = 4 * 1024 * 1024;
const REQUEST_DOMAIN: &[u8] = b"tools.kan.proof-read.request.v2\0";
const REPLY_DOMAIN: &[u8] = b"tools.kan.proof-read.reply.v2\0";
type Result<T> = std::result::Result<T, Failure>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Profile {
    Admitted,
    Copied,
}
impl Profile {
    pub fn inventory(self) -> inventory::Profile {
        match self {
            Self::Admitted => inventory::Profile::Admitted,
            Self::Copied => inventory::Profile::Copied,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub profile: Profile,
    pub archive: String,
    pub scope: String,
    pub issuer: String,
}
impl Binding {
    pub fn owner_binding(&self) -> Result<attested::Binding> {
        service::author(&self.issuer)?;
        Ok(attested::Binding {
            archive: exact32(&self.archive)?,
            scope: exact32(&self.scope)?,
            issuer: self.issuer.clone(),
        })
    }
}
fn exact32(value: &str) -> Result<[u8; 32]> {
    service::unhex(value, 32)?
        .try_into()
        .map_err(|_| Failure::Invalid)
}
fn link(value: &str) -> Result<Cid> {
    if value.len() > 128 {
        return Err(Failure::Invalid);
    }
    let cid: Cid = value.parse().map_err(|_| Failure::Invalid)?;
    if cid.to_string() != value {
        return Err(Failure::Invalid);
    }
    evidence::link(&Ipld::Link(cid.clone()), 0x71).map_err(|_| Failure::Invalid)?;
    Ok(cid)
}
/// Coordinates are claims until checked against a signed pin or verified chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Coordinate {
    pub through: String,
    pub manifest: Option<String>,
    pub attestation: Option<String>,
}
impl Coordinate {
    pub fn from_frontier(value: &Frontier) -> Self {
        Self {
            through: value.through.to_string(),
            manifest: value.manifest.as_ref().map(ToString::to_string),
            attestation: value.attestation.as_ref().map(ToString::to_string),
        }
    }
    pub fn frontier(&self, binding: &Binding) -> Result<Frontier> {
        let owner = binding.owner_binding()?;
        if self.through.len() > 16 {
            return Err(Failure::Invalid);
        }
        let through: u64 = self.through.parse().map_err(|_| Failure::Invalid)?;
        if through.to_string() != self.through
            || through > evidence::MAX_SAFE_INTEGER as u64
            || (through == 0) != self.manifest.is_none()
            || (through == 0) != self.attestation.is_none()
        {
            return Err(Failure::Invalid);
        }
        Ok(Frontier {
            through,
            manifest: self.manifest.as_deref().map(link).transpose()?,
            attestation: self.attestation.as_deref().map(link).transpose()?,
            archive: (through > 0).then_some(owner.archive),
            scope: (through > 0).then_some(owner.scope),
            issuer: (through > 0).then_some(owner.issuer),
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Command {
    Capabilities,
    Snapshot,
    Page {
        pin: Coordinate,
        next: Coordinate,
        limit: usize,
    },
    Read {
        pin: Coordinate,
        selected: Coordinate,
    },
    ReadBatch {
        pin: Coordinate,
        selections: Vec<Coordinate>,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u8,
    pub binding: Binding,
    pub principal: String,
    pub expires: u64,
    pub command: Command,
}
impl Request {
    fn validate(&self) -> Result<()> {
        if self.version != 2 {
            return Err(Failure::Invalid);
        }
        self.binding.owner_binding()?;
        service::author(&self.principal)?;
        if let Command::ReadBatch { pin, selections } = &self.command {
            if selections.is_empty() || selections.len() > READ_BATCH_LIMIT {
                return Err(Failure::Invalid);
            }
            let pin = pin.frontier(&self.binding)?;
            for selected in selections {
                let selected = selected.frontier(&self.binding)?;
                if selected.through == 0 || selected.through > pin.through {
                    return Err(Failure::Invalid);
                }
            }
            return Ok(());
        }
        let (pin, next) = match &self.command {
            Command::Page { pin, next, limit } => {
                if *limit == 0 || *limit > PAGE_LIMIT {
                    return Err(Failure::Invalid);
                }
                (pin, next)
            }
            Command::Read { pin, selected } => (pin, selected),
            _ => return Ok(()),
        };
        let pin = pin.frontier(&self.binding)?;
        let next = next.frontier(&self.binding)?;
        if next.through > pin.through
            || (matches!(self.command, Command::Read { .. }) && next.through == 0)
        {
            return Err(Failure::Invalid);
        }
        Ok(())
    }
}
fn json(value: &impl Serialize) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| Failure::Invalid)
}
fn preimage(domain: &[u8], value: &impl Serialize) -> Result<Vec<u8>> {
    let mut bytes = domain.to_vec();
    bytes.extend_from_slice(&Sha256::digest(json(value)?));
    Ok(bytes)
}
fn signature(value: &str) -> Result<Vec<u8>> {
    let bytes = service::unhex(value, 64)?;
    if bytes.len() != 64 {
        return Err(Failure::Invalid);
    }
    Ok(bytes)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRequest {
    pub request: Request,
    pub signature: String,
}
impl SignedRequest {
    pub fn sign(request: Request, signer: &Identity) -> Result<Self> {
        request.validate()?;
        if request.principal != signer.did().as_str() {
            return Err(Failure::Invalid);
        }
        let signature = signer
            .sign(&preimage(REQUEST_DOMAIN, &request)?)
            .map_err(|_| Failure::Unavailable)?;
        let signed = Self {
            request,
            signature: service::hex(&signature),
        };
        signed.bytes()?;
        Ok(signed)
    }
    pub fn bytes(&self) -> Result<Vec<u8>> {
        let bytes = json(self)?;
        if bytes.len() > MAX_REQUEST {
            return Err(Failure::Invalid);
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_REQUEST {
            return Err(Failure::Invalid);
        }
        let signed: Self = serde_json::from_slice(bytes).map_err(|_| Failure::Invalid)?;
        if signed.bytes()? != bytes {
            return Err(Failure::Invalid);
        }
        signed.request.validate()?;
        if !sign::verify(
            &signed.request.principal,
            &preimage(REQUEST_DOMAIN, &signed.request)?,
            &signature(&signed.signature)?,
        ) {
            return Err(Failure::AccessLimited);
        }
        Ok(signed)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Availability {
    Available,
    Erased,
    Missing,
    Corrupt,
}
impl From<inventory::Availability> for Availability {
    fn from(value: inventory::Availability) -> Self {
        match value {
            inventory::Availability::Available => Self::Available,
            inventory::Availability::Erased => Self::Erased,
            inventory::Availability::Missing => Self::Missing,
            inventory::Availability::Corrupt => Self::Corrupt,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordView {
    pub sequence: String,
    pub manifest: String,
    pub receipt: String,
    pub proof: String,
    pub availability: Availability,
}
fn view(row: &inventory::Occurrence) -> RecordView {
    RecordView {
        sequence: row.record.sequence.to_string(),
        manifest: service::hex(row.record.manifest.bytes()),
        receipt: service::hex(row.record.receipt.bytes()),
        proof: service::hex(row.proof.bytes()),
        availability: row.availability.into(),
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Source {
    Erased,
    Available {
        signed_request: String,
        writer: String,
    },
    Missing,
    Corrupt,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Output {
    Capabilities {
        protocol: String,
        operations: Vec<String>,
    },
    Snapshot {
        frontier: Coordinate,
        plan: Option<String>,
        recipe_metadata_match: Option<bool>,
    },
    Page {
        records: Vec<RecordView>,
        next: Option<Coordinate>,
    },
    Evidence {
        record: RecordView,
        source: Source,
    },
    EvidenceBatch {
        records: Vec<EvidenceRecord>,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRecord {
    pub record: RecordView,
    pub source: Source,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub version: u8,
    pub request: String,
    pub issuer: String,
    pub result: Result<Output>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReply {
    pub reply: Reply,
    pub signature: String,
}
impl SignedReply {
    pub fn bytes(&self) -> Result<Vec<u8>> {
        let bytes = json(self)?;
        if bytes.len() > MAX_REPLY {
            return Err(Failure::Invalid);
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8], request: &[u8], issuer: &str) -> Result<Self> {
        if bytes.len() > MAX_REPLY || request.len() > MAX_REQUEST {
            return Err(Failure::Invalid);
        }
        let signed: Self = serde_json::from_slice(bytes).map_err(|_| Failure::Invalid)?;
        if signed.bytes()? != bytes {
            return Err(Failure::Invalid);
        }
        signed.verify(request, issuer)?;
        Ok(signed)
    }
    pub fn verify(&self, request: &[u8], issuer: &str) -> Result<&Reply> {
        service::author(issuer)?;
        if request.len() > MAX_REQUEST
            || self.reply.version != 2
            || self.reply.issuer != issuer
            || self.reply.request != service::hex(&Sha256::digest(request))
        {
            return Err(Failure::Invalid);
        }
        if !sign::verify(
            issuer,
            &preimage(REPLY_DOMAIN, &self.reply)?,
            &signature(&self.signature)?,
        ) {
            return Err(Failure::AccessLimited);
        }
        Ok(&self.reply)
    }
}

/// Owner configuration, never populated from a remote request. No append API.
pub struct Service {
    erasure_history: Option<crate::evidence_erasure_history::Access>,
    policy: Option<crate::evidence_policy::Access>,
    path: PathBuf,
    binding: Binding,
    signer: Identity,
    grants: BTreeMap<String, Grant>,
    budget: inventory::Budget,
}
impl Service {
    pub fn new(
        path: PathBuf,
        binding: Binding,
        signer: Identity,
        grants: Vec<Grant>,
        budget: inventory::Budget,
    ) -> Result<Self> {
        if signer.did().as_str() != binding.issuer {
            return Err(Failure::Invalid);
        }
        let grants = Self::permissions(grants)?;
        // Valid metadata admits browsing, never admission or payload completeness.
        inventory::Inventory::open(
            &path,
            binding.profile.inventory(),
            binding.owner_binding()?,
            budget.clone(),
        )?;
        Ok(Self {
            erasure_history: None,
            policy: None,
            path,
            binding,
            signer,
            grants,
            budget,
        })
    }
    /// Enroll in independently owner-authenticated erasure custody. Every read
    /// fails closed until the local archive matches the current history.
    pub fn with_erasure_history(
        mut self,
        history: crate::evidence_erasure_history::Access,
    ) -> Result<Self> {
        if history.binding != self.binding {
            return Err(Failure::Invalid);
        }
        history
            .current()?
            .check_archive(&self.path, &self.binding)?;
        self.erasure_history = Some(history);
        Ok(self)
    }
    pub fn with_policy(mut self, policy: crate::evidence_policy::Access) -> Result<Self> {
        if policy.binding != self.binding {
            return Err(Failure::Invalid);
        }
        self.replace_grants(policy.read()?.grants()?)?;
        self.policy = Some(policy);
        Ok(self)
    }
    fn permissions(grants: Vec<Grant>) -> Result<BTreeMap<String, Grant>> {
        let mut selected = BTreeMap::new();
        for grant in grants {
            service::author(&grant.principal)?;
            if selected.insert(grant.principal.clone(), grant).is_some() {
                return Err(Failure::Invalid);
            }
        }
        Ok(selected)
    }
    /// Owner-side current grant replacement. No network command calls this.
    pub fn replace_grants(&mut self, grants: Vec<Grant>) -> Result<()> {
        self.grants = Self::permissions(grants)?;
        Ok(())
    }
    pub fn dispatch(&self, bytes: &[u8], now: u64) -> Result<SignedReply> {
        if bytes.len() > MAX_REQUEST {
            return Err(Failure::Invalid);
        }
        // Hold the custody lease through reply signing. Owner publication waits
        // for earlier reads; later reads cannot expose an unreconciled backup.
        let custody = self
            .erasure_history
            .as_ref()
            .map(crate::evidence_erasure_history::Access::current)
            .transpose()?;
        if let Some(current) = &custody {
            current.check_archive(&self.path, &self.binding)?;
        }
        let policy = self
            .policy
            .as_ref()
            .map(crate::evidence_policy::Access::read)
            .transpose()?;
        let current = policy
            .as_ref()
            .map(|s| Self::permissions(s.grants()?))
            .transpose()?;
        let reply = Reply {
            version: 2,
            request: service::hex(&Sha256::digest(bytes)),
            issuer: self.binding.issuer.clone(),
            result: self.execute(bytes, now, current.as_ref().unwrap_or(&self.grants)),
        };
        let signature = self
            .signer
            .sign(&preimage(REPLY_DOMAIN, &reply)?)
            .map_err(|_| Failure::Unavailable)?;
        let signed = SignedReply {
            reply,
            signature: service::hex(&signature),
        };
        signed.bytes()?;
        Ok(signed)
    }
    fn remaining(&self, deadline: Instant) -> Result<inventory::Budget> {
        let duration = deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or(Failure::Unavailable)?;
        Ok(inventory::Budget {
            duration,
            ..self.budget.clone()
        })
    }
    fn open(&self, pin: Option<&Coordinate>, deadline: Instant) -> Result<inventory::Inventory> {
        let binding = self.binding.owner_binding()?;
        Ok(if let Some(pin) = pin {
            inventory::Inventory::open_at(
                &self.path,
                self.binding.profile.inventory(),
                binding,
                &pin.frontier(&self.binding)?,
                self.remaining(deadline)?,
            )?
        } else {
            inventory::Inventory::open(
                &self.path,
                self.binding.profile.inventory(),
                binding,
                self.remaining(deadline)?,
            )?
        })
    }
    fn page_budget(rows: usize) -> inventory::PageBudget {
        inventory::PageBudget {
            rows,
            record_bytes: 4 * 1024 * 1024,
            payload_bytes: PAGE_LIMIT * service::MAX_REQUEST,
        }
    }
    fn read_row(&self, row: &inventory::Occurrence, deadline: Instant) -> Result<EvidenceRecord> {
        let fresh = inventory::source(
            &self.path,
            self.binding.profile.inventory(),
            self.binding.owner_binding()?,
            &row.selection,
            service::MAX_REQUEST,
            self.remaining(deadline)?,
        )?;
        let mut record = view(row);
        let source = match fresh {
            inventory::Source::Available { bytes, writer } => {
                record.availability = Availability::Available;
                Source::Available {
                    signed_request: service::hex(&bytes),
                    writer,
                }
            }
            inventory::Source::Unavailable(inventory::Availability::Erased) => {
                record.availability = Availability::Erased;
                Source::Erased
            }
            inventory::Source::Unavailable(inventory::Availability::Missing) => {
                record.availability = Availability::Missing;
                Source::Missing
            }
            inventory::Source::Unavailable(inventory::Availability::Corrupt) => {
                record.availability = Availability::Corrupt;
                Source::Corrupt
            }
            inventory::Source::Unavailable(inventory::Availability::Available) => {
                return Err(Failure::Corrupt)
            }
        };
        Ok(EvidenceRecord { record, source })
    }
    fn execute(&self, bytes: &[u8], now: u64, grants: &BTreeMap<String, Grant>) -> Result<Output> {
        let signed = SignedRequest::decode(bytes)?;
        let request = signed.request;
        if request.binding != self.binding
            || request.expires < now
            || request.expires.saturating_sub(now) > 300
            || !grants.get(&request.principal).is_some_and(|g| g.inventory)
        {
            return Err(Failure::AccessLimited);
        }
        let deadline = Instant::now()
            .checked_add(self.budget.duration)
            .ok_or(Failure::Invalid)?;
        match request.command {
            Command::Capabilities => Ok(Output::Capabilities {
                protocol: PROTOCOL.into(),
                operations: ["capabilities", "snapshot", "page", "read", "read-batch"]
                    .map(String::from)
                    .to_vec(),
            }),
            Command::Snapshot => {
                let inventory = self.open(None, deadline)?;
                Ok(Output::Snapshot {
                    frontier: Coordinate::from_frontier(inventory.frontier()),
                    plan: inventory.copy_plan().map(|p| service::hex(p.bytes())),
                    recipe_metadata_match: inventory.recipe_metadata_match(),
                })
            }
            Command::Page { pin, next, limit } => {
                let inventory = self.open(Some(&pin), deadline)?;
                let page = inventory.page_from(
                    &next.frontier(&self.binding)?,
                    Self::page_budget(limit),
                    self.remaining(deadline)?,
                )?;
                let next = page
                    .records
                    .last()
                    .map(|r| r.proof.previous())
                    .filter(|p| p.through > 0)
                    .map(Coordinate::from_frontier);
                Ok(Output::Page {
                    records: page.records.iter().map(view).collect(),
                    next,
                })
            }
            Command::ReadBatch { pin, selections } => {
                let inventory = self.open(Some(&pin), deadline)?;
                let mut records = Vec::new();
                let mut payload_bytes = 0;
                for selected in selections {
                    let mut page = inventory.page_from(
                        &selected.frontier(&self.binding)?,
                        Self::page_budget(1),
                        self.remaining(deadline)?,
                    )?;
                    // Return an ordered prefix that fits both memory and wire bounds.
                    // Every legal single request fits this byte allowance.
                    if payload_bytes + page.payload_budget_used > READ_BATCH_BYTES {
                        break;
                    }
                    payload_bytes += page.payload_budget_used;
                    let row = page.records.pop().ok_or(Failure::Missing)?;
                    records.push(self.read_row(&row, deadline)?);
                }
                if records.is_empty() {
                    return Err(Failure::Corrupt);
                }
                Ok(Output::EvidenceBatch { records })
            }
            Command::Read { pin, selected } => {
                let inventory = self.open(Some(&pin), deadline)?;
                let mut page = inventory.page_from(
                    &selected.frontier(&self.binding)?,
                    Self::page_budget(1),
                    self.remaining(deadline)?,
                )?;
                let row = page.records.pop().ok_or(Failure::Missing)?;
                drop(inventory);
                let EvidenceRecord { record, source } = self.read_row(&row, deadline)?;
                Ok(Output::Evidence { record, source })
            }
        }
    }
}

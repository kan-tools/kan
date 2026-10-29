//! Offline selected-byte recovery. Never promotes legacy trust or cuts over.
use crate::{
    evidence_crypto as crypto, evidence_delivery,
    evidence_import::CHUNK,
    evidence_service as service,
    evidence_store::{RecoveryReader, Snapshot},
};
use atproto_dasl::Ipld;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Write,
    path::Path,
};

const MAX_PLAN: usize = 32 * 1024 * 1024;
const MAX_CHUNKS: usize = 262_144;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid or incomplete import evidence: {0}")]
    Invalid(&'static str),
    #[error(transparent)]
    Store(#[from] crate::evidence_store::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
type Result<T> = std::result::Result<T, Error>;
fn require(ok: bool, what: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Error::Invalid(what))
    }
}
fn digest(bytes: &[u8]) -> String {
    service::hex(&Sha256::digest(bytes))
}
fn hex32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn operation(plan: &str, ordinal: usize) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(b"tools.kan.import.operation.v1\0");
    hash.update(plan.as_bytes());
    hash.update((ordinal as u64).to_be_bytes());
    hash.finalize()[..16].to_vec()
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Header {
    pub(crate) version: u8,
    pub(crate) plan: String,
    pub(crate) ordinal: usize,
    pub(crate) kind: String,
    #[serde(deserialize_with = "required_optional_index")]
    pub(crate) file: Option<usize>,
    pub(crate) part: usize,
    pub(crate) parts: usize,
}
fn required_optional_index<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<usize>, D::Error> {
    Option::<usize>::deserialize(d)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Part {
    pub(crate) length: usize,
    pub(crate) sha256: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Route {
    pub(crate) scope: String,
    pub(crate) writer: String,
    pub(crate) audience: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Source {
    pub(crate) path: String,
    pub(crate) length: u64,
    pub(crate) sha256: String,
    pub(crate) chunks: Vec<Part>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Plan {
    pub(crate) profile: u8,
    pub(crate) source_id: String,
    pub(crate) selection: String,
    pub(crate) recipient: String,
    pub(crate) route: Route,
    pub(crate) inventory: Value,
    pub(crate) files: Vec<Source>,
}
/// Explicit operator pins. The plan must come from the original source planning.
pub struct Pins<'a> {
    pub expected_plan: &'a str,
    pub scope: [u8; 32],
    pub writer: &'a str,
    pub recipient_private: [u8; 32],
    pub max_records: u64,
}
/// Deterministic fault-observation points; not durability guarantees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Boundary {
    DirectoryCreated,
    ChunkWritten,
    FilesSynced,
    BeforeReport,
}
struct Reader<'a> {
    archive: RecoveryReader,
    pins: &'a Pins<'a>,
    snapshot: Snapshot,
}
impl Reader<'_> {
    fn locate(&self, count: usize) -> Result<Vec<Option<u64>>> {
        let ops = (0..count)
            .map(|i| (operation(self.pins.expected_plan, i), i))
            .collect::<BTreeMap<_, _>>();
        require(ops.len() == count, "operation collision")?;
        let mut found = vec![None; count];
        for seq in 1..=self.snapshot.through {
            let record = self.archive.record(seq)?;
            let body = record.manifest.body();
            if body["scopeToken"] != Ipld::Bytes(self.pins.scope.to_vec()) {
                continue;
            }
            let Ipld::Map(writer) = &body["writer"] else {
                return Err(Error::Invalid("writer"));
            };
            if writer.get("principal") != Some(&Ipld::String(self.pins.writer.to_owned())) {
                continue;
            }
            let Ipld::Bytes(op) = &body["operation"] else {
                return Err(Error::Invalid("operation"));
            };
            if let Some(&ordinal) = ops.get(op) {
                require(found[ordinal].replace(seq).is_none(), "duplicate operation")?;
            }
        }
        Ok(found)
    }
    fn frame(&self, seq: Option<u64>, ordinal: usize) -> Result<(Header, Vec<u8>, Value)> {
        let record = self
            .archive
            .record(seq.ok_or(Error::Invalid("missing operation"))?)?;
        let Ipld::List(entries) = &record.manifest.body()["entries"] else {
            return Err(Error::Invalid("entries"));
        };
        require(entries.len() == 1, "entry count")?;
        let Ipld::Map(entry) = &entries[0] else {
            return Err(Error::Invalid("entry"));
        };
        let Some(Ipld::Link(cid)) = entry.get("ciphertext") else {
            return Err(Error::Invalid("object link"));
        };
        let bytes = self.archive.read_object(cid)?;
        let signed = service::verify_retained_request(&record, &bytes)
            .map_err(|_| Error::Invalid("signed request/manifest/receipt binding"))?;
        let service::Command::Append { id, .. } = &signed.request.command else {
            return Err(Error::Invalid("not append"));
        };
        require(
            *id == service::hex(&operation(self.pins.expected_plan, ordinal)),
            "operation binding",
        )?;
        let plain = evidence_delivery::decrypt_request(
            &bytes,
            &self.pins.recipient_private,
            &self.pins.scope,
            self.pins.writer,
        )
        .map_err(|_| Error::Invalid("request decryption or pins"))?;
        let (header, body_offset) = decode_frame(&plain)?;
        require(
            header.version == 1
                && header.plan == self.pins.expected_plan
                && header.ordinal == ordinal,
            "frame identity",
        )?;
        Ok((
            header,
            plain[body_offset..].to_vec(),
            json!({"ordinal":ordinal,"sequence":record.sequence,"manifest":record.manifest.cid().to_string(),"audience":signed.request.audience}),
        ))
    }
}
/// Shared bounded decoder. Transport and plan bindings are checked by callers.
pub(crate) fn decode_frame(plain: &[u8]) -> Result<(Header, usize)> {
    require(
        plain.len() >= 9 && plain.len() <= CHUNK + 4096 && plain[..5] == *b"KANI\x01",
        "frame prefix/length",
    )?;
    let length = u32::from_be_bytes(plain[5..9].try_into().expect("fixed prefix")) as usize;
    require(
        length > 0
            && length <= 4096
            && 9 + length <= plain.len()
            && plain.len() - (9 + length) <= CHUNK,
        "header length",
    )?;
    let header: Header = serde_json::from_slice(&plain[9..9 + length])?;
    require(
        header.version == 1
            && hex32(&header.plan)
            && header.parts > 0
            && header.parts <= MAX_CHUNKS
            && header.part < header.parts
            && header.ordinal < MAX_CHUNKS + MAX_PLAN / CHUNK + 1,
        "frame coordinates",
    )?;
    require(
        match header.kind.as_str() {
            "inventory" => header.file.is_none() && header.parts <= MAX_PLAN / CHUNK,
            "data" => header.file.is_some_and(|i| i < 16_384),
            "complete" => header.file.is_none() && header.part == 0 && header.parts == 1,
            _ => false,
        },
        "frame kind",
    )?;
    Ok((header, 9 + length))
}

fn coordinates(
    h: &Header,
    kind: &str,
    file: Option<usize>,
    part: usize,
    parts: usize,
) -> Result<()> {
    require(
        h.kind == kind && h.file == file && h.part == part && h.parts == parts,
        "frame coordinates",
    )
}
fn safe_path(path: &str) -> bool {
    !path.is_empty()
        && path
            .split('/')
            .all(|c| !c.is_empty() && c != "." && c != ".." && !c.contains(['\\', ':', '\0']))
}
fn validate_plan(document: &[u8], pins: &Pins<'_>) -> Result<Plan> {
    validate_document(
        document,
        pins.expected_plan,
        &service::hex(&pins.scope),
        pins.writer,
        &service::hex(
            &crypto::public_key(&pins.recipient_private)
                .map_err(|_| Error::Invalid("recipient key"))?,
        ),
    )
}
pub(crate) fn validate_document(
    document: &[u8],
    expected_plan: &str,
    scope: &str,
    writer: &str,
    recipient: &str,
) -> Result<Plan> {
    let mut hash = Sha256::new();
    hash.update(b"tools.kan.import.plan.v1\0");
    hash.update(document);
    require(
        service::hex(&hash.finalize()) == expected_plan,
        "plan commitment",
    )?;
    let value: Value = serde_json::from_slice(document)?;
    require(serde_json::to_vec(&value)? == document, "noncanonical plan")?;
    let plan: Plan = serde_json::from_value(value)?;
    require(
        plan.profile == 1
            && hex32(&plan.source_id)
            && ["workspace", "store", "identity"].contains(&plan.selection.as_str()),
        "plan profile",
    )?;
    require(
        plan.route.scope == scope && plan.route.writer == writer && plan.recipient == recipient,
        "plan route/recipient",
    )?;
    require(
        plan.inventory["selected_inventory_complete"].is_boolean()
            && plan.inventory["notices"].is_array(),
        "inventory observations",
    )?;
    let inventory = plan.inventory["files"]
        .as_array()
        .ok_or(Error::Invalid("inventory files"))?;
    require(
        plan.files.len() <= 16_384 && inventory.len() == plan.files.len(),
        "file count",
    )?;
    let mut originals = BTreeMap::new();
    for file in inventory {
        let path = file["path"]
            .as_str()
            .ok_or(Error::Invalid("inventory path"))?;
        require(
            originals.insert(path, file).is_none(),
            "duplicate inventory path",
        )?;
    }
    let mut paths = BTreeSet::new();
    let mut count = 0usize;
    for file in &plan.files {
        require(
            safe_path(&file.path) && paths.insert(file.path.as_str()),
            "unsafe or duplicate path",
        )?;
        let original = originals
            .remove(file.path.as_str())
            .ok_or(Error::Invalid("inventory path mismatch"))?;
        require(
            original["length"].as_u64() == Some(file.length)
                && original["sha256"].as_str() == Some(&file.sha256),
            "inventory commitment mismatch",
        )?;
        require(
            hex32(&file.sha256) && !file.chunks.is_empty(),
            "file hash/chunks",
        )?;
        count = count
            .checked_add(file.chunks.len())
            .ok_or(Error::Invalid("chunk count"))?;
        require(count <= MAX_CHUNKS, "chunk limit")?;
        let mut total = 0u64;
        for (i, part) in file.chunks.iter().enumerate() {
            require(
                part.length <= CHUNK
                    && hex32(&part.sha256)
                    && (i + 1 == file.chunks.len() || part.length == CHUNK)
                    && (part.length > 0 || file.chunks.len() == 1),
                "chunk shape",
            )?;
            total += part.length as u64;
        }
        require(total == file.length, "file length")?;
    }
    // Reject file/directory prefix collisions before creating output.
    for path in &paths {
        for (index, _) in path.match_indices('/') {
            require(!paths.contains(&path[..index]), "file/directory collision")?;
        }
    }
    Ok(plan)
}
fn mkdir(path: &Path) -> Result<()> {
    // surface-write: evidence-restore:files,evidence-restore:plan.json,evidence-restore:report.json
    crate::persistence::create_dir_owner_only(
        crate::persistence::SurfaceWrite::EvidenceRestore,
        path,
    )?;
    Ok(())
}
/// Writes a NEW destination. Failure retains partial plaintext output for inspection.
pub fn restore(database: &Path, destination: &Path, pins: &Pins<'_>) -> Result<Value> {
    restore_observed(database, destination, pins, |_| {})
}
pub fn restore_observed(
    database: &Path,
    destination: &Path,
    pins: &Pins<'_>,
    observe: impl FnMut(Boundary),
) -> Result<Value> {
    require(
        hex32(pins.expected_plan) && pins.max_records > 0,
        "operator pins/limit",
    )?;
    restore_reader(
        RecoveryReader::open(database)?,
        destination,
        pins,
        None,
        observe,
    )
}
/// Offline restoration from an explicitly bound admitted/copied proof archive.
/// Metadata proof audit and source reads share one pinned transaction.
pub fn restore_proof(
    database: &Path,
    destination: &Path,
    pins: &Pins<'_>,
    binding: &crate::evidence_proof_service::Binding,
) -> Result<Value> {
    require(
        hex32(pins.expected_plan)
            && binding.scope == service::hex(&pins.scope)
            && pins.max_records > 0
            && pins.max_records <= 1_000_000,
        "proof restore pins/limit",
    )?;
    let owner = binding
        .owner_binding()
        .map_err(|_| Error::Invalid("proof binding"))?;
    let inventory = crate::evidence_store::inventory::Inventory::open(
        database,
        binding.profile.inventory(),
        owner,
        crate::evidence_store::inventory::Budget {
            items: pins.max_records.saturating_mul(4),
            metadata_bytes: 512 * 1024 * 1024,
            duration: std::time::Duration::from_secs(300),
            cancelled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        },
    )?;
    restore_reader(
        inventory.into_recovery()?,
        destination,
        pins,
        Some(binding),
        |_| {},
    )
}
fn restore_reader(
    archive: RecoveryReader,
    destination: &Path,
    pins: &Pins<'_>,
    binding: Option<&crate::evidence_proof_service::Binding>,
    mut observe: impl FnMut(Boundary),
) -> Result<Value> {
    require(
        hex32(pins.expected_plan) && pins.max_records > 0,
        "operator pins/limit",
    )?;
    let snapshot = archive.snapshot()?;
    require(
        snapshot.through > 0 && snapshot.through <= pins.max_records,
        "archive record limit",
    )?;
    let reader = Reader {
        archive,
        pins,
        snapshot,
    };
    let first = reader.locate(MAX_PLAN / CHUNK)?;
    let (header, body, _) = reader.frame(first[0], 0)?;
    let parts = header.parts;
    require(
        parts > 0 && parts <= MAX_PLAN / CHUNK,
        "inventory part limit",
    )?;
    coordinates(&header, "inventory", None, 0, parts)?;
    let mut document = Vec::new();
    for (i, seq) in first.iter().copied().enumerate().take(parts) {
        let (h, data) = if i == 0 {
            (None, body.clone())
        } else {
            let (h, data, _) = reader.frame(seq, i)?;
            (Some(h), data)
        };
        if let Some(h) = h {
            coordinates(&h, "inventory", None, i, parts)?;
        }
        require(
            !data.is_empty() && data.len() <= CHUNK && (i + 1 == parts || data.len() == CHUNK),
            "inventory chunk length",
        )?;
        document.extend(data);
    }
    let plan = validate_plan(&document, pins)?;
    let count = parts + plan.files.iter().map(|f| f.chunks.len()).sum::<usize>() + 1;
    let locations = reader.locate(count)?;
    require(
        locations.iter().all(Option::is_some),
        "incomplete operation coverage",
    )?;
    // Check every selected request, including inventory, against the committed audience.
    let mut provenance = Vec::with_capacity(count);
    for (i, seq) in locations.iter().copied().enumerate().take(parts) {
        let (_, _, p) = reader.frame(seq, i)?;
        require(
            p["audience"] == plan.route.audience,
            "audience differs from plan",
        )?;
        provenance.push(p);
    }
    mkdir(destination)?;
    observe(Boundary::DirectoryCreated);
    let files_root = destination.join("files");
    mkdir(&files_root)?;
    let mut directories = BTreeSet::from([files_root.clone()]);
    let mut ordinal = parts;
    let mut files = Vec::new();
    for (i, source) in plan.files.iter().enumerate() {
        let path = files_root.join(&source.path);
        let mut parent = files_root.clone();
        for component in source
            .path
            .split('/')
            .take(source.path.split('/').count() - 1)
        {
            parent.push(component);
            if directories.insert(parent.clone()) {
                mkdir(&parent)?;
            }
        }
        let mut output =
            // surface-write: evidence-restore:files
            crate::persistence::open_new_owner_only(crate::persistence::SurfaceWrite::EvidenceRestore, &path)?;
        let mut full = Sha256::new();
        for (j, part) in source.chunks.iter().enumerate() {
            let (h, bytes, p) = reader.frame(locations[ordinal], ordinal)?;
            coordinates(&h, "data", Some(i), j, source.chunks.len())?;
            require(
                p["audience"] == plan.route.audience,
                "audience differs from plan",
            )?;
            require(
                bytes.len() == part.length && digest(&bytes) == part.sha256,
                "chunk commitment",
            )?;
            full.update(&bytes);
            output.write_all(&bytes)?;
            observe(Boundary::ChunkWritten);
            provenance.push(p);
            ordinal += 1;
        }
        require(
            service::hex(&full.finalize()) == source.sha256,
            "whole-file commitment",
        )?;
        output.sync_all()?;
        files.push(json!({"path":source.path,"length":source.length,"sha256":source.sha256}));
    }
    let (h, bytes, p) = reader.frame(locations[ordinal], ordinal)?;
    coordinates(&h, "complete", None, 0, 1)?;
    require(
        p["audience"] == plan.route.audience,
        "audience differs from plan",
    )?;
    require(
        bytes
            == serde_json::to_vec(
                &json!({"plan":pins.expected_plan,"observation":"selected-snapshot-queued","recovery_verified":false,"independent_backup":false,"ready_for_cutover":false}),
            )?,
        "completion observation",
    )?;
    provenance.push(p);
    // surface-write: evidence-restore:plan.json
    crate::persistence::write_new_owner_only(
        crate::persistence::SurfaceWrite::EvidenceRestore,
        &destination.join("plan.json"),
        &document,
    )?;
    for dir in directories.iter().rev() {
        File::open(dir)?.sync_all()?;
    }
    File::open(destination)?.sync_all()?;
    observe(Boundary::FilesSynced);
    let report = json!({"profile":1,"plan":pins.expected_plan,"source_id":plan.source_id,"selection":plan.selection,
        "recipient":plan.recipient,"route":plan.route,"files":files,"operations":provenance,
        "archive_snapshot":{"through":reader.snapshot.through,"tip":reader.snapshot.tip.map(|c|c.to_string())},
        "verified_selected_file_bytes":true,"signed_requests_verified":true,"receipt_binding":if binding.is_some() {"issuer-attested-metadata"} else {"structural-only-unsigned"},
        "archive_history":if binding.is_some() {"issuer-attested-metadata-chain"} else {"not-certified"},"server_attestation":binding.is_some(),"proof_binding":binding,"claim_signatures":"not-verified",
        "selected_inventory_complete":plan.inventory["selected_inventory_complete"],"notices":plan.inventory["notices"],
        "independent_backup":false,"ready_for_cutover":false});
    observe(Boundary::BeforeReport);
    // surface-write: evidence-restore:report.json
    crate::persistence::write_new_owner_only(
        crate::persistence::SurfaceWrite::EvidenceRestore,
        &destination.join("report.json"),
        &serde_json::to_vec(&report)?,
    )?;
    File::open(destination)?.sync_all()?;
    File::open(
        destination
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?
    .sync_all()?;
    Ok(report)
}

//! Read-only selected v1 snapshots, encrypted through the shared durable queue.
use crate::{
    evidence_delivery, evidence_service as service, evidence_spool::Spool,
    migration_preflight as preflight, sign::Identity,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    path::{Component, Path, PathBuf},
};
pub const CHUNK: usize = 512 * 1024;
const MAX_CHUNKS: usize = 262_144;
const MAX_PLAN: usize = 32 * 1024 * 1024;
const PLAN_DOMAIN: &[u8] = b"tools.kan.import.plan.v1\0";
const OP_DOMAIN: &[u8] = b"tools.kan.import.operation.v1\0";
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Spool(#[from] crate::evidence_spool::Error),
    #[error(transparent)]
    Delivery(#[from] evidence_delivery::Error),
    #[error("import plan differs from the explicit expected commitment")]
    PlanMismatch,
    #[error("source bytes changed from the selected snapshot")]
    Changed,
    #[error("import inventory exceeds its explicit resource limit")]
    Limit,
    #[error("invalid import configuration: {0}")]
    Invalid(&'static str),
}
type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Selection {
    Workspace,
    Store,
    Identity,
}
#[derive(Debug, Clone, Serialize)]
struct Part {
    length: usize,
    sha256: String,
}
#[derive(Debug, Clone, Serialize)]
struct Source {
    path: PathBuf,
    length: u64,
    sha256: String,
    chunks: Vec<Part>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct Route {
    scope: String,
    writer: String,
    audience: String,
}
#[derive(Serialize)]
struct Header<'a> {
    version: u8,
    plan: &'a str,
    ordinal: usize,
    kind: &'static str,
    file: Option<usize>,
    part: usize,
    parts: usize,
}
#[derive(Clone, Copy)]
enum Entry {
    Inventory(usize),
    Data(usize, usize),
    Complete,
}

pub struct Plan {
    id: String,
    root: PathBuf,
    selection: Selection,
    source_id: [u8; 32],
    recipient: [u8; 32],
    route: Route,
    inventory: serde_json::Value,
    files: Vec<Source>,
    document: Vec<u8>,
}
#[derive(Debug, Serialize)]
pub struct Progress {
    pub plan: String,
    pub total_operations: usize,
    pub retained_operations: usize,
    pub pending_operations: usize,
    pub newly_queued: usize,
    pub queue_coverage_complete: bool,
    pub recovery_verified: bool,
    pub ready_for_cutover: bool,
}
fn digest(bytes: &[u8]) -> String {
    service::hex(&Sha256::digest(bytes))
}
fn tagged_digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(bytes);
    service::hex(&h.finalize())
}
fn same(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    let equal = before.len() == after.len() && before.modified().ok() == after.modified().ok();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        equal
            && before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        equal
    }
}
fn source_file(root: &Path, relative: &Path) -> Result<File> {
    if relative.as_os_str().is_empty() {
        return Err(Error::Invalid("empty source path"));
    }
    let mut path = root.to_path_buf();
    for component in relative.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(Error::Invalid("relative source path required"));
        }
        path.push(component);
        let meta = fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() {
            return Err(Error::Invalid("symlink source refused"));
        }
    }
    let before = fs::symlink_metadata(&path)?;
    if !before.is_file() {
        return Err(Error::Invalid("regular source file required"));
    }
    let file = File::open(&path)?;
    if !same(&before, &file.metadata()?) {
        return Err(Error::Changed);
    }
    Ok(file)
}
fn route(spool: &mut Spool) -> Result<Route> {
    let st = spool.status()?;
    Ok(Route {
        scope: st.scope,
        writer: st.writer,
        audience: st.audience,
    })
}
impl Plan {
    /// Hashes selected raw evidence without creating state, keys or network traffic.
    pub fn build(
        root: &Path,
        selection: Selection,
        source_id: [u8; 32],
        recipient: [u8; 32],
        spool: &mut Spool,
    ) -> Result<Self> {
        let preview = match selection {
            Selection::Workspace => preflight::preview(root),
            Selection::Store => preflight::preview_store(root),
            Selection::Identity => preflight::preview_identity(root),
        }?;
        let root = preview.root.clone();
        let mut files = Vec::new();
        let mut count = 0usize;
        for item in &preview.files {
            let mut file = source_file(&root, &item.path)?;
            let before = file.metadata()?;
            let mut whole = Sha256::new();
            let mut chunks = Vec::new();
            let mut length = 0u64;
            loop {
                let mut bytes = Vec::with_capacity(CHUNK);
                (&mut file).take(CHUNK as u64).read_to_end(&mut bytes)?;
                if bytes.is_empty() && !chunks.is_empty() {
                    break;
                }
                if count >= MAX_CHUNKS {
                    return Err(Error::Limit);
                }
                whole.update(&bytes);
                length += bytes.len() as u64;
                let last = bytes.len() < CHUNK;
                chunks.push(Part {
                    length: bytes.len(),
                    sha256: digest(&bytes),
                });
                count += 1;
                if last {
                    break;
                }
            }
            if length != item.length
                || service::hex(&whole.finalize()) != item.sha256
                || !same(&before, &file.metadata()?)
            {
                return Err(Error::Changed);
            }
            files.push(Source {
                path: item.path.clone(),
                length,
                sha256: item.sha256.clone(),
                chunks,
            });
        }
        // Canonical JSON object ordering is supplied by serde_json's default BTreeMap.
        let mut inventory = serde_json::to_value(&preview)?;
        if let Some(notices) = inventory["notices"].as_array_mut() {
            notices.sort_by_cached_key(|notice| notice.to_string());
        }
        let route = route(spool)?;
        let document = serde_json::to_vec(
            &serde_json::json!({"profile":1,"source_id":service::hex(&source_id),"selection":selection,"recipient":service::hex(&recipient),"route":route,"inventory":inventory,"files":files}),
        )?;
        if document.len() > MAX_PLAN {
            return Err(Error::Limit);
        }
        let id = tagged_digest(PLAN_DOMAIN, &document);
        Ok(Self {
            id,
            root,
            selection,
            source_id,
            recipient,
            route,
            inventory,
            files,
            document,
        })
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn summary(&self) -> serde_json::Value {
        serde_json::json!({"plan":self.id,"inventory":self.inventory,"data_chunks":self.files.iter().map(|f|f.chunks.len()).sum::<usize>(),"total_operations":self.entries().len(),"ready_for_cutover":false,"recovery_verified":false})
    }
    fn entries(&self) -> Vec<Entry> {
        let mut entries = (0..self.document.len().div_ceil(CHUNK))
            .map(Entry::Inventory)
            .collect::<Vec<_>>();
        for (i, file) in self.files.iter().enumerate() {
            for j in 0..file.chunks.len() {
                entries.push(Entry::Data(i, j));
            }
        }
        entries.push(Entry::Complete);
        entries
    }
    fn operation(&self, ordinal: usize) -> [u8; 16] {
        let mut h = Sha256::new();
        h.update(OP_DOMAIN);
        h.update(self.id.as_bytes());
        h.update((ordinal as u64).to_be_bytes());
        h.finalize()[..16].try_into().expect("fixed digest length")
    }
    /// Re-read one selected source chunk and check its pinned content hash.
    /// This reads raw source bytes, not remote evidence or a completion witness.
    pub fn read_source_chunk(&self, file_index: usize, chunk_index: usize) -> Result<Vec<u8>> {
        let source = self
            .files
            .get(file_index)
            .ok_or(Error::Invalid("source index"))?;
        let expected = source
            .chunks
            .get(chunk_index)
            .ok_or(Error::Invalid("chunk index"))?;
        let mut file = source_file(&self.root, &source.path)?;
        if file.metadata()?.len() != source.length {
            return Err(Error::Changed);
        }
        file.seek(SeekFrom::Start((chunk_index * CHUNK) as u64))?;
        let mut bytes = vec![0; expected.length];
        file.read_exact(&mut bytes)?;
        if digest(&bytes) != expected.sha256 {
            return Err(Error::Changed);
        }
        Ok(bytes)
    }
    fn frame(&self, ordinal: usize, entry: Entry) -> Result<Vec<u8>> {
        let (kind, index, part, parts, body) = match entry {
            Entry::Inventory(part) => {
                let end = ((part + 1) * CHUNK).min(self.document.len());
                (
                    "inventory",
                    None,
                    part,
                    self.document.len().div_ceil(CHUNK),
                    self.document[part * CHUNK..end].to_vec(),
                )
            }
            Entry::Data(i, j) => {
                let source = &self.files[i];
                let bytes = self.read_source_chunk(i, j)?;
                ("data", Some(i), j, source.chunks.len(), bytes)
            }
            Entry::Complete => (
                "complete",
                None,
                0,
                1,
                serde_json::to_vec(
                    &serde_json::json!({"plan":self.id,"observation":"selected-snapshot-queued","recovery_verified":false,"independent_backup":false,"ready_for_cutover":false}),
                )?,
            ),
        };
        let header = serde_json::to_vec(&Header {
            version: 1,
            plan: &self.id,
            ordinal,
            kind,
            file: index,
            part,
            parts,
        })?;
        let mut frame = b"KANI\x01".to_vec();
        frame.extend_from_slice(&(header.len() as u32).to_be_bytes());
        frame.extend_from_slice(&header);
        frame.extend_from_slice(&body);
        Ok(frame)
    }
    /// Local operation history is a resume hint, not independent recovered-content proof.
    pub fn progress(&self, spool: &mut Spool) -> Result<Progress> {
        if route(spool)? != self.route {
            return Err(Error::PlanMismatch);
        }
        let entries = self.entries();
        let mut retained = 0;
        let mut pending = 0;
        for ordinal in 0..entries.len() {
            if let Some(op) = spool.operation(&service::hex(&self.operation(ordinal)))? {
                retained += 1;
                pending += usize::from(op.pending);
            }
        }
        Ok(Progress {
            plan: self.id.clone(),
            total_operations: entries.len(),
            retained_operations: retained,
            pending_operations: pending,
            newly_queued: 0,
            queue_coverage_complete: retained == entries.len(),
            recovery_verified: false,
            ready_for_cutover: false,
        })
    }
    /// Revalidate the pinned inventory, then admit at most `limit` new operations.
    /// Full/error preserves any earlier admissions; delivery is a separate command.
    pub fn enqueue(
        &self,
        expected: &str,
        spool: &mut Spool,
        signer: &Identity,
        limit: usize,
    ) -> Result<Progress> {
        if !(1..=1024).contains(&limit) {
            return Err(Error::Invalid("batch limit must be 1..1024"));
        }
        if expected != self.id || route(spool)? != self.route {
            return Err(Error::PlanMismatch);
        }
        if signer.did().as_str() != self.route.writer {
            return Err(Error::Invalid("writer does not match plan"));
        }
        let current = Self::build(
            &self.root,
            self.selection,
            self.source_id,
            self.recipient,
            spool,
        )?;
        if current.id != self.id {
            return Err(Error::Changed);
        }
        let mut added = 0;
        for (ordinal, entry) in self.entries().into_iter().enumerate() {
            let operation = self.operation(ordinal);
            if spool.operation(&service::hex(&operation))?.is_some() {
                continue;
            }
            if added == limit {
                break;
            }
            if matches!(entry, Entry::Complete) {
                let final_plan = Self::build(
                    &self.root,
                    self.selection,
                    self.source_id,
                    self.recipient,
                    spool,
                )?;
                if final_plan.id != self.id {
                    return Err(Error::Changed);
                }
            }
            let plaintext = self.frame(ordinal, entry)?;
            evidence_delivery::queue(spool, signer, &self.recipient, &operation, &plaintext)?;
            added += 1;
        }
        let mut progress = self.progress(spool)?;
        progress.newly_queued = added;
        Ok(progress)
    }
}

//! Owner-triggered operations generations. No automatic expiry or deletion.
use crate::evidence_operations::{Journal, Snapshot};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::File,
    path::{Path, PathBuf},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const MANIFEST: &str = "manifest.json";
const LOCK: &str = "LOCK";
const MAX_MANIFEST: u64 = 1024 * 1024;
fn invalid() -> Box<dyn std::error::Error + Send + Sync> {
    "operations collection invalid, unavailable or in use".into()
}
fn hex(value: &str, size: usize) -> bool {
    value.len() == size
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn id() -> String {
    crate::evidence_service::hex(&rand::random::<[u8; 16]>())
}
fn digest(bytes: &[u8]) -> String {
    crate::evidence_service::hex(&Sha256::digest(bytes))
}
fn generation_path(root: &Path, id: &str) -> PathBuf {
    root.join(format!("generation-{id}.sqlite"))
}
fn private(path: &Path, directory: bool, max: u64) -> Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink()
        || (directory && !meta.is_dir())
        || (!directory && (!meta.is_file() || meta.len() > max))
    {
        return Err(invalid());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if meta.permissions().mode() & 0o077 != 0 || (!directory && meta.nlink() != 1) {
            return Err(invalid());
        }
    }
    Ok(())
}
fn lock(root: &Path, exclusive: bool) -> Result<File> {
    private(root, true, 0)?;
    let path = root.join(LOCK);
    private(&path, false, 0)?;
    let file = File::open(path)?;
    if exclusive {
        fs4::FileExt::try_lock(&file).map_err(|_| invalid())?;
    } else {
        fs4::FileExt::try_lock_shared(&file).map_err(|_| invalid())?;
    }
    Ok(file)
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Binding {
    spool: String,
    writer: String,
    scope: String,
    audience: String,
}
impl Binding {
    fn of(journal: &Journal) -> Result<Self> {
        let (spool, writer, scope, audience) = journal.binding()?;
        Ok(Self {
            spool,
            writer,
            scope,
            audience,
        })
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Generation {
    pub id: String,
    pub sealed_sha256: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u8,
    binding: Binding,
    active: String,
    generations: Vec<Generation>,
}
fn manifest(root: &Path) -> Result<Manifest> {
    let path = root.join(MANIFEST);
    private(&path, false, MAX_MANIFEST)?;
    let m: Manifest = serde_json::from_slice(&std::fs::read(path)?)?;
    if m.version != 1
        || m.generations.is_empty()
        || m.generations.len() > 1024
        || !hex(&m.active, 32)
    {
        return Err(invalid());
    }
    let mut ids = BTreeSet::new();
    for (i, g) in m.generations.iter().enumerate() {
        if !hex(&g.id, 32) || !ids.insert(&g.id) {
            return Err(invalid());
        }
        if i == m.generations.len() - 1 {
            if g.id != m.active || g.sealed_sha256.is_some() {
                return Err(invalid());
            }
        } else if !g.sealed_sha256.as_ref().is_some_and(|s| hex(s, 64)) {
            return Err(invalid());
        }
    }
    Ok(m)
}
/// Prevent upgraded callers from bypassing collection lifetime locks by opening
/// a generation path directly. Historical readers use the read-only API below.
pub(crate) fn check_standalone(path: &Path) -> Result<()> {
    if path
        .file_name()
        .and_then(|s| s.to_str())
        .is_some_and(|s| s.starts_with("generation-"))
        && path
            .parent()
            .is_some_and(|p| std::fs::symlink_metadata(p.join(MANIFEST)).is_ok())
    {
        return Err(invalid());
    }
    Ok(())
}
pub fn open(root: &Path) -> Result<Journal> {
    let held = lock(root, false)?;
    let m = manifest(root)?;
    let path = generation_path(root, &m.active);
    private(&path, false, 32 * 1024 * 1024)?;
    let mut journal = Journal::open_file(&path, false, false)?;
    if Binding::of(&journal)? != m.binding {
        return Err(invalid());
    }
    journal.scope = format!(
        "active generation {} only; sealed history excluded",
        m.active
    );
    journal.collection_lock = Some(held);
    Ok(journal)
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Boundary {
    StagedGeneration,
    SealedHistory,
    StagedManifest,
    PublishedManifest,
    DirectorySynced,
}
fn publish(root: &Path, m: &Manifest, hook: &mut impl FnMut(Boundary) -> Result<()>) -> Result<()> {
    let tmp = root.join(format!(".manifest-{}", id()));
    let body = serde_json::to_vec(m)?;
    if body.len() > MAX_MANIFEST as usize {
        return Err(invalid());
    }
    // surface-write: evidence-operations-collection:.manifest-*
    crate::persistence::write_new_owner_only(
        crate::persistence::SurfaceWrite::EvidenceOperationsCollection,
        &tmp,
        &body,
    )?;
    hook(Boundary::StagedManifest)?;
    let destination = root.join(MANIFEST);
    match std::fs::symlink_metadata(&destination) {
        Ok(_) => private(&destination, false, MAX_MANIFEST)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    // surface-write: evidence-operations-collection:manifest.json,evidence-operations-collection:.manifest-*
    crate::persistence::rename(
        crate::persistence::SurfaceWrite::EvidenceOperationsCollection,
        &tmp,
        &destination,
    )?;
    hook(Boundary::PublishedManifest)?;
    File::open(root)?.sync_all()?;
    hook(Boundary::DirectorySynced)
}
fn sidecars_absent(path: &Path) -> Result<()> {
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        match std::fs::symlink_metadata(Path::new(&name)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err(invalid()),
        }
    }
    Ok(())
}
fn new_generation(root: &Path, binding: &Binding, old: &Journal) -> Result<Generation> {
    let id = id();
    let path = generation_path(root, &id);
    let mut fresh = Journal::create(&path, Path::new(&binding.spool))?;
    if Binding::of(&fresh)? != *binding {
        return Err(invalid());
    }
    fresh.seed_worker(old)?;
    drop(fresh);
    File::open(&path)?.sync_all()?;
    File::open(root)?.sync_all()?;
    Ok(Generation {
        id,
        sealed_sha256: None,
    })
}
/// Adopt by copying: the original standalone file remains untouched. Older
/// binaries do not honor our advisory locks and must be stopped by the owner.
pub fn adopt(source: &Path, root: &Path) -> Result<()> {
    adopt_with_hook(source, root, |_| Ok(()))
}
pub fn adopt_with_hook(
    source: &Path,
    root: &Path,
    mut hook: impl FnMut(Boundary) -> Result<()>,
) -> Result<()> {
    check_standalone(source)?;
    sidecars_absent(source)?;
    let mut original = Journal::open_file(source, true, false)?;
    let binding = Binding::of(&original)?;
    let bytes = original.frozen_bytes(source)?;
    // surface-write: evidence-operations-collection:directory
    crate::persistence::create_dir_owner_only(
        crate::persistence::SurfaceWrite::EvidenceOperationsCollection,
        root,
    )?;
    // surface-write: evidence-operations-collection:LOCK
    crate::persistence::write_new_owner_only(
        crate::persistence::SurfaceWrite::EvidenceOperationsCollection,
        &root.join(LOCK),
        &[],
    )?;
    let _held = lock(root, true)?;
    let copied = id();
    let copy = generation_path(root, &copied);
    // surface-write: evidence-operations-collection:generation-*.sqlite
    crate::persistence::write_new_owner_only(
        crate::persistence::SurfaceWrite::EvidenceOperationsCollection,
        &copy,
        &bytes,
    )?;
    if digest(&std::fs::read(&copy)?) != digest(&bytes) {
        return Err(invalid());
    }
    let checked = Journal::open_file(&copy, false, true)?;
    if Binding::of(&checked)? != binding {
        return Err(invalid());
    }
    let fresh = new_generation(root, &binding, &original)?;
    hook(Boundary::StagedGeneration)?;
    let m = Manifest {
        version: 1,
        binding,
        active: fresh.id.clone(),
        generations: vec![
            Generation {
                id: copied,
                sealed_sha256: Some(digest(&bytes)),
            },
            fresh,
        ],
    };
    hook(Boundary::SealedHistory)?;
    publish(root, &m, &mut hook)
}
pub fn rotate(root: &Path) -> Result<()> {
    rotate_with_hook(root, |_| Ok(()))
}
pub fn rotate_with_hook(root: &Path, mut hook: impl FnMut(Boundary) -> Result<()>) -> Result<()> {
    let _held = lock(root, true)?;
    let mut m = manifest(root)?;
    if m.generations.len() >= 1024 {
        return Err(invalid());
    }
    // Owner maintenance verifies membership; ordinary active polling does not
    // read every sealed file. Unreferenced staged files are never auto-admitted.
    for g in &m.generations[..m.generations.len() - 1] {
        let path = generation_path(root, &g.id);
        private(&path, false, 32 * 1024 * 1024)?;
        sidecars_absent(&path)?;
        if Some(digest(&std::fs::read(&path)?)) != g.sealed_sha256 {
            return Err(invalid());
        }
        let j = Journal::open_file(&path, true, true)?;
        if Binding::of(&j)? != m.binding {
            return Err(invalid());
        }
    }
    let path = generation_path(root, &m.active);
    private(&path, false, 32 * 1024 * 1024)?;
    sidecars_absent(&path)?;
    let mut old = Journal::open_file(&path, true, false)?;
    if Binding::of(&old)? != m.binding {
        return Err(invalid());
    }
    let frozen = old.frozen_bytes(&path)?;
    let fresh = new_generation(root, &m.binding, &old)?;
    hook(Boundary::StagedGeneration)?;
    m.generations.last_mut().ok_or_else(invalid)?.sealed_sha256 = Some(digest(&frozen));
    m.active = fresh.id.clone();
    m.generations.push(fresh);
    hook(Boundary::SealedHistory)?;
    publish(root, &m, &mut hook)
}
#[derive(Debug, Serialize)]
pub struct Generations {
    pub version: u8,
    pub active: String,
    pub generations: Vec<Generation>,
    pub next: Option<usize>,
    pub totals: &'static str,
}
pub fn generations(root: &Path, after: usize, limit: usize) -> Result<Generations> {
    if limit == 0 || limit > 100 {
        return Err(invalid());
    }
    let _held = lock(root, false)?;
    let m = manifest(root)?;
    if after > m.generations.len() {
        return Err(invalid());
    }
    let end = after.saturating_add(limit).min(m.generations.len());
    Ok(Generations {
        version: 1,
        active: m.active,
        generations: m.generations[after..end].to_vec(),
        next: (end < m.generations.len()).then_some(end),
        totals: "not additive; cumulative identities may recur across generations",
    })
}
pub fn history(root: &Path, generation: &str) -> Result<Snapshot> {
    let _held = lock(root, false)?;
    let m = manifest(root)?;
    let g = m
        .generations
        .iter()
        .find(|g| g.id == generation)
        .ok_or_else(invalid)?;
    let expected = g.sealed_sha256.as_ref().ok_or_else(invalid)?;
    let path = generation_path(root, generation);
    private(&path, false, 32 * 1024 * 1024)?;
    sidecars_absent(&path)?;
    let mut journal = Journal::open_file(&path, false, true)?;
    if &digest(&std::fs::read(&path)?) != expected || Binding::of(&journal)? != m.binding {
        return Err(invalid());
    }
    journal.scope = format!("sealed generation {generation} only; not a collection total");
    journal.snapshot()
}

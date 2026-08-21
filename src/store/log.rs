//! The local append-only signed log — source of truth (`docs/SPEC.md` §10;
//! ADR-3 for the `.kan/log/` location; ADR-12 for the `atproto-repo` switch;
//! ADR-13 for incremental append).
//!
//! Claims are stored content-addressed, keyed by their own `content_cid`
//! (`crate::cid::content_cid`) under the typed `tools.kan.claim` collection,
//! inside a single on-disk CAR file — this is the same on-disk artifact
//! atproto sync would use later. Logs written with the historical
//! `dev.kan.claim` collection are verified and migrated on the next writable
//! open; old blocks remain in the append-only CAR while old keys leave the
//! live MST.
//!
//! `atproto-repo`'s `CarWriter` always writes a fresh header at construction
//! time, and there's no public "resume writing an existing file" mode. But
//! `CarBlock::to_bytes()` (length-prefix + CID + data, the exact wire format
//! `atproto_dasl::car`'s own module doc documents) is public, so
//! `Log::append` writes *only the new blocks* — the new record, whatever
//! `Mst` internal nodes changed along the insertion path (not the whole
//! tree — MST is a persistent structure, most nodes are unchanged and
//! shared across versions), and the new commit — directly to the end of the
//! file. This is genuinely incremental, not O(n) per append.
//!
//! The tradeoff: since the CAR header's `roots` field is fixed at whatever
//! it was when the file was first created, it goes stale after the first
//! append and is never consulted for real logic. A sibling `HEAD` file
//! (the same pattern ADR-8 used for `atrium-repo`, dropped when ADR-12
//! switched crates because full-rewrite made it briefly unnecessary — now
//! back) tracks the actual current root commit's CID.
//!
//! Two `Cid` types are in play, and the split isn't consistent, so every
//! call site converts explicitly rather than relying on inference: `Mst`'s
//! `root`/`from_root` speak the *raw* `cid` crate type (aliased here as
//! `RawCid`), but `insert`/`get` — on the same `Mst` — speak
//! `atproto_dasl::Cid`, the DAG-CBOR-serialization-friendly wrapper that
//! `Commit` and `BlockStorage` also use; `CarBlock` splits the same way
//! (`CarBlock::new` takes raw; `CarHeader::with_root` takes wrapped). This
//! asymmetry isn't a kan design choice; it's the crate's actual shape, found
//! via compiler error rather than assumed from its docs (see ADR-11/12's
//! whole point: verify, don't trust the shape). Kan's own types
//! (`crate::claim::v1::*`) standardize on the wrapper.

use std::{collections::HashSet, path::Path};

use atproto_dasl::{
    car::{CarBlock, CarHeader, CarReader},
    storage::{BlockStorage, MemoryStorage},
    Cid, CidCore as RawCid,
};
use atproto_repo::{compute_cid, Commit, RecordPath};

use crate::mst::{Mst, MstConfig};
use serde::{Deserialize, Serialize};
use tokio::{fs, io::AsyncWriteExt};

use crate::{
    cid::content_cid,
    claim::v1::{Claim, ClaimContent},
    sign::Identity,
    store::tid::TidGenerator,
};

/// Closed transport signer inventory for the ATProto repository containing
/// kan records. This approves a repository transition; it does not author a
/// kan claim or confer scope authority. A future network-account arm can be
/// added without making a kan principal usable here.
pub enum RepositoryTransportSigner<'a> {
    LocalDidKey(&'a Identity),
}

impl RepositoryTransportSigner<'_> {
    fn did(&self) -> String {
        match self {
            Self::LocalDidKey(identity) => identity.did(),
        }
    }

    fn sign(&self, unsigned: &[u8]) -> Result<Vec<u8>, Error> {
        match self {
            Self::LocalDidKey(identity) => Ok(identity.sign(unsigned)?),
        }
    }

    fn verify(&self, commit: &Commit) -> Result<bool, Error> {
        let unsigned = commit.signing_bytes()?;
        match self {
            Self::LocalDidKey(identity) => {
                Ok(crate::sign::verify(&identity.did(), &unsigned, &commit.sig))
            }
        }
    }
}

const LEGACY_COLLECTION: &str = "dev.kan.claim";
const COLLECTION: &str = "tools.kan.claim";

/// Canonical ordering value for published records written before the git-tree
/// envelope carried a `rev`. TID zero sorts before every timestamped record;
/// claims sharing it remain deterministically ordered by their content CID.
pub(crate) const LEGACY_PUBLISHED_REV: &str = "2222222222222";

/// Opaque filesystem artifacts owned by one log. Their internal CAR/MST
/// fields have their own conformance suite, so the surface catalog treats the
/// container as one value rather than duplicating that format specification.
pub const SURFACE_VALUES: &[crate::surface::SurfaceValue] = &[
    crate::surface::SurfaceValue::new("local-log:repo.car", "*"),
    crate::surface::SurfaceValue::new("local-log:repo.car.damaged-*", "*"),
    crate::surface::SurfaceValue::new("local-log:repo.repair", "*"),
    crate::surface::SurfaceValue::new("local-log:HEAD", "*"),
    crate::surface::SurfaceValue::new("local-log:HEAD.tmp", "*"),
    crate::surface::SurfaceValue::new("local-log:LOCK", "*"),
];

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("repository error: {0}")]
    Repo(#[from] atproto_repo::errors::RepoError),
    #[error("MST error: {0}")]
    Mst(#[from] crate::mst::Error),
    #[error("storage error: {0}")]
    Storage(#[from] atproto_dasl::errors::StorageError),
    #[error("CAR error: {0}")]
    Car(#[from] atproto_dasl::errors::CarError),
    #[error("signing error: {0}")]
    Sign(#[from] crate::sign::Error),
    #[error("content addressing error: {0}")]
    Cid(#[from] crate::cid::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("claim signature does not verify against its own author")]
    BadSignature,
    #[error(transparent)]
    AtClaim(#[from] crate::at_claim::Error),
    #[error(transparent)]
    ClaimCodecEncode(#[from] crate::claim::codec::EncodeError),
    #[error(transparent)]
    Claim(#[from] crate::claim::Error),
    #[error("claim codec decode failed: {0}")]
    ClaimCodecDecode(#[from] crate::claim::codec::DecodeError),
    #[error("current claim scope `{claim}` does not match activated scope `{activated}`")]
    ClaimScopeMismatch {
        claim: crate::identity::scope_inception::ScopeId,
        activated: crate::identity::scope_inception::ScopeId,
    },
    #[error("claim key already exists in the mixed-codec collection: {0}")]
    ClaimAlreadyExists(String),
    #[error("existing repository belongs to `{actual}`, not transport signer `{expected}`")]
    RepositoryDidMismatch { expected: String, actual: String },
    #[error("repository commit history contains a cycle at {0}")]
    RepositoryCommitCycle(String),
    #[error("repository commit {0} does not verify under its selected owner")]
    BadRepositorySignature(String),
    #[error("repository commit history no longer descends from the previously verified root {0}")]
    RepositoryHistoryDiverged(String),
    #[error("legacy and current claim records conflict at key {0}")]
    ClaimMigrationConflict(String),
    #[error("claim migration cannot load {collection}/{key} record block {record_cid}")]
    MissingClaimRecord {
        collection: &'static str,
        key: String,
        record_cid: String,
    },
    #[error("log exists but its CAR file has no root")]
    MissingRoot,
    /// The CAR's header cannot be read at all — a zero-byte file (the
    /// residue of a crash between file creation and the first header
    /// write) or leading corruption. Distinct from a damaged *tail*, which
    /// the tolerant reader recovers from: with no header there is nothing
    /// safe to recover toward, so kan refuses to touch the file.
    #[error(
        "the log header at {path} is unreadable (empty or corrupt at the start of the \
         file). kan will not modify it. Move the file aside and restore from the \
         published .claims/ tree (`kan restore`) or a backup; any claims after the \
         damaged header are still in the file"
    )]
    UnreadableCar { path: String },
    #[error("log exists but HEAD is missing or unreadable")]
    MissingHead,
    #[error("record key is not a valid CID: {0}")]
    InvalidCid(#[from] atproto_dasl::errors::DecodeError),
    /// A write was attempted through a log opened read-only.
    ///
    /// This is an internal invariant, not something an operator can provoke:
    /// the CLI routes write verbs to `Workspace::open` and read verbs to
    /// `Workspace::open_read_only`. It exists so that routing is enforced by
    /// the type rather than by everyone remembering.
    #[error(
        "internal error: a write reached a log opened read-only, which has no signing \
         identity. A read path acquired a write it should not have."
    )]
    ReadOnly,
}

/// What's actually stored in the MST: the signed claim plus its log-revision
/// TID, captured at append time (ordering is log structure, not claim
/// content, so it lives in the envelope rather than `ClaimContent`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredClaim {
    pub claim: Claim,
    pub rev: String,
}

pub struct Log {
    car_path: std::path::PathBuf,
    head_path: std::path::PathBuf,
    mst: Mst<MemoryStorage>,
    /// `None` until the first claim is appended — `Mst::new` starts with no
    /// root at all (unlike `atrium-repo`, which eagerly computed an
    /// empty-tree CID), so there's no meaningful "genesis commit over
    /// nothing" to create up front. The CAR file itself doesn't exist yet
    /// either in this state; both come into being together on first append.
    commit_cid: Option<Cid>,
    /// Every CID already durably written to `car_path` — `append` diffs
    /// against this to find only the new blocks to write, instead of
    /// re-serializing everything `mst.storage()` has ever seen.
    persisted: HashSet<Cid>,
    lock_path: std::path::PathBuf,
    /// The authoritative log and derived overlay share CAR machinery, but
    /// their files are distinct declared persistence surfaces.
    surface: LogSurface,
    /// The DID that goes into a commit this log writes — `None` for a log
    /// opened read-only, which has no signing identity and cannot commit.
    ///
    /// Read-only is not a lesser mode: a *read* genuinely has no business
    /// resolving an identity (`.design/identity-surface.md` REQ-2), and
    /// making that unrepresentable in the type is what stops a read path
    /// quietly acquiring one again.
    did: Option<String>,
    tid: TidGenerator,
    /// Floor for the next `ClaimContent::recorded_at`, so two appends in the
    /// same wall-clock microsecond still get distinct values — without which
    /// identical content in a tight loop collides again and the defect
    /// `recorded_at` exists to fix returns.
    ///
    /// Cross-process too, not merely within-process: the floor is seeded
    /// from the reopened log's last commit `rev` (itself a microsecond
    /// timestamp) on open and again on any mid-flight reload, and the write
    /// lock serializes appends — so a second writer cannot mint a value at
    /// or below one already durably recorded.
    last_recorded_at: u64,
    /// Set when the CAR was read tolerantly because its tail was damaged.
    ///
    /// The file must be rewritten from the intact blocks **before** anything
    /// is appended to it. Without that, `persist_new_blocks` opens the file
    /// `append(true)` and writes *past* the damaged region, so every new
    /// block is unreachable to the same tolerant read that recovered the
    /// rest — silently, permanently, at exit 0. v0.6 bricked reads on a torn
    /// tail, which was loud and recoverable; leaving this unrepaired would
    /// turn that into unbounded silent loss, which is strictly worse than
    /// the defect recovery was added to fix.
    ///
    /// The repair happens under the write lock in `append`, never on open: a
    /// read command must not modify the log.
    needs_repair: bool,
    /// Set when `HEAD` on disk does not name the root this `Log` is using —
    /// it was missing, unparseable, or named a block the CAR lacks, and a
    /// root was recovered instead.
    ///
    /// Persisted by the next append, under the write lock, never on open. A
    /// read command must not rewrite `HEAD`: doing so off the lock turned a
    /// transient torn read (CAR read before `HEAD`, an append landing
    /// between) into a permanent rollback of a healthy log.
    head_stale: bool,
}

/// Holds the exclusive write lock for as long as it is alive.
///
/// `flock` is released by the OS when the file descriptor closes, so a
/// crashed or killed writer cannot leave the log permanently locked — which
/// is the property an `O_EXCL` lockfile would not have given us.
struct WriteGuard {
    file: std::fs::File,
}

#[derive(Clone, Copy)]
enum LogSurface {
    Local,
    Overlay,
}

impl LogSurface {
    async fn create_dir(self, dir: &Path) -> std::io::Result<()> {
        match self {
            Self::Local => {
                // surface-write: local-log:repo.car
                crate::persistence::create_dir_all_async(
                    crate::persistence::SurfaceWrite::LocalLogCar,
                    dir,
                )
                .await
            }
            Self::Overlay => {
                // surface-write: overlay:repo.car
                crate::persistence::create_dir_all_async(
                    crate::persistence::SurfaceWrite::Overlay,
                    dir,
                )
                .await
            }
        }
    }

    async fn copy_damaged(self, from: &Path, to: &Path) -> std::io::Result<u64> {
        match self {
            Self::Local => {
                // surface-write: local-log:repo.car.damaged-*
                crate::persistence::copy_async(
                    crate::persistence::SurfaceWrite::LocalLogDamaged,
                    from,
                    to,
                )
                .await
            }
            Self::Overlay => {
                // surface-write: overlay:repo.car.damaged-*
                crate::persistence::copy_async(crate::persistence::SurfaceWrite::Overlay, from, to)
                    .await
            }
        }
    }

    async fn create_repair(self, path: &Path) -> std::io::Result<tokio::fs::File> {
        match self {
            Self::Local => {
                // surface-write: local-log:repo.repair
                crate::persistence::create_file_async(
                    crate::persistence::SurfaceWrite::LocalLogRepair,
                    path,
                )
                .await
            }
            Self::Overlay => {
                // surface-write: overlay:repo.repair
                crate::persistence::create_file_async(
                    crate::persistence::SurfaceWrite::Overlay,
                    path,
                )
                .await
            }
        }
    }

    async fn rename_car(self, from: &Path, to: &Path) -> std::io::Result<()> {
        match self {
            Self::Local => {
                // surface-write: local-log:repo.car
                crate::persistence::rename_async(
                    crate::persistence::SurfaceWrite::LocalLogCar,
                    from,
                    to,
                )
                .await
            }
            Self::Overlay => {
                // surface-write: overlay:repo.car
                crate::persistence::rename_async(
                    crate::persistence::SurfaceWrite::Overlay,
                    from,
                    to,
                )
                .await
            }
        }
    }

    async fn open_append(self, path: &Path) -> std::io::Result<tokio::fs::File> {
        match self {
            Self::Local => {
                // surface-write: local-log:repo.car
                crate::persistence::open_append_async(
                    crate::persistence::SurfaceWrite::LocalLogCar,
                    path,
                )
                .await
            }
            Self::Overlay => {
                // surface-write: overlay:repo.car
                crate::persistence::open_append_async(
                    crate::persistence::SurfaceWrite::Overlay,
                    path,
                )
                .await
            }
        }
    }

    async fn create_head_temp(self, path: &Path) -> std::io::Result<tokio::fs::File> {
        match self {
            Self::Local => {
                // surface-write: local-log:HEAD.tmp
                crate::persistence::create_file_async(
                    crate::persistence::SurfaceWrite::LocalLogHeadTemp,
                    path,
                )
                .await
            }
            Self::Overlay => {
                // surface-write: overlay:HEAD.tmp
                crate::persistence::create_file_async(
                    crate::persistence::SurfaceWrite::Overlay,
                    path,
                )
                .await
            }
        }
    }

    async fn rename_head(self, from: &Path, to: &Path) -> std::io::Result<()> {
        match self {
            Self::Local => {
                // surface-write: local-log:HEAD
                crate::persistence::rename_async(
                    crate::persistence::SurfaceWrite::LocalLogHead,
                    from,
                    to,
                )
                .await
            }
            Self::Overlay => {
                // surface-write: overlay:HEAD
                crate::persistence::rename_async(
                    crate::persistence::SurfaceWrite::Overlay,
                    from,
                    to,
                )
                .await
            }
        }
    }

    fn open_lock(self, path: &Path) -> std::io::Result<std::fs::File> {
        match self {
            Self::Local => {
                // surface-write: local-log:LOCK
                crate::persistence::open_lock_file(
                    crate::persistence::SurfaceWrite::LocalLogLock,
                    path,
                )
            }
            Self::Overlay => {
                // surface-write: overlay:LOCK
                crate::persistence::open_lock_file(crate::persistence::SurfaceWrite::Overlay, path)
            }
        }
    }
}

impl WriteGuard {
    /// Explicit release, so the lock's lifetime is visible at the call site
    /// rather than resting on where a binding happens to drop.
    fn release(self) {
        // `Drop` does the work; this exists to make the intent legible.
    }
}

impl Drop for WriteGuard {
    fn drop(&mut self) {
        // Best-effort: closing the descriptor releases the lock regardless,
        // so a failure here cannot strand it.
        let _ = fs4::FileExt::unlock(&self.file);
    }
}

/// Read every intact block, stopping at the first damaged one rather than
/// discarding the whole file.
///
/// A CAR is an append-only sequence of self-describing blocks, so a torn
/// write can only ever damage the *last* one — everything before it is
/// complete and verifiable. `stream_to_storage` treats any parse failure as
/// a failure of the whole read, which meant one truncated byte made every
/// claim in the file unreachable while all of them sat intact on disk
/// (`.design/v0.7-milestone.md` REQ-4).
///
/// Returns the blocks that were recovered and whether anything was dropped.
///
/// A parse failure mid-stream stops the walk: everything before the damage
/// is kept, and everything after it — if anything — is unreachable until a
/// repair. The caller's messages must not promise the tail was empty; a
/// flipped byte mid-file lands here exactly like a torn final block
/// (review/full-pass-v0.12 F2).
async fn read_blocks_tolerantly(
    bytes: &[u8],
    path: &std::path::Path,
) -> Result<(MemoryStorage, bool), Error> {
    let mut storage = MemoryStorage::new();
    let mut reader = match CarReader::new(std::io::Cursor::new(bytes)).await {
        Ok(reader) => reader,
        Err(_) => {
            return Err(Error::UnreadableCar {
                path: path.display().to_string(),
            })
        }
    };
    loop {
        match reader.next_block().await {
            Ok(Some(block)) => {
                storage.put(&block.cid, block.data).await?;
            }
            Ok(None) => return Ok((storage, false)),
            // The tail is damaged. Keep everything already read.
            Err(_) => return Ok((storage, true)),
        }
    }
}

/// The newest commit in `storage` whose MST is fully walkable.
///
/// "Newest" is by commit `rev`, a TID and therefore lexicographically
/// sortable. Walkability is checked by actually enumerating the tree rather
/// than by confirming the root block exists: a torn append can leave a commit
/// whose root node is present but whose children are not, and a root that
/// cannot be enumerated is no use as a recovery point. Walking back to the
/// previous commit is always safe, because the MST is persistent — earlier
/// commits share the nodes they had, and those were durable before this one
/// was written.
async fn recover_root(storage: &MemoryStorage) -> Option<Cid> {
    let mut candidates: Vec<(String, Cid)> = Vec::new();
    for raw in storage.cids().collect::<Vec<_>>() {
        let cid = Cid::from(raw);
        let Ok(Some(block)) = storage.get(&cid).await else {
            continue;
        };
        if let Ok(commit) = Commit::from_bytes(&block) {
            candidates.push((commit.rev.clone(), cid));
        }
    }
    // Newest first, so the first walkable candidate is the best one.
    candidates.sort_by(|a, b| b.0.cmp(&a.0));

    for (_rev, cid) in candidates {
        if is_walkable(storage, &cid).await {
            return Some(cid);
        }
    }
    None
}

/// Whether `root` names a commit whose entire MST can be enumerated from
/// `storage`.
///
/// Checked by actually walking the tree rather than by confirming the root
/// block is present: a torn append can leave a commit durable while nodes it
/// points at are missing, and a root that cannot be enumerated is no use
/// either as `HEAD` or as a recovery point. Walking back to an earlier commit
/// is always safe — the MST is persistent, so earlier commits share nodes
/// that were durable before the damaged one was written.
async fn is_walkable(storage: &MemoryStorage, root: &Cid) -> bool {
    let Ok(Some(block)) = storage.get(root).await else {
        return false;
    };
    let Ok(commit) = Commit::from_bytes(&block) else {
        return false;
    };
    // `Mst::from_root` needs owned storage and `MemoryStorage` is not
    // `Clone`, so copy the blocks per attempt. This is a cold path — it runs
    // on open, but only the copy branch is reached when something is already
    // wrong — and usually tries one or two candidates.
    let Ok(copy) = copy_storage(storage).await else {
        return false;
    };
    let mst = Mst::from_root(RawCid::from(commit.data), copy, MstConfig::default());
    mst.entries().await.is_ok()
}

async fn copy_storage(src: &MemoryStorage) -> Result<MemoryStorage, Error> {
    let mut out = MemoryStorage::new();
    for raw in src.cids().collect::<Vec<_>>() {
        let cid = Cid::from(raw);
        if let Some(block) = src.get(&cid).await? {
            out.put(&cid, block).await?;
        }
    }
    Ok(out)
}

/// Wall-clock microseconds since the Unix epoch.
fn now_micros() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_micros() as u64
}

impl Log {
    /// The DID a commit this log writes is stamped with, or [`Error::ReadOnly`]
    /// if this log was opened without a signing identity.
    fn writing_did(&self) -> Result<String, Error> {
        self.did.clone().ok_or(Error::ReadOnly)
    }

    /// Open an existing log **without creating anything and without a signing
    /// identity** — the read path (`.design/identity-surface.md` REQ-2).
    ///
    /// A directory that does not exist yields an empty log rather than an
    /// error, and creates no directory. That is AC-3: `kan status` in a git
    /// repo with no `.kan/` reports no subjects and leaves the repo exactly
    /// as it found it. A read that vivifies a workspace is the defect (#149);
    /// "read it if it is there" is the whole behaviour.
    pub async fn open_read_only(dir: &Path) -> Result<Self, Error> {
        Self::open_read_only_on(dir, LogSurface::Local).await
    }

    pub(crate) async fn open_overlay_read_only(dir: &Path) -> Result<Self, Error> {
        Self::open_read_only_on(dir, LogSurface::Overlay).await
    }

    async fn open_read_only_on(dir: &Path, surface: LogSurface) -> Result<Self, Error> {
        if !dir.join("repo.car").exists() {
            return Ok(Self::empty(dir, None, surface));
        }
        Self::open_inner(dir, None, surface).await
    }

    /// The in-memory shape of a log with nothing in it, for a directory that
    /// may not exist. Touches no disk.
    fn empty(dir: &Path, did: Option<String>, surface: LogSurface) -> Self {
        Self {
            car_path: dir.join("repo.car"),
            head_path: dir.join("HEAD"),
            mst: Mst::new(MemoryStorage::new(), MstConfig::default()),
            commit_cid: None,
            persisted: HashSet::new(),
            lock_path: dir.join("LOCK"),
            surface,
            did,
            tid: TidGenerator::new(),
            last_recorded_at: 0,
            needs_repair: false,
            head_stale: false,
        }
    }

    pub async fn open_or_create(dir: &Path, identity: &Identity) -> Result<Self, Error> {
        Self::open_or_create_on(dir, identity, LogSurface::Local).await
    }

    /// Open a local ATProto repository with an explicit transport signer. An
    /// existing repository is never silently rebound to another transport
    /// DID, regardless of who authors the kan records inside it.
    pub async fn open_or_create_transport(
        dir: &Path,
        signer: &RepositoryTransportSigner<'_>,
    ) -> Result<Self, Error> {
        LogSurface::Local.create_dir(dir).await?;
        let mut log = Self::open_inner(dir, Some(signer.did()), LogSurface::Local).await?;
        log.require_repository_did(signer, None).await?;
        log.migrate_claim_collection(signer).await?;
        Ok(log)
    }

    pub(crate) async fn open_or_create_overlay(
        dir: &Path,
        identity: &Identity,
    ) -> Result<Self, Error> {
        Self::open_or_create_on(dir, identity, LogSurface::Overlay).await
    }

    async fn open_or_create_on(
        dir: &Path,
        identity: &Identity,
        surface: LogSurface,
    ) -> Result<Self, Error> {
        surface.create_dir(dir).await?;
        let mut log = Self::open_inner(dir, Some(identity.did()), surface).await?;
        let signer = RepositoryTransportSigner::LocalDidKey(identity);
        log.migrate_claim_collection(&signer).await?;
        Ok(log)
    }

    async fn require_repository_did(
        &self,
        signer: &RepositoryTransportSigner<'_>,
        trusted_ancestor: Option<&Cid>,
    ) -> Result<(), Error> {
        let expected = signer.did();
        let Some(mut cursor) = self.commit_cid.clone() else {
            return match trusted_ancestor {
                Some(ancestor) => Err(Error::RepositoryHistoryDiverged(ancestor.to_string())),
                None => Ok(()),
            };
        };
        let mut seen = HashSet::new();
        loop {
            if trusted_ancestor == Some(&cursor) {
                return Ok(());
            }
            if !seen.insert(cursor.clone()) {
                return Err(Error::RepositoryCommitCycle(cursor.to_string()));
            }
            let bytes = self
                .mst
                .storage()
                .get(&cursor)
                .await?
                .ok_or(Error::MissingRoot)?;
            let commit = Commit::from_bytes(&bytes)?;
            if commit.did != expected {
                return Err(Error::RepositoryDidMismatch {
                    expected,
                    actual: commit.did,
                });
            }
            if !signer.verify(&commit)? {
                return Err(Error::BadRepositorySignature(cursor.to_string()));
            }
            let Some(previous) = commit.prev else {
                return match trusted_ancestor {
                    Some(ancestor) => Err(Error::RepositoryHistoryDiverged(ancestor.to_string())),
                    None => Ok(()),
                };
            };
            cursor = previous;
        }
    }

    async fn open_inner(
        dir: &Path,
        did: Option<String>,
        surface: LogSurface,
    ) -> Result<Self, Error> {
        let car_path = dir.join("repo.car");
        let head_path = dir.join("HEAD");
        let lock_path = dir.join("LOCK");

        if car_path.exists() {
            let bytes = fs::read(&car_path).await?;
            let (mut storage, mut truncated) = read_blocks_tolerantly(&bytes, &car_path).await?;

            let read_head = |p: &std::path::Path| {
                let p = p.to_path_buf();
                async move {
                    fs::read_to_string(&p)
                        .await
                        .ok()
                        .and_then(|h| h.trim().parse::<Cid>().ok())
                }
            };
            let mut stated = read_head(&head_path).await;

            // Walkability, not mere presence. A crash mid-append can leave
            // the commit block durable while nodes it points at are still
            // missing, so "the root block exists" is not enough to call
            // `HEAD` usable — the tree under it has to actually enumerate.
            let mut usable = match &stated {
                Some(cid) if is_walkable(&storage, cid).await => Some(cid.clone()),
                _ => None,
            };

            // Re-read before concluding damage.
            //
            // The CAR is read first and `HEAD` second, and neither read takes
            // the write lock, so a concurrent append landing between them
            // leaves this process holding an old CAR and a new `HEAD` — a
            // torn view of a perfectly healthy log. Concluding "damaged" from
            // that and recovering an older root would roll the log back and
            // strand every claim written since. Re-reading both closes the
            // window in the overwhelmingly common case; the recovery path
            // below is then reserved for a log that is still inconsistent on
            // a second look.
            if usable.is_none() && stated.is_some() {
                let bytes = fs::read(&car_path).await?;
                let (fresh_storage, fresh_truncated) =
                    read_blocks_tolerantly(&bytes, &car_path).await?;
                let fresh_head = read_head(&head_path).await;
                if let Some(cid) = &fresh_head {
                    if is_walkable(&fresh_storage, cid).await {
                        usable = Some(cid.clone());
                        storage = fresh_storage;
                        truncated = fresh_truncated;
                        stated = fresh_head;
                    }
                }
            }

            if truncated {
                eprintln!(
                    "warning: {} contains a damaged block (an interrupted append, or corruption \
                     by something outside kan) -- every intact block before it was recovered. \
                     Blocks after the damage, if any, are unreadable until the next write \
                     repairs the file; the repair keeps the pre-repair file beside the log.",
                    car_path.display()
                );
            }
            let persisted: HashSet<Cid> = storage.cids().map(Cid::from).collect();

            // `HEAD` names the current root. If it is missing, unparseable,
            // or points at a block this CAR does not contain, the claims are
            // still all here — the pointer to them is what was lost. Rebuild
            // it from the newest commit in the CAR that is actually whole
            // (`.design/v0.7-milestone.md` REQ-4).
            //
            // **Nothing is written here.** This runs on every open, including
            // `kan show`, and a read command must not modify the log — the
            // previous version rewrote `HEAD` with a plain `fs::write`, off
            // the lock and non-atomically, which turned a transient torn read
            // into a permanent rollback. The recovered root is held in memory
            // and persisted by the next append, under the lock.
            let mut head_stale = false;
            let root = match usable {
                Some(root) => root,
                None => {
                    let recovered = recover_root(&storage).await.ok_or(Error::MissingHead)?;
                    // "No claim was lost" is only true when the CAR read
                    // clean: a tolerant read that dropped blocks may have
                    // dropped claims recorded after the damage, and saying
                    // otherwise taught an operator to discard exactly the
                    // file that still held them (review/full-pass-v0.12 F2).
                    eprintln!(
                        "warning: HEAD was {} -- reading from the newest intact commit ({}) in \
                         {}. {}HEAD will be rewritten on the next write.",
                        if stated.is_some() {
                            "pointing at a block this log does not contain"
                        } else {
                            "missing or unreadable"
                        },
                        recovered,
                        car_path.display(),
                        if truncated {
                            "Claims recorded after the damaged block, if any, are not reachable \
                             from this commit. "
                        } else {
                            "No claim was lost; the pointer to them was. "
                        }
                    );
                    head_stale = true;
                    recovered
                }
            };

            let commit_bytes = storage.get(&root).await?.ok_or(Error::MissingRoot)?;
            let commit = Commit::from_bytes(&commit_bytes)?;
            let mst = Mst::from_root(RawCid::from(commit.data), storage, MstConfig::default());

            // Seed from the reopened log's last commit rev, not a fresh
            // zero baseline -- kan's real usage is a fresh process per
            // command, so strict monotonicity has to hold across process
            // restarts, not just within one generator's lifetime.
            let tid = TidGenerator::seeded(&commit.rev);

            Ok(Self {
                car_path,
                head_path,
                mst,
                commit_cid: Some(root),
                persisted,
                lock_path,
                surface,
                did,
                // Floor the recording clock at the last durable append's
                // wall-clock time, so a fresh process cannot mint a
                // recorded_at at or below one already persisted.
                last_recorded_at: tid.last_micros(),
                tid,
                needs_repair: truncated,
                head_stale,
            })
        } else {
            let mst = Mst::new(MemoryStorage::new(), MstConfig::default());
            Ok(Self {
                car_path,
                head_path,
                mst,
                commit_cid: None,
                persisted: HashSet::new(),
                lock_path,
                surface,
                did,
                tid: TidGenerator::new(),
                last_recorded_at: 0,
                needs_repair: false,
                head_stale: false,
            })
        }
    }

    /// Rewrite the CAR from the blocks that survived a tolerant read,
    /// discarding the damaged tail.
    ///
    /// Whole-file rather than a computed truncation offset: the offset would
    /// have to be derived from re-serializing every block and the header, and
    /// getting it wrong by one byte reintroduces exactly the defect this
    /// exists to remove. This only ever runs on an already-damaged log, so
    /// the cost is irrelevant next to being certain.
    ///
    /// Written to a temp file and renamed, so an interruption mid-repair
    /// leaves the original damaged file rather than a half-written one —
    /// damaged-but-recoverable beats truncated-at-an-unknown-point.
    async fn rewrite_car(&mut self) -> Result<(), Error> {
        let Some(root) = self.commit_cid.clone() else {
            return Ok(());
        };

        // Keep the pre-repair file. The tolerant read stops at the first
        // damaged block, so if the damage was mid-file rather than a torn
        // tail, every intact block *after* it exists only in this copy —
        // rewriting from the recovered set alone made that loss permanent
        // while the recovery message said nothing was lost
        // (review/full-pass-v0.12 F2). A repair that cannot preserve the
        // original does not run: the copy failing (full disk, permissions)
        // means the one file holding the unrecovered blocks would be
        // destroyed by the very step meant to help.
        let damaged = {
            let mut name = self.car_path.file_name().unwrap_or_default().to_os_string();
            name.push(format!(".damaged-{}", now_micros()));
            self.car_path.with_file_name(name)
        };
        self.surface.copy_damaged(&self.car_path, &damaged).await?;
        eprintln!(
            "warning: repairing {} -- the pre-repair file is kept at {}. If the damage \
             was mid-file rather than at the tail, blocks after it exist only in that \
             copy.",
            self.car_path.display(),
            damaged.display()
        );

        let tmp = self.car_path.with_extension("repair");
        let mut out = self.surface.create_repair(&tmp).await?;
        out.write_all(&CarHeader::with_root(root).to_bytes()?)
            .await?;

        // Sorted so the rewrite is deterministic; CAR block order carries no
        // meaning, and determinism makes a repaired file comparable.
        let mut cids: Vec<Cid> = self.mst.storage().cids().map(Cid::from).collect();
        cids.sort_by_key(|c| c.to_string());
        let mut written = HashSet::new();
        for cid in cids {
            if let Some(data) = self.mst.storage().get(&cid).await? {
                let block = CarBlock::new(RawCid::from(cid.clone()), data);
                out.write_all(&block.to_bytes()?).await?;
                written.insert(cid);
            }
        }
        out.sync_all().await?;
        drop(out);
        self.surface.rename_car(&tmp, &self.car_path).await?;
        self.persisted = written;
        Ok(())
    }

    /// Append every block in `mst.storage()` not already in `persisted` to
    /// the end of the CAR file (writing the header first if this is the
    /// file's first-ever write), then update `HEAD`.
    async fn persist_new_blocks(&mut self, root: &Cid) -> Result<(), Error> {
        let file_is_new = !self.car_path.exists();
        let mut file = self.surface.open_append(&self.car_path).await?;

        if file_is_new {
            let header = CarHeader::with_root(root.clone());
            file.write_all(&header.to_bytes()?).await?;
        }

        let new_cids: Vec<Cid> = self
            .mst
            .storage()
            .cids()
            .map(Cid::from)
            .filter(|c| !self.persisted.contains(c))
            .collect();
        for cid in new_cids {
            let data = self
                .mst
                .storage()
                .get(&cid)
                .await?
                .expect("cid came from this storage's own cids() iterator");
            let block = CarBlock::new(RawCid::from(cid.clone()), data);
            file.write_all(&block.to_bytes()?).await?;
            self.persisted.insert(cid);
        }

        // `flush()` only pushes tokio's userspace buffer at the kernel; it
        // makes no promise the bytes survive a crash. `sync_all` does, and
        // the *ordering* is the point: every block must be durable before
        // the root that points at them, or a crash in the window leaves a
        // HEAD referencing blocks that were never written — `MissingRoot` on
        // the next open, with a log that looks corrupt and is not
        // (`.design/v0.7-milestone.md` REQ-4).
        file.sync_all().await?;

        self.write_head_atomically(root).await
    }

    /// Replace `HEAD` atomically: write a temp file beside it, fsync that,
    /// then `rename` over the target.
    ///
    /// A plain `fs::write` truncates first and then writes, so a crash — or
    /// a full disk — between the two leaves a zero-length or half-written
    /// `HEAD`, which `open_or_create` reports as `MissingHead` and which
    /// bricks reads *and* writes while every claim sits intact in the CAR.
    /// `rename` within a directory is atomic on POSIX: readers see either
    /// the old root or the new one, never a partial one.
    ///
    /// The directory fsync at the end is what makes the rename itself
    /// durable — without it the file contents are on disk but the directory
    /// entry pointing at them need not be.
    async fn write_head_atomically(&self, root: &Cid) -> Result<(), Error> {
        let tmp_path = self.head_path.with_extension("tmp");
        let mut tmp = self.surface.create_head_temp(&tmp_path).await?;
        tmp.write_all(root.to_string().as_bytes()).await?;
        tmp.sync_all().await?;
        drop(tmp);

        self.surface.rename_head(&tmp_path, &self.head_path).await?;

        if let Some(dir) = self.head_path.parent() {
            // Best-effort: a filesystem that refuses to open a directory for
            // fsync (rare, but not worth failing an otherwise-good append
            // over) leaves the rename durable-on-next-sync rather than
            // immediately.
            if let Ok(dir_handle) = fs::File::open(dir).await {
                let _ = dir_handle.sync_all().await;
            }
        }
        Ok(())
    }

    /// Block until this process holds the log's exclusive write lock.
    ///
    /// A dedicated `LOCK` file rather than locking the CAR itself: the CAR is
    /// opened for reading by every command, and locking a file you also read
    /// invites a reader accidentally taking or blocking on a writer's lock.
    /// A file whose only purpose is the lock has no such ambiguity, and its
    /// contents are never read.
    ///
    /// Readers deliberately do **not** take this lock, and this is a real
    /// trade rather than a free one. A reader loads the CAR and then `HEAD`
    /// as two separate reads, so an append landing between them leaves it
    /// holding an old CAR with a new `HEAD` — a genuinely torn view. (An
    /// earlier version of this comment claimed readers "never see a torn
    /// state"; that was false, and an adversarial review said so.)
    ///
    /// What makes it survivable is that a reader can no longer *act* on the
    /// torn view: it re-reads both before concluding damage, and it never
    /// writes `HEAD` — a recovered root is held in memory and persisted by
    /// the next append under this lock. The remaining cost of a torn read is
    /// a stale view for one command, which is the same cost as running the
    /// command a moment earlier.
    async fn lock_for_write(&self) -> Result<WriteGuard, Error> {
        let lock_path = self.lock_path.clone();
        let surface = self.surface;
        // `fs4`'s blocking `lock()` on a `std::fs::File`, moved off the async
        // runtime: it parks the calling thread until the lock is available,
        // which would stall other tasks on a shared worker thread.
        let file = tokio::task::spawn_blocking(move || -> std::io::Result<std::fs::File> {
            let file = surface.open_lock(&lock_path)?;
            fs4::FileExt::lock(&file)?;
            Ok(file)
        })
        .await
        .expect("lock task panicked")?;
        Ok(WriteGuard { file })
    }

    /// Rebuild in-memory state from disk if another process has moved `HEAD`
    /// since this `Log` was opened. A no-op in the overwhelmingly common
    /// single-writer case — one `read_to_string` of a CID-sized file.
    async fn reload_if_stale(&mut self) -> Result<(), Error> {
        // A recovered root is out of step with what is on disk by
        // construction — but the recovery ran *before* this process held the
        // lock, so "the damage is real" and "another writer moved HEAD while
        // we were recovering" are indistinguishable until now. An early
        // return here rolled back every writer that landed between open and
        // append: six concurrent first-appends to a fresh workspace all
        // exited 0 and two subjects survived, the losers' blocks reachable
        // from no root (review/full-pass-v0.12 F1). Prefer the on-disk root
        // whenever it is walkable in a fresh read; the recovered root is
        // only for a log that is still broken while the lock is held.
        if self.head_stale {
            let on_disk = match fs::read_to_string(&self.head_path).await {
                Ok(head) => head.trim().parse::<Cid>().ok(),
                Err(_) => None,
            };
            if let Some(root) = on_disk {
                let bytes = fs::read(&self.car_path).await?;
                let (storage, truncated) = read_blocks_tolerantly(&bytes, &self.car_path).await?;
                if is_walkable(&storage, &root).await {
                    // `=`, not `|=`: this branch replaces the entire in-memory
                    // state from a fresh under-lock read, so the repair flag
                    // must reflect THAT read, not the damage the pre-lock open
                    // saw. Keeping the open-time flag set made a second
                    // recovering opener run `rewrite_car` on a file the first
                    // one already repaired — a spurious `repo.car.damaged-*`
                    // copy plus a "blocks exist only in that copy" warning
                    // that was false for it (cold review of the F1/F2 branch).
                    self.needs_repair = truncated;
                    self.persisted = storage.cids().map(Cid::from).collect();
                    let commit_bytes = storage.get(&root).await?.ok_or(Error::MissingRoot)?;
                    let commit = Commit::from_bytes(&commit_bytes)?;
                    self.mst =
                        Mst::from_root(RawCid::from(commit.data), storage, MstConfig::default());
                    self.commit_cid = Some(root);
                    self.tid = TidGenerator::seeded(&commit.rev);
                    self.last_recorded_at = self.last_recorded_at.max(self.tid.last_micros());
                    self.head_stale = false;
                }
            }
            return Ok(());
        }
        let on_disk = match fs::read_to_string(&self.head_path).await {
            Ok(head) => head.trim().parse::<Cid>().ok(),
            // No HEAD yet: nothing to be stale relative to.
            Err(_) => return Ok(()),
        };
        if on_disk.is_none() || on_disk == self.commit_cid {
            return Ok(());
        }

        // Tolerant, like `open_or_create`: an intolerant read here would
        // fail the whole append on a damaged tail that the open path had
        // already recovered from.
        let bytes = fs::read(&self.car_path).await?;
        let (storage, truncated) = read_blocks_tolerantly(&bytes, &self.car_path).await?;
        self.needs_repair |= truncated;
        self.persisted = storage.cids().map(Cid::from).collect();

        let root = on_disk.expect("checked above");
        let commit_bytes = storage.get(&root).await?.ok_or(Error::MissingRoot)?;
        let commit = Commit::from_bytes(&commit_bytes)?;
        self.mst = Mst::from_root(RawCid::from(commit.data), storage, MstConfig::default());
        self.commit_cid = Some(root);
        // Keep TID monotonicity across the takeover, exactly as reopening
        // would have.
        self.tid = TidGenerator::seeded(&commit.rev);
        self.last_recorded_at = self.last_recorded_at.max(self.tid.last_micros());
        Ok(())
    }

    /// Sign and append a claim, keyed by its own `content_cid` under the
    /// `tools.kan.claim` collection. Returns that CID — the claim's citable
    /// identity (`docs/SPEC.md` §1, no explicit id field).
    pub async fn append(
        &mut self,
        content: ClaimContent,
        identity: &Identity,
    ) -> Result<Cid, Error> {
        // Serialize the whole read-modify-write against every other process
        // holding this log open (`.design/v0.7-milestone.md` REQ-3).
        //
        // Without this, each process opened the CAR into an in-memory MST,
        // appended to *its* copy, and last-writer-wins overwrote HEAD: five
        // concurrent `kan observe` calls returned five distinct CIDs and five
        // exit-0 successes while two claims survived, the losers' blocks
        // reaching the CAR but unreachable from the winning root. ADR-15's
        // "reopens from disk every call ... avoids any question of
        // concurrent-mutation safety" was exactly inverted: reopening per
        // call is *what makes* each process start from a stale root. This is
        // the deployment kan targets — one human, one-or-more local agents,
        // plus `day` shelling out to the same binary (ADR-42).
        let guard = self.lock_for_write().await?;
        let result = self.append_locked(content, identity).await;
        guard.release();
        result
    }

    /// Append one already-verified current claim. The activation token is
    /// proof that the stored scope inception was cryptographically verified;
    /// an installed but unverified scope cannot select this writer.
    pub async fn append_current(
        &mut self,
        claim: crate::claim::Claim,
        scope: &crate::identity::scope_store::VerifiedScope,
        signer: &RepositoryTransportSigner<'_>,
    ) -> Result<Cid, Error> {
        let guard = self.lock_for_write().await?;
        let result = self.append_current_locked(claim, scope, signer).await;
        guard.release();
        result
    }

    async fn append_current_locked(
        &mut self,
        claim: crate::claim::Claim,
        scope: &crate::identity::scope_store::VerifiedScope,
        signer: &RepositoryTransportSigner<'_>,
    ) -> Result<Cid, Error> {
        let trusted_root = self.commit_cid.clone();
        self.reload_if_stale().await?;
        let selected_did = signer.did();
        let configured_did = self.writing_did()?;
        if configured_did != selected_did {
            return Err(Error::RepositoryDidMismatch {
                expected: selected_did,
                actual: configured_did,
            });
        }
        self.require_repository_did(signer, trusted_root.as_ref())
            .await?;
        if self.needs_repair {
            self.rewrite_car().await?;
            self.needs_repair = false;
        }
        if self.head_stale {
            if let Some(root) = self.commit_cid.clone() {
                self.write_head_atomically(&root).await?;
            }
            self.head_stale = false;
        }

        let claim_scope = claim.content().scope();
        if claim_scope != scope.scope() {
            return Err(Error::ClaimScopeMismatch {
                claim: claim_scope,
                activated: scope.scope(),
            });
        }
        let claim_id = claim.id()?;
        let claim_cid = claim_id.cid().clone();
        let key = RecordPath::new(COLLECTION, claim_cid.to_string()).to_mst_key();
        if self.mst.get(&key).await?.is_some() {
            return Err(Error::ClaimAlreadyExists(claim_cid.to_string()));
        }

        self.last_recorded_at = self
            .last_recorded_at
            .max(claim.content().recorded_at().micros());
        let rev = self.tid.next();
        let record_bytes = crate::claim::codec::encode_claim(&claim, &rev)?;
        let record_cid = Cid::from(compute_cid(&record_bytes));
        self.mst
            .storage_mut()
            .put(&record_cid, record_bytes)
            .await?;
        self.mst.insert(&key, record_cid).await?;

        let unsigned = Commit::new_unsigned(
            self.writing_did()?,
            Cid::from(mst_root(&self.mst)?),
            self.tid.next(),
            self.commit_cid.clone(),
        );
        let commit_sig = signer.sign(&unsigned.to_bytes()?)?;
        let commit = unsigned.sign(commit_sig);
        let new_commit_cid = write_commit(&mut self.mst, &commit).await?;
        self.commit_cid = Some(new_commit_cid.clone());
        self.persist_new_blocks(&new_commit_cid).await?;
        Ok(claim_cid)
    }

    /// Move legacy `dev.kan.claim` entries into the typed current collection.
    ///
    /// Validation is completed before the in-memory tree changes. The new
    /// commit removes legacy keys from the live MST but the append-only CAR
    /// retains every historical block and commit that contained them.
    async fn migrate_claim_collection(
        &mut self,
        signer: &RepositoryTransportSigner<'_>,
    ) -> Result<(), Error> {
        let legacy = self.mst.list_collection(LEGACY_COLLECTION).await?;
        if legacy.is_empty() {
            return Ok(());
        }

        let guard = self.lock_for_write().await?;
        let result = self.migrate_claim_collection_locked(signer).await;
        guard.release();
        result
    }

    async fn migrate_claim_collection_locked(
        &mut self,
        signer: &RepositoryTransportSigner<'_>,
    ) -> Result<(), Error> {
        self.reload_if_stale().await?;
        let legacy = self.mst.list_collection(LEGACY_COLLECTION).await?;
        if legacy.is_empty() {
            return Ok(());
        }

        let mut converted = Vec::with_capacity(legacy.len());
        for (legacy_key, record_cid) in &legacy {
            let path = RecordPath::from_mst_key(legacy_key)?;
            let claim_cid: Cid = path.rkey.parse().map_err(Error::InvalidCid)?;
            let bytes = self.mst.storage().get(record_cid).await?.ok_or_else(|| {
                Error::MissingClaimRecord {
                    collection: LEGACY_COLLECTION,
                    key: path.rkey.clone(),
                    record_cid: record_cid.to_string(),
                }
            })?;
            let stored: StoredClaim = atproto_dasl::from_slice(&bytes).map_err(|e| {
                Error::Car(atproto_dasl::errors::CarError::Io(std::io::Error::other(e)))
            })?;
            let record =
                crate::at_claim::Record::from_claim(stored.claim.clone(), stored.rev.clone())?;
            if record.claim_cid != claim_cid.to_string() || record.clone().verify()? != stored.claim
            {
                return Err(Error::BadSignature);
            }

            let current_key = RecordPath::new(COLLECTION, path.rkey.clone()).to_mst_key();
            if let Some(current_record_cid) = self.mst.get(&current_key).await? {
                let current_bytes = self
                    .mst
                    .storage()
                    .get(&current_record_cid)
                    .await?
                    .ok_or_else(|| Error::MissingClaimRecord {
                        collection: COLLECTION,
                        key: path.rkey.clone(),
                        record_cid: current_record_cid.to_string(),
                    })?;
                let current: crate::at_claim::Record = atproto_dasl::from_slice(&current_bytes)
                    .map_err(|e| {
                        Error::Car(atproto_dasl::errors::CarError::Io(std::io::Error::other(e)))
                    })?;
                let current_stored = StoredClaim {
                    claim: current.clone().verify()?,
                    rev: current.rev,
                };
                if current_stored != stored {
                    return Err(Error::ClaimMigrationConflict(path.rkey));
                }
            } else {
                let current_bytes = atproto_dasl::to_vec(&record).map_err(|e| {
                    Error::Car(atproto_dasl::errors::CarError::Io(std::io::Error::other(e)))
                })?;
                converted.push((current_key, current_bytes));
            }
        }

        let mut final_entries: Vec<(String, Cid)> = self
            .mst
            .entries()
            .await?
            .into_iter()
            .filter(|(key, _)| !key.starts_with(&format!("{LEGACY_COLLECTION}/")))
            .collect();
        for (key, bytes) in converted {
            let record_cid = Cid::from(compute_cid(&bytes));
            self.mst.storage_mut().put(&record_cid, bytes).await?;
            final_entries.push((key, record_cid));
        }
        self.mst.replace_entries(final_entries).await?;

        let unsigned = Commit::new_unsigned(
            self.writing_did()?,
            Cid::from(mst_root(&self.mst)?),
            self.tid.next(),
            self.commit_cid.clone(),
        );
        let commit_sig = signer.sign(&unsigned.to_bytes()?)?;
        let commit = unsigned.sign(commit_sig);
        let new_commit_cid = write_commit(&mut self.mst, &commit).await?;
        self.commit_cid = Some(new_commit_cid.clone());
        self.persist_new_blocks(&new_commit_cid).await?;
        Ok(())
    }

    /// The append itself, with the write lock already held. Split out so the
    /// lock is released on every path, including the error ones.
    async fn append_locked(
        &mut self,
        mut content: ClaimContent,
        identity: &Identity,
    ) -> Result<Cid, Error> {
        // The lock excludes concurrent writers from here on, but this
        // process may have read the log *before* acquiring it — so whatever
        // is in memory can already be behind. Re-read HEAD and rebuild from
        // disk if another writer moved it. Taking the lock without this
        // check would serialize the writes and still lose them.
        self.reload_if_stale().await?;

        // Repair a damaged tail before writing past it (see `needs_repair`).
        if self.needs_repair {
            self.rewrite_car().await?;
            self.needs_repair = false;
        }
        if self.head_stale {
            if let Some(root) = self.commit_cid.clone() {
                self.write_head_atomically(&root).await?;
            }
            self.head_stale = false;
        }

        // Stamp the observer-frame recording time before the CID is computed
        // — it is signed content, not storage metadata
        // (`ClaimContent::recorded_at`). `get_or_insert` rather than an
        // unconditional set so a caller that already holds an authored claim
        // (a future ingest path for claims arriving from another actor,
        // v0.8) cannot have its author's attested time silently rewritten,
        // which would change the CID and break the signature. Every
        // authoring caller today passes `None`.
        let stamped = now_micros().max(self.last_recorded_at.saturating_add(1));
        let recorded_at = *content.recorded_at.get_or_insert(stamped);
        self.last_recorded_at = self.last_recorded_at.max(recorded_at);

        let claim_cid = content_cid(&content)?;
        let claim_sig = identity.sign(&claim_cid.to_bytes())?;
        let claim = Claim {
            content,
            sig: claim_sig,
        };
        let stored = StoredClaim {
            claim,
            rev: self.tid.next(),
        };

        let record = crate::at_claim::Record::from_claim(stored.claim.clone(), stored.rev.clone())?;
        let record_bytes = atproto_dasl::to_vec(&record).map_err(|e| {
            Error::Car(atproto_dasl::errors::CarError::Io(std::io::Error::other(e)))
        })?;
        let record_cid = Cid::from(compute_cid(&record_bytes));
        self.mst
            .storage_mut()
            .put(&record_cid, record_bytes)
            .await?;

        let key = RecordPath::new(COLLECTION, claim_cid.to_string()).to_mst_key();
        self.mst.insert(&key, record_cid).await?;

        let unsigned = Commit::new_unsigned(
            self.writing_did()?,
            Cid::from(mst_root(&self.mst)?),
            self.tid.next(),
            self.commit_cid.clone(),
        );
        let commit_sig = identity.sign(&unsigned.to_bytes()?)?;
        let commit = unsigned.sign(commit_sig);
        let new_commit_cid = write_commit(&mut self.mst, &commit).await?;
        self.commit_cid = Some(new_commit_cid.clone());

        self.persist_new_blocks(&new_commit_cid).await?;
        Ok(claim_cid)
    }

    /// Whether this log already holds a claim with this content CID.
    ///
    /// Lock-free on purpose: it reads the in-memory MST this `Log` opened
    /// with. `ingest` re-checks under the lock, so this is a cheap filter
    /// that lets the common "nothing new to ingest" path avoid taking a
    /// write lock at all, not a substitute for the authoritative check.
    pub async fn contains(&self, claim_cid: &Cid) -> Result<bool, Error> {
        let key = RecordPath::new(COLLECTION, claim_cid.to_string()).to_mst_key();
        if self.mst.get(&key).await?.is_some() {
            return Ok(true);
        }
        let legacy_key = RecordPath::new(LEGACY_COLLECTION, claim_cid.to_string()).to_mst_key();
        Ok(self.mst.get(&legacy_key).await?.is_some())
    }

    /// Insert a fully-formed `StoredClaim` **verbatim** — same content, same
    /// CID, same signature, no re-signing.
    ///
    /// This is the primitive `append` structurally cannot be. `append_locked`
    /// signs with the *local* identity, so pushing a restored or foreign
    /// claim through it reproduces the content CID and replaces the
    /// signature, which `get_stored`'s own-author verification then rejects.
    /// A round-trip that silently invalidates what it stored is worse than a
    /// missing feature.
    ///
    /// The record's signature is verified against **its own**
    /// `content.author.did` before anything is written, so an unverifiable
    /// record is refused at the door rather than stored and discovered later.
    /// The *commit* is still signed by the local identity: a commit attests
    /// to the repo's state, which this process genuinely is asserting, while
    /// each record keeps its own author's signature. Those are different
    /// claims and conflating them is what made `append` unusable here.
    ///
    /// Returns `Ok(None)` when the record is already present — ingest is
    /// idempotent, because it runs on every read of a published tree and
    /// must not rewrite the log each time.
    ///
    /// Destination is the caller's decision, keyed on the record's signed
    /// author: same author into `log/repo.car` (restore), foreign author
    /// into the overlay (`Workspace::open`). `log/repo.car` stays *claims I
    /// authored*, which is what atproto repo semantics require.
    /// (`.design/durability-log-recovery.md` REQ-1/REQ-4.)
    pub async fn ingest(
        &mut self,
        stored: StoredClaim,
        identity: &Identity,
    ) -> Result<Option<Cid>, Error> {
        let guard = self.lock_for_write().await?;
        let result = self.ingest_locked(stored, identity).await;
        guard.release();
        result
    }

    async fn ingest_locked(
        &mut self,
        stored: StoredClaim,
        identity: &Identity,
    ) -> Result<Option<Cid>, Error> {
        self.reload_if_stale().await?;
        if self.needs_repair {
            self.rewrite_car().await?;
            self.needs_repair = false;
        }

        let claim_cid = content_cid(&stored.claim.content)?;
        if !crate::sign::verify(
            &stored.claim.content.author.did,
            &claim_cid.to_bytes(),
            &stored.claim.sig,
        ) {
            return Err(Error::BadSignature);
        }

        let key = RecordPath::new(COLLECTION, claim_cid.to_string()).to_mst_key();
        if self.mst.get(&key).await?.is_some() {
            return Ok(None);
        }

        // Keep the TID watermark ahead of anything ingested, so a later
        // local append cannot collide with or sort before a record that
        // arrived from elsewhere.
        if let Some(micros) = stored.claim.content.recorded_at {
            self.last_recorded_at = self.last_recorded_at.max(micros);
        }

        let record = crate::at_claim::Record::from_claim(stored.claim.clone(), stored.rev.clone())?;
        let record_bytes = atproto_dasl::to_vec(&record).map_err(|e| {
            Error::Car(atproto_dasl::errors::CarError::Io(std::io::Error::other(e)))
        })?;
        let record_cid = Cid::from(compute_cid(&record_bytes));
        self.mst
            .storage_mut()
            .put(&record_cid, record_bytes)
            .await?;
        self.mst.insert(&key, record_cid).await?;

        let unsigned = Commit::new_unsigned(
            self.writing_did()?,
            Cid::from(mst_root(&self.mst)?),
            self.tid.next(),
            self.commit_cid.clone(),
        );
        let commit_sig = identity.sign(&unsigned.to_bytes()?)?;
        let commit = unsigned.sign(commit_sig);
        let new_commit_cid = write_commit(&mut self.mst, &commit).await?;
        self.commit_cid = Some(new_commit_cid.clone());
        self.persist_new_blocks(&new_commit_cid).await?;
        Ok(Some(claim_cid))
    }

    /// Fetch a claim by its `content_cid`, verifying its signature against
    /// its own author before returning it.
    pub async fn get(&mut self, claim_cid: Cid) -> Result<Option<Claim>, Error> {
        Ok(self.get_stored(claim_cid).await?.map(|s| s.claim))
    }

    /// Fetch any record in the mixed-codec collection. Callers must branch on
    /// supported versus preserved-unsupported content before interpretation.
    pub async fn get_decoded(
        &mut self,
        claim_cid: Cid,
        verification: crate::claim::codec::VerificationContext<'_>,
    ) -> Result<Option<crate::claim::codec::DecodedRecord>, Error> {
        let key = RecordPath::new(COLLECTION, claim_cid.to_string()).to_mst_key();
        if let Some(record_cid) = self.mst.get(&key).await? {
            let Some(bytes) = self.mst.storage().get(&record_cid).await? else {
                return Ok(None);
            };
            let decoded = match crate::claim::codec::decode_record(&bytes, verification) {
                Ok(decoded) => decoded,
                Err(codec_error) if legacy_at_claim_candidate(&bytes) => {
                    let record: crate::at_claim::Record =
                        atproto_dasl::from_slice(&bytes).map_err(|_| codec_error)?;
                    let rev = record.rev.clone();
                    crate::claim::codec::DecodedRecord {
                        claim: crate::claim::codec::DecodedClaim::Supported(
                            crate::claim::codec::SupportedClaim::V1(record.verify()?),
                        ),
                        rev,
                    }
                }
                Err(codec_error) => return Err(codec_error.into()),
            };
            if decoded_claim_id(&decoded.claim)? != claim_cid {
                return Err(Error::BadSignature);
            }
            return Ok(Some(decoded));
        }

        let legacy_key = RecordPath::new(LEGACY_COLLECTION, claim_cid.to_string()).to_mst_key();
        let Some(record_cid) = self.mst.get(&legacy_key).await? else {
            return Ok(None);
        };
        let Some(bytes) = self.mst.storage().get(&record_cid).await? else {
            return Ok(None);
        };
        let stored: StoredClaim = atproto_dasl::from_slice(&bytes).map_err(|error| {
            Error::Car(atproto_dasl::errors::CarError::Io(std::io::Error::other(
                error,
            )))
        })?;
        let actual = content_cid(&stored.claim.content)?;
        if actual != claim_cid
            || !crate::sign::verify(
                &stored.claim.content.author.did,
                &claim_cid.to_bytes(),
                &stored.claim.sig,
            )
        {
            return Err(Error::BadSignature);
        }
        Ok(Some(crate::claim::codec::DecodedRecord {
            claim: crate::claim::codec::DecodedClaim::Supported(
                crate::claim::codec::SupportedClaim::V1(stored.claim),
            ),
            rev: stored.rev,
        }))
    }

    /// Like `get`, but also returns the log-revision TID captured at append
    /// time.
    pub async fn get_stored(&mut self, claim_cid: Cid) -> Result<Option<StoredClaim>, Error> {
        let key = RecordPath::new(COLLECTION, claim_cid.to_string()).to_mst_key();
        let (record_cid, legacy) = if let Some(record_cid) = self.mst.get(&key).await? {
            (record_cid, false)
        } else {
            let legacy_key = RecordPath::new(LEGACY_COLLECTION, claim_cid.to_string()).to_mst_key();
            let Some(record_cid) = self.mst.get(&legacy_key).await? else {
                return Ok(None);
            };
            (record_cid, true)
        };
        let Some(bytes) = self.mst.storage().get(&record_cid).await? else {
            return Ok(None);
        };
        let stored = if legacy {
            atproto_dasl::from_slice(&bytes).map_err(|e| {
                Error::Car(atproto_dasl::errors::CarError::Io(std::io::Error::other(e)))
            })?
        } else if common_envelope(&bytes)? {
            let decoded = crate::claim::codec::decode_record(
                &bytes,
                crate::claim::codec::VerificationContext::StaticDidKey,
            );
            match decoded {
                Ok(crate::claim::codec::DecodedRecord {
                    claim:
                        crate::claim::codec::DecodedClaim::Supported(
                            crate::claim::codec::SupportedClaim::V1(claim),
                        ),
                    rev,
                }) => StoredClaim { claim, rev },
                Ok(_) => return Ok(None),
                Err(error) => return Err(error.into()),
            }
        } else {
            let record: crate::at_claim::Record =
                atproto_dasl::from_slice(&bytes).map_err(|e| {
                    Error::Car(atproto_dasl::errors::CarError::Io(std::io::Error::other(e)))
                })?;
            let rev = record.rev.clone();
            StoredClaim {
                claim: record.verify().map_err(|error| match error {
                    crate::at_claim::Error::BadSignature | crate::at_claim::Error::CidMismatch => {
                        Error::BadSignature
                    }
                    other => Error::AtClaim(other),
                })?,
                rev,
            }
        };

        let recomputed = content_cid(&stored.claim.content)?;
        if recomputed != claim_cid
            || !crate::sign::verify(
                &stored.claim.content.author.did,
                &claim_cid.to_bytes(),
                &stored.claim.sig,
            )
        {
            return Err(Error::BadSignature);
        }
        Ok(Some(stored))
    }

    /// Enumerate supported and preserved-unsupported records without routing
    /// either through the legacy fold type.
    pub async fn iter_decoded(
        &mut self,
        verification: crate::claim::codec::VerificationContext<'_>,
    ) -> Result<Vec<(Cid, crate::claim::codec::DecodedRecord)>, Error> {
        let entries = self.mst.entries().await?;
        self.warn_once_if_claims_are_unreachable(&entries).await?;
        let mut out = Vec::with_capacity(entries.len());
        let mut seen = HashSet::new();
        for (key, _) in entries {
            let path = RecordPath::from_mst_key(&key)?;
            if path.collection != COLLECTION && path.collection != LEGACY_COLLECTION {
                continue;
            }
            let claim_cid: Cid = path.rkey.parse().map_err(Error::InvalidCid)?;
            if !seen.insert(claim_cid.clone()) {
                continue;
            }
            if let Some(record) = self.get_decoded(claim_cid.clone(), verification).await? {
                out.push((claim_cid, record));
            }
        }
        Ok(out)
    }

    /// The log's current root commit CID, if any claim has ever been
    /// appended — already resident in memory from `open_or_create` (which
    /// reads it from the `HEAD` file), so this is free: no additional I/O,
    /// no MST walk, no signature verification. `Workspace::open`
    /// (`.design/v0.4-milestone.md` REQ-5) compares this against the
    /// index's stored `built_from_root` to decide whether `iter_all`'s
    /// per-claim signature verification can be skipped.
    pub fn current_root(&self) -> Option<Cid> {
        self.commit_cid.clone()
    }

    /// Enumerate every claim currently in the log, each with the CID it's
    /// keyed by and its log-revision TID. Order is not guaranteed; sort by
    /// `rev` for chronological order.
    ///
    /// A record that fails signature verification is skipped (with a
    /// warning), not fatal to the whole log — `docs/SPEC.md` §8's "folds
    /// tolerate dangling cites (normal; handled at view layer)" philosophy
    /// applies here too: one bad record shouldn't make every other command
    /// fail. Any other error (storage/IO genuinely broken, not just one
    /// record's content) still propagates — this only tolerates the
    /// specific, legible "this one record doesn't verify" case.
    pub async fn iter_all(&mut self) -> Result<Vec<(Cid, StoredClaim)>, Error> {
        let entries = self.mst.entries().await?;
        self.warn_once_if_claims_are_unreachable(&entries).await?;
        let mut out = Vec::with_capacity(entries.len());
        let mut seen = HashSet::new();
        for (key, _record_cid) in entries {
            let path = RecordPath::from_mst_key(&key)?;
            if path.collection != COLLECTION && path.collection != LEGACY_COLLECTION {
                continue;
            }
            let claim_cid: Cid = path.rkey.parse().map_err(Error::InvalidCid)?;
            if !seen.insert(claim_cid.clone()) {
                continue;
            }
            match self.get_stored(claim_cid.clone()).await {
                Ok(Some(stored)) => out.push((claim_cid, stored)),
                Ok(None) => {}
                Err(Error::BadSignature) => {
                    eprintln!(
                        "warning: claim {claim_cid} failed signature verification and was \
                         excluded from this fold (docs/SPEC.md §8)"
                    );
                }
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    /// Say so, once, if this log holds claims a read cannot reach.
    ///
    /// A write repairs the condition (`Mst::insert` sorts the walk before
    /// rebuilding), but a log that is only ever *read* never triggers that, so
    /// the claim would stay invisible indefinitely. Reads are not blocked and
    /// the exit code is unaffected: this is affordance, not enforcement, and
    /// the reader still gets everything the fold can see.
    ///
    /// Once per process, because a single command may fold several times and
    /// repeating the same line per fold turns a real signal into noise.
    async fn warn_once_if_claims_are_unreachable(
        &self,
        walk: &[(String, Cid)],
    ) -> Result<(), Error> {
        static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

        let lost = self.mst.unreachable_among(walk).await?;
        if lost.is_empty() {
            return Ok(());
        }
        if WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
            return Ok(());
        }

        let n = lost.len();
        let plural = if n == 1 { "claim is" } else { "claims are" };
        eprintln!(
            "warning: {n} {plural} present in this log but not reachable by ordered lookup, so \
             this and every other read excludes them (kan#204). Nothing is lost -- they are in \
             the CAR. A log gets into this state when a kan built before the MST fix writes to \
             it. Any write repairs it, after which this warning stops."
        );
        Ok(())
    }
}

fn decoded_claim_id(claim: &crate::claim::codec::DecodedClaim) -> Result<Cid, Error> {
    match claim {
        crate::claim::codec::DecodedClaim::Supported(
            crate::claim::codec::SupportedClaim::Claim(claim),
        ) => Ok(claim.id()?.cid().clone()),
        crate::claim::codec::DecodedClaim::Supported(crate::claim::codec::SupportedClaim::V1(
            claim,
        )) => Ok(content_cid(&claim.content)?),
        crate::claim::codec::DecodedClaim::Unsupported(claim) => Ok(claim.claim_id().clone()),
    }
}

fn common_envelope(bytes: &[u8]) -> Result<bool, Error> {
    let raw: atproto_dasl::Ipld = atproto_dasl::from_slice(bytes).map_err(|error| {
        Error::Car(atproto_dasl::errors::CarError::Io(std::io::Error::other(
            error,
        )))
    })?;
    Ok(matches!(raw, atproto_dasl::Ipld::Map(ref fields) if fields.contains_key("$type")))
}

/// Old `tools.kan.claim` records predate the common envelope and therefore
/// have no `$type`. Only records that canonically decode to that shape may use
/// the compatibility decoder: malformed or typed records must retain the
/// current codec's fail-closed classification.
fn legacy_at_claim_candidate(bytes: &[u8]) -> bool {
    matches!(
        atproto_dasl::from_slice::<atproto_dasl::Ipld>(bytes),
        Ok(atproto_dasl::Ipld::Map(fields)) if !fields.contains_key("$type")
    )
}

fn mst_root(mst: &Mst<MemoryStorage>) -> Result<RawCid, Error> {
    mst.root().cloned().ok_or(Error::MissingRoot)
}

async fn write_commit(mst: &mut Mst<MemoryStorage>, commit: &Commit) -> Result<Cid, Error> {
    let bytes = commit.to_bytes()?;
    let cid = Cid::from(compute_cid(&bytes));
    mst.storage_mut().put(&cid, bytes).await?;
    Ok(cid)
}

#[cfg(test)]
mod claim_collection_migration_tests {
    use super::*;
    use crate::claim::v1::{Anchor, AuthorId, ClaimBody, Rkey, SubjectRef};

    fn signed(identity: &Identity, text: &str, rev: &str) -> (Cid, StoredClaim) {
        let content = ClaimContent {
            author: AuthorId {
                did: identity.did(),
                agent: None,
            },
            workspace: Anchor::Workspace("migration-fixture".into()),
            subject: SubjectRef::Local(Rkey::from("migration")),
            body: ClaimBody::Observation { text: text.into() },
            cites: vec![],
            artifacts: vec![],
            recorded_at: Some(42),
        };
        let cid = content_cid(&content).unwrap();
        let sig = identity.sign(&cid.to_bytes()).unwrap();
        (
            cid,
            StoredClaim {
                claim: Claim { content, sig },
                rev: rev.into(),
            },
        )
    }

    async fn seed_legacy(
        log: &mut Log,
        identity: &Identity,
        claim_cid: &Cid,
        stored: &StoredClaim,
    ) -> Cid {
        let bytes = atproto_dasl::to_vec(stored).unwrap();
        let record_cid = Cid::from(compute_cid(&bytes));
        log.mst.storage_mut().put(&record_cid, bytes).await.unwrap();
        let key = RecordPath::new(LEGACY_COLLECTION, claim_cid.to_string()).to_mst_key();
        log.mst.insert(&key, record_cid.clone()).await.unwrap();
        let unsigned = Commit::new_unsigned(
            identity.did(),
            Cid::from(mst_root(&log.mst).unwrap()),
            log.tid.next(),
            log.commit_cid.clone(),
        );
        let signature = identity.sign(&unsigned.to_bytes().unwrap()).unwrap();
        let commit = unsigned.sign(signature);
        let root = write_commit(&mut log.mst, &commit).await.unwrap();
        log.commit_cid = Some(root.clone());
        log.persist_new_blocks(&root).await.unwrap();
        record_cid
    }

    #[tokio::test]
    async fn legacy_only_migrates_once_and_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let identity = Identity::generate();
        let mut writer = Log::open_or_create(&path, &identity).await.unwrap();
        let (claim_cid, stored) = signed(&identity, "legacy", "3jzfcijpj2z2a");
        let historical_record = seed_legacy(&mut writer, &identity, &claim_cid, &stored).await;
        drop(writer);

        let mut migrated = Log::open_or_create(&path, &identity).await.unwrap();
        assert!(migrated
            .mst
            .list_collection(LEGACY_COLLECTION)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            migrated
                .mst
                .list_collection(COLLECTION)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            migrated.get_stored(claim_cid.clone()).await.unwrap(),
            Some(stored.clone())
        );
        assert!(migrated
            .mst
            .storage()
            .get(&historical_record)
            .await
            .unwrap()
            .is_some());
        let migrated_root = migrated.current_root();
        drop(migrated);

        let mut reopened = Log::open_or_create(&path, &identity).await.unwrap();
        assert_eq!(
            reopened.current_root(),
            migrated_root,
            "migration must be idempotent"
        );
        assert_eq!(reopened.get_stored(claim_cid).await.unwrap(), Some(stored));
    }

    #[tokio::test]
    async fn identical_mixed_collections_coalesce_but_conflicts_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let identity = Identity::generate();
        let mut writer = Log::open_or_create(&path, &identity).await.unwrap();
        let cid = writer
            .append(
                signed(&identity, "same", "unused").1.claim.content,
                &identity,
            )
            .await
            .unwrap();
        let current = writer.get_stored(cid.clone()).await.unwrap().unwrap();
        seed_legacy(&mut writer, &identity, &cid, &current).await;
        drop(writer);
        let migrated = Log::open_or_create(&path, &identity).await.unwrap();
        assert_eq!(
            migrated
                .mst
                .list_collection(COLLECTION)
                .await
                .unwrap()
                .len(),
            1
        );
        drop(migrated);

        let mut writer = Log::open_or_create(&path, &identity).await.unwrap();
        let mut conflict = writer.get_stored(cid.clone()).await.unwrap().unwrap();
        conflict.rev = "3jzfcijpj2z2b".into();
        seed_legacy(&mut writer, &identity, &cid, &conflict).await;
        drop(writer);
        assert!(matches!(
            Log::open_or_create(&path, &identity).await,
            Err(Error::ClaimMigrationConflict(key)) if key == cid.to_string()
        ));
    }

    #[tokio::test]
    async fn unverifiable_legacy_claim_stops_migration_without_committing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let identity = Identity::generate();
        let mut writer = Log::open_or_create(&path, &identity).await.unwrap();
        let (cid, mut stored) = signed(&identity, "forged", "3jzfcijpj2z2a");
        stored.claim.sig[0] ^= 1;
        seed_legacy(&mut writer, &identity, &cid, &stored).await;
        let before = writer.current_root();
        drop(writer);
        assert!(matches!(
            Log::open_or_create(&path, &identity).await,
            Err(Error::AtClaim(crate::at_claim::Error::BadSignature))
        ));
        let reader = Log::open_read_only(&path).await.unwrap();
        assert_eq!(reader.current_root(), before);
        assert_eq!(
            reader
                .mst
                .list_collection(LEGACY_COLLECTION)
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(reader
            .mst
            .list_collection(COLLECTION)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn lexicon_incompatible_legacy_claim_stops_migration_without_committing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let identity = Identity::generate();
        let mut writer = Log::open_or_create(&path, &identity).await.unwrap();
        let (_, mut stored) = signed(&identity, "placeholder", "3jzfcijpj2z2a");
        stored.claim.content.body = ClaimBody::Observation {
            text: "x".repeat(900_001),
        };
        let claim_cid = content_cid(&stored.claim.content).unwrap();
        stored.claim.sig = identity.sign(&claim_cid.to_bytes()).unwrap();
        seed_legacy(&mut writer, &identity, &claim_cid, &stored).await;
        let before = writer.current_root();
        drop(writer);

        assert!(matches!(
            Log::open_or_create(&path, &identity).await,
            Err(Error::AtClaim(crate::at_claim::Error::LexiconConstraint(_)))
        ));
        let reader = Log::open_read_only(&path).await.unwrap();
        assert_eq!(reader.current_root(), before);
        assert_eq!(
            reader
                .mst
                .list_collection(LEGACY_COLLECTION)
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(reader
            .mst
            .list_collection(COLLECTION)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn unknown_history_and_record_cid_substitution_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unknown");
        let identity = Identity::generate();
        let mut writer = Log::open_or_create(&path, &identity).await.unwrap();
        let (_, mut stored) = signed(&identity, "placeholder", "3jzfcijpj2z2a");
        stored.claim.content.body = ClaimBody::Unknown {
            kind: "FutureBody".into(),
            raw: vec![0xa0],
        };
        let unknown_cid = content_cid(&stored.claim.content).unwrap();
        stored.claim.sig = identity.sign(&unknown_cid.to_bytes()).unwrap();
        seed_legacy(&mut writer, &identity, &unknown_cid, &stored).await;
        drop(writer);
        assert!(matches!(
            Log::open_or_create(&path, &identity).await,
            Err(Error::AtClaim(crate::at_claim::Error::UnsupportedClaimCodec(kind)))
                if kind == "FutureBody"
        ));

        let path = dir.path().join("substitution");
        let mut writer = Log::open_or_create(&path, &identity).await.unwrap();
        let (_, stored) = signed(&identity, "valid claim", "3jzfcijpj2z2a");
        let enclosing_record_cid = content_cid(&"enclosing ATProto record").unwrap();
        seed_legacy(&mut writer, &identity, &enclosing_record_cid, &stored).await;
        drop(writer);
        assert!(matches!(
            Log::open_or_create(&path, &identity).await,
            Err(Error::BadSignature)
        ));
    }
}

//! The local append-only signed log — source of truth (`docs/SPEC.md` §10;
//! ADR-3 for the `.kan/log/` location; ADR-12 for the `atproto-repo` switch;
//! ADR-13 for incremental append).
//!
//! Claims are stored content-addressed, keyed by their own `content_cid`
//! (`crate::cid::content_cid`) under the `dev.kan.claim` collection (matching
//! `docs/SPEC.md` §10.1's future lexicon namespace), inside a single on-disk
//! CAR file — this is the same on-disk artifact atproto sync would use later.
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
//! (`crate::claim::*`) standardize on the wrapper.

use std::{collections::HashSet, path::Path};

use atproto_dasl::{
    car::{CarBlock, CarHeader, CarReader},
    storage::{BlockStorage, MemoryStorage},
    Cid, CidCore as RawCid,
};
use atproto_repo::{compute_cid, Commit, Mst, RecordPath, RepoConfig};
use serde::{Deserialize, Serialize};
use tokio::{fs, io::AsyncWriteExt};

use crate::{
    cid::content_cid,
    claim::{Claim, ClaimContent},
    sign::Identity,
    store::tid::TidGenerator,
};

const COLLECTION: &str = "dev.kan.claim";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("repository error: {0}")]
    Repo(#[from] atproto_repo::errors::RepoError),
    #[error("MST error: {0}")]
    Mst(#[from] atproto_repo::errors::MstError),
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
    #[error("log exists but its CAR file has no root")]
    MissingRoot,
    #[error("log exists but HEAD is missing or unreadable")]
    MissingHead,
    #[error("record key is not a valid CID: {0}")]
    InvalidCid(#[from] atproto_dasl::errors::DecodeError),
}

/// What's actually stored in the MST: the signed claim plus its log-revision
/// TID, captured at append time (ordering is log structure, not claim
/// content, so it lives in the envelope rather than `ClaimContent`).
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    did: String,
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
async fn read_blocks_tolerantly(bytes: &[u8]) -> Result<(MemoryStorage, bool), Error> {
    let mut storage = MemoryStorage::new();
    let mut reader = CarReader::new(std::io::Cursor::new(bytes)).await?;
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
    let mst = Mst::from_root(RawCid::from(commit.data), copy, RepoConfig::default());
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
    pub async fn open_or_create(dir: &Path, identity: &Identity) -> Result<Self, Error> {
        fs::create_dir_all(dir).await?;
        let car_path = dir.join("repo.car");
        let head_path = dir.join("HEAD");
        let lock_path = dir.join("LOCK");
        let did = identity.did();

        if car_path.exists() {
            let bytes = fs::read(&car_path).await?;
            let (mut storage, mut truncated) = read_blocks_tolerantly(&bytes).await?;

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
                let (fresh_storage, fresh_truncated) = read_blocks_tolerantly(&bytes).await?;
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
                    "warning: {} ends in a damaged block (an interrupted append, or truncation \
                     by something outside kan) -- every intact block before it was recovered, \
                     and the file will be repaired on the next write",
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
                    eprintln!(
                        "warning: HEAD was {} -- reading from the newest intact commit ({}) in \
                         {}. No claim was lost; the pointer to them was. HEAD will be rewritten \
                         on the next write.",
                        if stated.is_some() {
                            "pointing at a block this log does not contain"
                        } else {
                            "missing or unreadable"
                        },
                        recovered,
                        car_path.display()
                    );
                    head_stale = true;
                    recovered
                }
            };

            let commit_bytes = storage.get(&root).await?.ok_or(Error::MissingRoot)?;
            let commit = Commit::from_bytes(&commit_bytes)?;
            let mst = Mst::from_root(RawCid::from(commit.data), storage, RepoConfig::default());

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
            let mst = Mst::new(MemoryStorage::new(), RepoConfig::default());
            Ok(Self {
                car_path,
                head_path,
                mst,
                commit_cid: None,
                persisted: HashSet::new(),
                lock_path,
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
        let tmp = self.car_path.with_extension("repair");
        let mut out = fs::File::create(&tmp).await?;
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
        fs::rename(&tmp, &self.car_path).await?;
        self.persisted = written;
        Ok(())
    }

    /// Append every block in `mst.storage()` not already in `persisted` to
    /// the end of the CAR file (writing the header first if this is the
    /// file's first-ever write), then update `HEAD`.
    async fn persist_new_blocks(&mut self, root: &Cid) -> Result<(), Error> {
        let file_is_new = !self.car_path.exists();
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.car_path)
            .await?;

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
        let mut tmp = fs::File::create(&tmp_path).await?;
        tmp.write_all(root.to_string().as_bytes()).await?;
        tmp.sync_all().await?;
        drop(tmp);

        fs::rename(&tmp_path, &self.head_path).await?;

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
        // `fs4`'s blocking `lock()` on a `std::fs::File`, moved off the async
        // runtime: it parks the calling thread until the lock is available,
        // which would stall other tasks on a shared worker thread.
        let file = tokio::task::spawn_blocking(move || -> std::io::Result<std::fs::File> {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .truncate(false)
                .open(&lock_path)?;
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
        // A recovered root is *deliberately* out of step with what is on
        // disk until this append rewrites it — reloading toward the on-disk
        // value here would walk straight back into the damage recovery just
        // stepped around.
        if self.head_stale {
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
        let (storage, truncated) = read_blocks_tolerantly(&bytes).await?;
        self.needs_repair |= truncated;
        self.persisted = storage.cids().map(Cid::from).collect();

        let root = on_disk.expect("checked above");
        let commit_bytes = storage.get(&root).await?.ok_or(Error::MissingRoot)?;
        let commit = Commit::from_bytes(&commit_bytes)?;
        self.mst = Mst::from_root(RawCid::from(commit.data), storage, RepoConfig::default());
        self.commit_cid = Some(root);
        // Keep TID monotonicity across the takeover, exactly as reopening
        // would have.
        self.tid = TidGenerator::seeded(&commit.rev);
        self.last_recorded_at = self.last_recorded_at.max(self.tid.last_micros());
        Ok(())
    }

    /// Sign and append a claim, keyed by its own `content_cid` under the
    /// `dev.kan.claim` collection. Returns that CID — the claim's citable
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

        let record_bytes = atproto_dasl::to_vec(&stored).map_err(|e| {
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
            self.did.clone(),
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

    /// Fetch a claim by its `content_cid`, verifying its signature against
    /// its own author before returning it.
    pub async fn get(&mut self, claim_cid: Cid) -> Result<Option<Claim>, Error> {
        Ok(self.get_stored(claim_cid).await?.map(|s| s.claim))
    }

    /// Like `get`, but also returns the log-revision TID captured at append
    /// time.
    pub async fn get_stored(&mut self, claim_cid: Cid) -> Result<Option<StoredClaim>, Error> {
        let key = RecordPath::new(COLLECTION, claim_cid.to_string()).to_mst_key();
        let Some(record_cid) = self.mst.get(&key).await? else {
            return Ok(None);
        };
        let Some(bytes) = self.mst.storage().get(&record_cid).await? else {
            return Ok(None);
        };
        let stored: StoredClaim = atproto_dasl::from_slice(&bytes).map_err(|e| {
            Error::Car(atproto_dasl::errors::CarError::Io(std::io::Error::other(e)))
        })?;

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
        let mut out = Vec::with_capacity(entries.len());
        for (key, _record_cid) in entries {
            let path = RecordPath::from_mst_key(&key)?;
            if path.collection != COLLECTION {
                continue;
            }
            let claim_cid: Cid = path.rkey.parse().map_err(Error::InvalidCid)?;
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

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
    did: String,
    tid: TidGenerator,
}

impl Log {
    pub async fn open_or_create(dir: &Path, identity: &Identity) -> Result<Self, Error> {
        fs::create_dir_all(dir).await?;
        let car_path = dir.join("repo.car");
        let head_path = dir.join("HEAD");
        let did = identity.did();

        if car_path.exists() {
            let bytes = fs::read(&car_path).await?;
            let mut storage = MemoryStorage::new();
            let reader = CarReader::new(std::io::Cursor::new(&bytes)).await?;
            reader.stream_to_storage(&mut storage).await?;
            let persisted: HashSet<Cid> = storage.cids().map(Cid::from).collect();

            let head = fs::read_to_string(&head_path)
                .await
                .map_err(|_| Error::MissingHead)?;
            let root: Cid = head.trim().parse().map_err(|_| Error::MissingHead)?;

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
                did,
                tid,
            })
        } else {
            let mst = Mst::new(MemoryStorage::new(), RepoConfig::default());
            Ok(Self {
                car_path,
                head_path,
                mst,
                commit_cid: None,
                persisted: HashSet::new(),
                did,
                tid: TidGenerator::new(),
            })
        }
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
        file.flush().await?;

        fs::write(&self.head_path, root.to_string()).await?;
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

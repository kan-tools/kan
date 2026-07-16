//! The local append-only signed log — source of truth (`docs/SPEC.md` §10;
//! ADR-3 for the `.kan/log/` location; ADR-12 for the `atproto-repo` switch).
//!
//! Claims are stored content-addressed, keyed by their own `content_cid`
//! (`crate::cid::content_cid`) under the `dev.kan.claim` collection (matching
//! `docs/SPEC.md` §10.1's future lexicon namespace), inside a single on-disk
//! CAR file — this is the same on-disk artifact atproto sync would use later.
//!
//! Unlike `atrium-repo` (ADR-1's original pick, dropped after ADR-11's
//! confirmed data-loss bug), `atproto-repo`'s `CarWriter` doesn't support
//! incremental append — writing means serializing the *entire* reachable
//! block set fresh. `Log::append` therefore keeps everything in one
//! in-memory `MemoryStorage` for the lifetime of the `Log`, and does a full
//! CAR rewrite on every append. This is O(n) per append rather than O(1) —
//! a deliberate, documented tradeoff (`docs/DECISIONS.md` ADR-12): simple
//! and obviously correct beats fast-but-unverified, and it's what let this
//! whole rewrite be validated by construction rather than by trusting the
//! crate's shape the way ADR-8 did. A nice side effect: since the CAR
//! header's `roots` are rewritten fresh every time (unlike `atrium-repo`'s
//! fixed-at-creation header), there's no `HEAD` sidecar file to maintain —
//! `CarReader::root()` on open is simply correct.
//!
//! Two `Cid` types are in play, and the split isn't consistent, so every
//! call site converts explicitly rather than relying on inference: `Mst`'s
//! `root`/`from_root` speak the *raw* `cid` crate type (aliased here as
//! `RawCid`), but `insert`/`get` — on the same `Mst` — speak
//! `atproto_dasl::Cid`, the DAG-CBOR-serialization-friendly wrapper that
//! `Commit` and `BlockStorage` also use. This asymmetry isn't a kan design
//! choice; it's the crate's actual shape, found via compiler error rather
//! than assumed from its docs (see ADR-11/12's whole point: verify, don't
//! trust the shape). Kan's own types (`crate::claim::*`) standardize on the
//! wrapper.

use std::path::Path;

use atproto_dasl::{
    car::{CarReader, CarWriter},
    storage::{BlockStorage, MemoryStorage},
    Cid, CidCore as RawCid,
};
use atproto_repo::{compute_cid, Commit, Mst, RecordPath, RepoConfig};
use serde::{Deserialize, Serialize};
use tokio::fs;

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
    mst: Mst<MemoryStorage>,
    /// `None` until the first claim is appended — `Mst::new` starts with no
    /// root at all (unlike `atrium-repo`, which eagerly computed an
    /// empty-tree CID), so there's no meaningful "genesis commit over
    /// nothing" to create up front. The CAR file itself doesn't exist yet
    /// either in this state; both come into being together on first append.
    commit_cid: Option<Cid>,
    did: String,
    tid: TidGenerator,
}

impl Log {
    pub async fn open_or_create(dir: &Path, identity: &Identity) -> Result<Self, Error> {
        fs::create_dir_all(dir).await?;
        let car_path = dir.join("repo.car");
        let did = identity.did();

        if car_path.exists() {
            let bytes = fs::read(&car_path).await?;
            let mut storage = MemoryStorage::new();
            let reader = CarReader::new(std::io::Cursor::new(&bytes)).await?;
            let root = reader.root().cloned().ok_or(Error::MissingRoot)?;
            reader.stream_to_storage(&mut storage).await?;

            let commit_bytes = storage.get(&root).await?.ok_or(Error::MissingRoot)?;
            let commit = Commit::from_bytes(&commit_bytes)?;
            let mst = Mst::from_root(RawCid::from(commit.data), storage, RepoConfig::default());

            Ok(Self {
                car_path,
                mst,
                commit_cid: Some(root),
                did,
                tid: TidGenerator::new(),
            })
        } else {
            let mst = Mst::new(MemoryStorage::new(), RepoConfig::default());
            Ok(Self {
                car_path,
                mst,
                commit_cid: None,
                did,
                tid: TidGenerator::new(),
            })
        }
    }

    async fn write_car(&self, root: &Cid) -> Result<(), Error> {
        let mut bytes = Vec::new();
        {
            let mut writer = CarWriter::new(&mut bytes, vec![root.clone()]).await?;
            writer.write_from_storage(self.mst.storage()).await?;
            writer.finish().await?;
        }
        fs::write(&self.car_path, bytes).await?;
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

        self.write_car(&new_commit_cid).await?;
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
    pub async fn iter_all(&mut self) -> Result<Vec<(Cid, StoredClaim)>, Error> {
        let entries = self.mst.entries().await?;
        let mut out = Vec::with_capacity(entries.len());
        for (key, _record_cid) in entries {
            let path = RecordPath::from_mst_key(&key)?;
            if path.collection != COLLECTION {
                continue;
            }
            let claim_cid: Cid = path.rkey.parse().map_err(Error::InvalidCid)?;
            if let Some(stored) = self.get_stored(claim_cid.clone()).await? {
                out.push((claim_cid, stored));
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

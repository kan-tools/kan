//! The local append-only signed log — source of truth (`docs/SPEC.md` §10;
//! ADR-3 for the `.kan/log/` location).
//!
//! Claims are stored content-addressed, keyed by their own `content_cid`
//! (`crate::cid::content_cid`), inside a single on-disk CAR file
//! (`atrium_repo::blockstore::CarStore`) wrapped in an `atrium_repo::Repository`
//! for the commit chain — this is the same on-disk artifact atproto sync would
//! use later (ADR-8).
//!
//! `atrium-repo`'s CAR header `roots` are fixed at file-creation time (there's
//! no API to rewrite them), so they can't track a moving HEAD. A sibling
//! `HEAD` file holds the current root commit's CID, the same way git's `HEAD`
//! points at a ref instead of the tip being baked into the object store.
//!
//! `atrium-repo`'s `Commit` type exposes `rev()` but not `prev()`, so a
//! claim's log-revision order can't be recovered later by walking the commit
//! chain through the public API. Instead each claim's `Tid` (atproto's
//! lexicographically-sortable timestamp id, minted fresh per commit) is
//! captured at append time and stored *in the record envelope itself*
//! (`StoredClaim`, not the signed `ClaimContent` — ordering is log structure,
//! not claim content). That keeps ordering recoverable from the log alone, so
//! the SQLite index stays a true disposable projection (`docs/SPEC.md` §10).

use std::path::{Path, PathBuf};

use atrium_repo::{blockstore::CarStore, Repository};
use futures::TryStreamExt;
use ipld_core::cid::Cid;
use serde::{Deserialize, Serialize};
use tokio::fs::{File, OpenOptions};

use crate::{
    cid::content_cid,
    claim::{Claim, ClaimContent},
    sign::Identity,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("repository error: {0}")]
    Repo(#[from] atrium_repo::repo::Error),
    #[error("CAR store error: {0}")]
    Car(#[from] atrium_repo::blockstore::CarError),
    #[error("signing error: {0}")]
    Sign(#[from] crate::sign::Error),
    #[error("content addressing error: {0}")]
    Cid(#[from] crate::cid::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("invalid did:key for repository: {0}")]
    InvalidDid(&'static str),
    #[error("log exists but HEAD is missing or unreadable")]
    MissingHead,
    #[error("claim signature does not verify against its own author")]
    BadSignature,
    #[error("record key is not a valid CID: {0}")]
    InvalidCid(#[from] ipld_core::cid::Error),
    #[error("MST error: {0}")]
    Mst(#[from] atrium_repo::mst::Error),
}

/// What's actually stored in the MST: the signed claim plus its log-revision
/// `Tid`, captured at append time (see module docs).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredClaim {
    pub claim: Claim,
    pub rev: String,
}

pub struct Log {
    repo: Repository<CarStore<File>>,
    head_path: PathBuf,
}

impl Log {
    /// Open the log at `dir` (typically `.kan/log/`), creating a fresh signed
    /// repository owned by `identity` if none exists yet.
    pub async fn open_or_create(dir: &Path, identity: &Identity) -> Result<Self, Error> {
        tokio::fs::create_dir_all(dir).await?;
        let car_path = dir.join("repo.car");
        let head_path = dir.join("HEAD");

        if car_path.exists() {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&car_path)
                .await?;
            let car = CarStore::open(file).await?;
            let head = tokio::fs::read_to_string(&head_path)
                .await
                .map_err(|_| Error::MissingHead)?;
            let root: Cid = head.trim().parse().map_err(|_| Error::MissingHead)?;
            let repo = Repository::open(car, root).await?;
            Ok(Self { repo, head_path })
        } else {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&car_path)
                .await?;
            let car = CarStore::create(file).await?;
            let did =
                atrium_api::types::string::Did::new(identity.did()).map_err(Error::InvalidDid)?;
            let builder = Repository::create(car, did).await?;
            let sig = identity.sign(&builder.bytes())?;
            let repo = builder.finalize(sig).await?;
            let log = Self { repo, head_path };
            log.write_head().await?;
            Ok(log)
        }
    }

    async fn write_head(&self) -> Result<(), Error> {
        tokio::fs::write(&self.head_path, self.repo.root().to_string()).await?;
        Ok(())
    }

    /// Sign and append a claim, keyed by its own `content_cid`. Returns that
    /// CID — the claim's citable identity (`docs/SPEC.md` §1, no explicit id
    /// field; identity is the content CID).
    pub async fn append(
        &mut self,
        content: ClaimContent,
        identity: &Identity,
    ) -> Result<Cid, Error> {
        let claim_cid = content_cid(&content)?;
        let sig = identity.sign(&claim_cid.to_bytes())?;
        let claim = Claim { content, sig };
        let rev = atrium_api::types::string::Tid::now(atrium_api::types::LimitedU32::MIN);
        let stored = StoredClaim {
            claim,
            rev: rev.as_str().to_string(),
        };

        let (builder, _block_cid) = self.repo.add_raw(&claim_cid.to_string(), &stored).await?;
        let commit_bytes = builder.bytes();
        let commit_sig = identity.sign(&commit_bytes)?;
        builder.finalize(commit_sig).await?;

        self.write_head().await?;
        Ok(claim_cid)
    }

    /// Fetch a claim by its `content_cid`, verifying its signature against
    /// its own author before returning it.
    pub async fn get(&mut self, claim_cid: Cid) -> Result<Option<Claim>, Error> {
        Ok(self.get_stored(claim_cid).await?.map(|s| s.claim))
    }

    /// Like `get`, but also returns the log-revision `Tid` captured at
    /// append time.
    pub async fn get_stored(&mut self, claim_cid: Cid) -> Result<Option<StoredClaim>, Error> {
        let Some(stored) = self
            .repo
            .get_raw::<StoredClaim>(&claim_cid.to_string())
            .await?
        else {
            return Ok(None);
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

    /// Enumerate every claim currently in the log, each with the CID it's
    /// keyed by and its log-revision `Tid` — what a disposable index rebuild
    /// (`docs/SPEC.md` §10) scans to reconstruct projected state from
    /// scratch. Order is not guaranteed; sort by `rev` for chronological
    /// order.
    pub async fn iter_all(&mut self) -> Result<Vec<(Cid, StoredClaim)>, Error> {
        let keys: Vec<String> = {
            let mut tree = self.repo.tree();
            let mut entries = Box::pin(tree.entries());
            let mut keys = Vec::new();
            while let Some((key, _block_cid)) = entries.try_next().await? {
                keys.push(key);
            }
            keys
        };

        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            let cid: Cid = key.parse()?;
            if let Some(stored) = self.get_stored(cid).await? {
                out.push((cid, stored));
            }
        }
        Ok(out)
    }
}

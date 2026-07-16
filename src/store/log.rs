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

use std::path::{Path, PathBuf};

use atrium_repo::{blockstore::CarStore, Repository};
use ipld_core::cid::Cid;
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

        let (builder, _block_cid) = self.repo.add_raw(&claim_cid.to_string(), &claim).await?;
        let commit_bytes = builder.bytes();
        let commit_sig = identity.sign(&commit_bytes)?;
        builder.finalize(commit_sig).await?;

        self.write_head().await?;
        Ok(claim_cid)
    }

    /// Fetch a claim by its `content_cid`, verifying its signature against
    /// its own author before returning it.
    pub async fn get(&mut self, claim_cid: Cid) -> Result<Option<Claim>, Error> {
        let Some(claim) = self.repo.get_raw::<Claim>(&claim_cid.to_string()).await? else {
            return Ok(None);
        };
        let recomputed = content_cid(&claim.content)?;
        if recomputed != claim_cid
            || !crate::sign::verify(&claim.content.author.did, &claim_cid.to_bytes(), &claim.sig)
        {
            return Err(Error::BadSignature);
        }
        Ok(Some(claim))
    }
}

//! Shared setup for every CLI command: resolve `.kan/` (ADR-3, sibling to
//! `.git/`), load or create the local identity, and open the log + index.
//!
//! M3 resolves `.kan/` relative to the current directory rather than
//! searching upward for a repo root the way `git` does — a real but small
//! gap, fine for now since dogfooding runs from the repo root anyway; worth
//! revisiting once `kan` is used from subdirectories.
//!
//! The workspace anchor is a placeholder: a hash of the repo root's
//! canonical path, not the real git-genesis algorithm `docs/SPEC.md` §5
//! describes (that's M4's `RelationProvider`/anchor work). It's honest about
//! being provisional — good enough for a single checkout, not yet portable
//! across clones the way a true genesis hash would be.

use std::path::{Path, PathBuf};

use sha2::Digest;

use crate::{
    claim::{Anchor, GenesisCid},
    sign::Identity,
    store::{index::Index, log::Log},
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("identity error: {0}")]
    Sign(#[from] crate::sign::Error),
    #[error("log error: {0}")]
    Log(#[from] crate::store::log::Error),
    #[error("index error: {0}")]
    Index(#[from] crate::store::index::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub struct Workspace {
    pub identity: Identity,
    pub log: Log,
    pub index: Index,
    pub anchor: Anchor,
}

impl Workspace {
    pub async fn open(cwd: &Path) -> Result<Self, Error> {
        let kan_dir = cwd.join(".kan");
        let identity = Identity::load_or_create(&kan_dir.join("identity"))?;
        let mut log = Log::open_or_create(&kan_dir.join("log"), &identity).await?;
        let mut index = Index::open(&kan_dir.join("index.sqlite"))?;

        // Correctness-first (CLAUDE.md house rules): always rebuild from the
        // log before use rather than trusting a possibly-stale index.
        // Fine at today's scale; incremental indexing is a later
        // optimization once fixtures exist to guard it.
        let claims = log.iter_all().await?;
        index.rebuild(&claims)?;

        let anchor = Anchor::Workspace(workspace_anchor(cwd));
        Ok(Self {
            identity,
            log,
            index,
            anchor,
        })
    }
}

fn workspace_anchor(repo_root: &Path) -> GenesisCid {
    let canonical = repo_root
        .canonicalize()
        .unwrap_or_else(|_| repo_root.to_path_buf());
    let digest = sha2::Sha256::digest(canonical.to_string_lossy().as_bytes());
    format!("{digest:x}")
}

pub fn cwd() -> Result<PathBuf, Error> {
    Ok(std::env::current_dir()?)
}

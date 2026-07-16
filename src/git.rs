//! Shells out to the system `git` binary rather than embedding a git
//! library (`libgit2`/`gitoxide`) — kan already requires running inside a
//! git checkout (`.kan/` sits beside `.git/`, ADR-3), so `git` is always on
//! hand, and the handful of read-only plumbing commands M4b needs
//! (`rev-list`, `merge-base`) make shelling out dramatically simpler than
//! vendoring a git implementation for it (`CLAUDE.md`'s smell test).

use std::{
    path::{Path, PathBuf},
    process::Command,
};

use sha2::Digest;

use crate::claim::{GenesisCid, Sha};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to run `git {0}`: {1}")]
    Spawn(String, std::io::Error),
    #[error("`git {0}` exited with status {1}: {2}")]
    Failed(String, i32, String),
    #[error("`git {0}` produced non-UTF8 output")]
    NonUtf8(String),
}

pub struct GitSubstrate {
    repo_root: PathBuf,
}

impl GitSubstrate {
    /// `repo_root` need not be the repo's top level — `git` itself walks
    /// upward to find `.git/`, same as every other git command.
    pub fn open(repo_root: &Path) -> Result<Self, Error> {
        let substrate = Self {
            repo_root: repo_root.to_path_buf(),
        };
        substrate.run(&["rev-parse", "--git-dir"])?;
        Ok(substrate)
    }

    /// `docs/SPEC.md` §5 — a content-addressed fact about the shared
    /// substrate, computed identically by every actor: sha256 of the repo's
    /// root commit SHA(s), sorted so histories with multiple roots (grafts,
    /// merged-unrelated histories) still hash deterministically regardless
    /// of enumeration order.
    pub fn genesis(&self) -> Result<GenesisCid, Error> {
        let out = self.run(&["rev-list", "--max-parents=0", "HEAD"])?;
        let mut roots: Vec<&str> = out.lines().filter(|l| !l.is_empty()).collect();
        roots.sort_unstable();
        let digest = sha2::Sha256::digest(roots.join("\n").as_bytes());
        Ok(format!("{digest:x}"))
    }

    /// Does `ancestor` reach `descendant` by following parent edges — i.e.
    /// is `ancestor` causally earlier? (`git merge-base --is-ancestor`:
    /// exit 0 = yes, exit 1 = no, anything else = a real error.)
    pub fn is_ancestor(&self, ancestor: &Sha, descendant: &Sha) -> Result<bool, Error> {
        if ancestor == descendant {
            return Ok(false);
        }
        let args = [
            "merge-base",
            "--is-ancestor",
            ancestor.as_str(),
            descendant.as_str(),
        ];
        let output = Command::new("git")
            .args(args)
            .current_dir(&self.repo_root)
            .output()
            .map_err(|e| Error::Spawn(args.join(" "), e))?;
        match output.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            other => Err(Error::Failed(
                args.join(" "),
                other.unwrap_or(-1),
                String::from_utf8_lossy(&output.stderr).into_owned(),
            )),
        }
    }

    fn run(&self, args: &[&str]) -> Result<String, Error> {
        let output = Command::new("git")
            .args(args)
            .current_dir(&self.repo_root)
            .output()
            .map_err(|e| Error::Spawn(args.join(" "), e))?;
        if !output.status.success() {
            return Err(Error::Failed(
                args.join(" "),
                output.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&output.stderr).into_owned(),
            ));
        }
        String::from_utf8(output.stdout).map_err(|_| Error::NonUtf8(args.join(" ")))
    }
}

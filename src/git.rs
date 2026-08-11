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
    #[error(
        "this is a shallow clone — the workspace anchor must be computed identically by \
         every actor (docs/SPEC.md §5), which a shallow clone's truncated history can't \
         guarantee (its root commit is wherever the clone was truncated, not the repo's \
         real genesis); run `git fetch --unshallow` first"
    )]
    ShallowClone,
    #[error(
        "this git repo has no commits yet, and kan anchors every claim to one (docs/SPEC.md \
         §5/§6.2): the workspace identity is derived from the repo's root commit, and a \
         repo with no commits has no root.\n\n\
         Make a commit first -- `git commit --allow-empty -m init` is enough -- then run kan \
         again. Nothing was written."
    )]
    NoCommits,
    #[error(
        "this directory is not inside a git repository, and kan anchors every claim to a \
         repo's history (docs/SPEC.md §5). Run kan from inside a git repo, or create one \
         here with `git init && git commit --allow-empty -m init`. Nothing was written."
    )]
    NotAGitRepo,
}

pub struct GitSubstrate {
    repo_root: PathBuf,
}

/// A commit SHA is hex (SHA-1 or SHA-256), never empty. Anything else is not
/// a hash git could resolve, and — reaching git as a positional argument —
/// must not be allowed to start with `-` and be read as an option.
fn is_hex_sha(sha: &Sha) -> bool {
    !sha.is_empty() && sha.bytes().all(|b| b.is_ascii_hexdigit())
}

impl GitSubstrate {
    /// `repo_root` need not be the repo's top level — `git` itself walks
    /// upward to find `.git/`, same as every other git command.
    pub fn open(repo_root: &Path) -> Result<Self, Error> {
        let substrate = Self {
            repo_root: repo_root.to_path_buf(),
        };
        // git's own "fatal: not a git repository" is raw plumbing an operator
        // can't act on; give the actionable form instead (the no-commits and
        // shallow cases already have theirs).
        if let Err(Error::Failed(_, _, _)) = substrate.run(&["rev-parse", "--git-dir"]) {
            return Err(Error::NotAGitRepo);
        }
        Ok(substrate)
    }

    /// `docs/SPEC.md` §5 — a content-addressed fact about the shared
    /// substrate, computed identically by every actor: sha256 of the repo's
    /// root commit SHA(s), sorted so histories with multiple roots (grafts,
    /// merged-unrelated histories) still hash deterministically regardless
    /// of enumeration order.
    ///
    /// `--max-parents=0` only walks history reachable from `HEAD` — a
    /// shallow clone's truncated history would silently produce a
    /// *different* genesis than a full clone of "the same" repo, violating
    /// the "computed identically by every actor" invariant this exists to
    /// satisfy. Checked and rejected explicitly (`Error::ShallowClone`)
    /// rather than left to silently produce a wrong-but-different hash.
    pub fn genesis(&self) -> Result<GenesisCid, Error> {
        let shallow = self.run(&["rev-parse", "--is-shallow-repository"])?;
        if shallow.trim() == "true" {
            return Err(Error::ShallowClone);
        }

        // #141: a repo with no commits fails `rev-list ... HEAD` with a raw
        // 128 and git's own "ambiguous argument 'HEAD'" prose, which names
        // neither kan's requirement nor the one-line fix. Asked before the
        // call rather than pattern-matched on stderr afterwards, because
        // git's message is localised and version-dependent and the question
        // "does HEAD resolve" has a direct answer.
        if self
            .run(&["rev-parse", "--verify", "--quiet", "HEAD"])
            .is_err()
        {
            return Err(Error::NoCommits);
        }

        let out = self.run(&["rev-list", "--max-parents=0", "HEAD"])?;
        let mut roots: Vec<&str> = out.lines().filter(|l| !l.is_empty()).collect();
        roots.sort_unstable();
        let digest = sha2::Sha256::digest(roots.join("\n").as_bytes());
        Ok(format!("{digest:x}"))
    }

    /// Current `HEAD` commit SHA — the artifact every write verb attaches by
    /// default (`docs/SPEC.md` §6.2's "anchor to the tightest git object you
    /// can" as a real default, not just a recommendation).
    pub fn head_commit(&self) -> Result<Sha, Error> {
        Ok(self.run(&["rev-parse", "HEAD"])?.trim().to_string())
    }

    /// Does `ancestor` reach `descendant` by following parent edges — i.e.
    /// is `ancestor` causally earlier? (`git merge-base --is-ancestor`:
    /// exit 0 = yes, exit 1 = no, anything else = a real error.)
    ///
    /// Deliberately *not* real git's own reflexive semantics (`merge-base
    /// --is-ancestor X X` exits 0 — every commit is trivially its own
    /// ancestor) — this early-returns `false` instead, because the only
    /// caller (`relations::GitAncestry`) has already filtered out
    /// equal-sha pairs before calling this, and "is X causally *after*
    /// itself" should read as false for that ordering use, not true. Kept
    /// as an explicit branch (not relied on implicitly) so this deviation
    /// from git's own contract is visible here, not just at the call site.
    pub fn is_ancestor(&self, ancestor: &Sha, descendant: &Sha) -> Result<bool, Error> {
        if ancestor == descendant {
            return Ok(false);
        }
        // A `Sha` reaches here from a claim's `Anchor::Commit`/`ArtifactRef`,
        // which is untrusted text (review/full-pass-v0.12, git-arg finding).
        // A validated hex string can never be read by git as a `-`-prefixed
        // option, which closes the argument-injection surface at the source;
        // anything else is not a commit this repo could contain, so it
        // participates in no ancestry edge.
        if !is_hex_sha(ancestor) || !is_hex_sha(descendant) {
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

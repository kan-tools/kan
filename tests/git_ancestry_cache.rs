//! AC-13: `GitAncestry::relations` doesn't re-invoke `GitSubstrate::
//! is_ancestor` for a commit pair already resolved earlier in the same
//! `compute_all`-feeding call. Verified via a fake `git` shim placed ahead
//! of the real one on `PATH`, logging every invocation -- a call-count
//! instrumented test double, the most direct proof short of adding
//! test-only instrumentation to production code (AC-13's own suggested
//! approach). Deliberately the only test in this file/binary: it mutates
//! the process-wide `PATH`, which would otherwise race any other test in
//! the same process that also shells out to `git`.

use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};

use kan::{
    claim::{Anchor, ArtifactRef, AuthorId, ClaimBody, ClaimContent, Rkey, SubjectRef},
    git::GitSubstrate,
    relations::{GitAncestry, RelationProvider},
    sign::Identity,
    store::log::Log,
};

fn run_git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(dir)
        .status()
        .expect("failed to run git");
    assert!(status.success(), "git {args:?} failed");
}

fn head_sha(dir: &Path) -> String {
    let out = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(dir)
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn real_git_path() -> String {
    let out = Command::new("which").arg("git").output().unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A `git` on `PATH` ahead of the real one that appends each invocation's
/// args to `log_path`, then execs the real binary so behavior stays
/// correct -- `GitSubstrate::is_ancestor` keeps working, just observably.
fn install_git_shim(bin_dir: &Path, log_path: &Path, real_git: &str) {
    let script = format!(
        "#!/bin/sh\necho \"$@\" >> '{}'\nexec '{}' \"$@\"\n",
        log_path.display(),
        real_git,
    );
    let shim = bin_dir.join("git");
    fs::write(&shim, script).unwrap();
    let mut perms = fs::metadata(&shim).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&shim, perms).unwrap();
}

#[tokio::test]
async fn is_ancestor_is_not_re_invoked_for_a_pair_already_resolved() {
    let repo = tempfile::tempdir().unwrap();
    run_git(repo.path(), &["init", "-q"]);
    let base_env = [
        "-c",
        "user.email=kan-test@example.com",
        "-c",
        "user.name=kan-test",
    ];
    run_git(
        repo.path(),
        &[
            base_env[0],
            base_env[1],
            base_env[2],
            base_env[3],
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "first",
        ],
    );
    let commit1 = head_sha(repo.path());
    run_git(
        repo.path(),
        &[
            base_env[0],
            base_env[1],
            base_env[2],
            base_env[3],
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "second",
        ],
    );
    let commit2 = head_sha(repo.path());

    // Many claims anchored to just two distinct commits -- forces
    // GitAncestry's O(n^2) loop over claim pairs to repeatedly need the
    // *same* (commit1, commit2) / (commit2, commit1) directed pair.
    let log_dir = tempfile::tempdir().unwrap();
    let identity = Identity::generate();
    let author = AuthorId {
        did: identity.did(),
        agent: None,
    };
    let workspace_anchor = Anchor::Workspace("test-workspace".to_string());
    let mut log = Log::open_or_create(&log_dir.path().join("log"), &identity)
        .await
        .unwrap();
    for i in 0..8 {
        let sha = if i % 2 == 0 {
            commit1.clone()
        } else {
            commit2.clone()
        };
        log.append(
            ClaimContent {
                author: author.clone(),
                workspace: workspace_anchor.clone(),
                subject: SubjectRef::Local(Rkey::from(format!("s{i}"))),
                body: ClaimBody::Observation {
                    text: format!("claim {i}"),
                },
                cites: vec![],
                artifacts: vec![ArtifactRef::Commit(sha)],
                recorded_at: None,
            },
            &identity,
        )
        .await
        .unwrap();
    }
    let stored = log.iter_all().await.unwrap();
    let claims: Vec<_> = stored.into_iter().map(|(cid, s)| (cid, s.claim)).collect();

    // Now install the logging shim and run GitAncestry over those claims.
    let real_git = real_git_path();
    let bin_dir = tempfile::tempdir().unwrap();
    let log_path = bin_dir.path().join("git-calls.log");
    fs::write(&log_path, "").unwrap();
    install_git_shim(bin_dir.path(), &log_path, &real_git);
    let original_path = std::env::var("PATH").unwrap_or_default();
    // SAFETY: this is the only test in this binary/process, so no other
    // thread is concurrently reading/writing PATH.
    unsafe {
        std::env::set_var(
            "PATH",
            format!("{}:{original_path}", bin_dir.path().display()),
        );
    }

    let substrate = GitSubstrate::open(repo.path()).unwrap();
    let edges = GitAncestry.relations(&claims, &substrate);

    unsafe {
        std::env::set_var("PATH", original_path);
    }

    // Correctness: commit1's 4 claims are each ancestors of commit2's 4
    // claims -- 16 Ancestry edges.
    assert_eq!(
        edges.len(),
        16,
        "expected one edge per (commit1, commit2) claim pair"
    );

    // AC-13: only the two distinct directed pairs -- (commit1, commit2)
    // and (commit2, commit1) -- were ever actually resolved via a real git
    // subprocess, no matter how many of the 16 differing-commit claim
    // pairs needed that same fact. Without the cache this would be up to
    // 16 real `git merge-base --is-ancestor` invocations.
    let log_contents = fs::read_to_string(&log_path).unwrap();
    let is_ancestor_calls: Vec<&str> = log_contents
        .lines()
        .filter(|line| line.starts_with("merge-base --is-ancestor"))
        .collect();
    // **At most** two, not exactly two -- and the difference is a real
    // flake this assertion had, caught by CI on 2026-08-04 after passing for
    // months.
    //
    // `relations` asks `is_ancestor(b, a)` only when `is_ancestor(a, b)` was
    // false (it is an `else if`), so the *second* directed pair is queried
    // only when some claim pair happens to be visited descendant-first. That
    // depends on the order `Log::iter_all` returns claims in, which is MST
    // key order -- keyed on content CID, which is content-addressed over
    // wall-clock `recorded_at`. So the order is effectively random per run,
    // and with 4+4 claims the ~1.4% of runs where every commit-1 claim sorts
    // before every commit-2 claim need only ONE real call.
    //
    // One call is the cache working *better*, and the old assertion failed
    // on it. What AC-13 actually claims is that up to 16 claim pairs needing
    // the same fact collapse to at most one call per distinct directed
    // commit pair -- which is what this now says.
    assert!(
        (1..=2).contains(&is_ancestor_calls.len()),
        "expected at most 2 real `git merge-base --is-ancestor` subprocess calls (one per \
         distinct directed commit pair, cached after that) and at least 1, got {}: {:?}\n\
         full log: {log_contents:?}",
        is_ancestor_calls.len(),
        is_ancestor_calls,
    );
}

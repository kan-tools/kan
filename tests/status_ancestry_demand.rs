//! kan#202: Git ancestry is enrichment requested by the disagreement branch,
//! not a default cost paid by every status-like read.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

fn git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.com")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.com")
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "commit.gpgsign")
        .env("GIT_CONFIG_VALUE_0", "false")
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?} failed");
}

fn install_git_shim(bin_dir: &Path, log: &Path) -> String {
    let real = String::from_utf8_lossy(
        &Command::new("/usr/bin/which")
            .arg("git")
            .output()
            .unwrap()
            .stdout,
    )
    .trim()
    .to_string();
    let shim = bin_dir.join("git");
    fs::write(
        &shim,
        format!(
            "#!/bin/sh\necho \"$@\" >> '{}'\nexec '{}' \"$@\"\n",
            log.display(),
            real
        ),
    )
    .unwrap();
    let mut permissions = fs::metadata(&shim).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&shim, permissions).unwrap();
    format!("{}:{}", bin_dir.display(), std::env::var("PATH").unwrap())
}

fn run_kan(dir: &Path, key: &Path, args: &[&str], path: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kan"));
    command
        .args(args)
        .current_dir(dir)
        .env("KAN_IDENTITY_FILE", key)
        .env("KAN_NO_KEYCHAIN", "1");
    if let Some(path) = path {
        command.env("PATH", path);
    }
    command.output().unwrap()
}

fn assert_kan(dir: &Path, key: &Path, args: &[&str], path: Option<&str>) {
    let output = run_kan(dir, key, args, path);
    assert!(
        output.status.success(),
        "kan {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn ancestry_calls(log: &Path) -> Vec<String> {
    fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .filter(|line| line.contains("merge-base") || line.contains("is-ancestor"))
        .map(str::to_string)
        .collect()
}

fn two_author_repo() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-q"]);
    git(
        dir.path(),
        &["commit", "-q", "--allow-empty", "-m", "initial"],
    );
    let a = dir.path().join("a.key");
    let b = dir.path().join("b.key");
    kan::sign::Identity::generate().save(&a).unwrap();
    kan::sign::Identity::generate().save(&b).unwrap();

    // Resolve both deliberate identities while the log is empty. Once either
    // has authored a claim, the guard correctly refuses an undeclared new
    // identity rather than guessing that it is a role.
    assert_kan(dir.path(), &a, &["identity", "did"], None);
    assert_kan(dir.path(), &b, &["identity", "did"], None);
    (dir, a, b)
}

#[test]
fn status_like_reads_make_zero_ancestry_queries_without_live_disagreement() {
    let (dir, a, b) = two_author_repo();

    assert_kan(
        dir.path(),
        &a,
        &["observe", "narrative", "--subject", "no-status"],
        None,
    );
    assert_kan(dir.path(), &a, &["mark", "single", "blocked"], None);
    assert_kan(dir.path(), &a, &["mark", "agreeing", "blocked"], None);
    git(
        dir.path(),
        &["commit", "-q", "--allow-empty", "-m", "later"],
    );
    assert_kan(dir.path(), &b, &["mark", "agreeing", "blocked"], None);

    let shim_dir = dir.path().join("shim");
    fs::create_dir_all(&shim_dir).unwrap();
    let log = dir.path().join("git.log");
    let path = install_git_shim(&shim_dir, &log);

    for args in [
        vec!["status"],
        vec!["issues"],
        vec!["show", "agreeing"],
        vec!["show", "agreeing", "--json"],
        vec!["context", "--budget", "4000"],
    ] {
        assert_kan(dir.path(), &a, &args, Some(&path));
    }
    let calls = ancestry_calls(&log);
    assert!(
        calls.is_empty(),
        "uncontested/agreeing reads made ancestry queries:\n{}",
        calls.join("\n")
    );
}

#[test]
fn contested_status_queries_only_pairs_among_three_live_disagreeing_positions() {
    let (dir, a, b) = two_author_repo();
    let c = dir.path().join("c.key");
    kan::sign::Identity::generate().save(&c).unwrap();
    assert_kan(dir.path(), &c, &["identity", "did"], None);
    assert_kan(dir.path(), &a, &["mark", "contested", "blocked"], None);
    git(
        dir.path(),
        &["commit", "-q", "--allow-empty", "-m", "later"],
    );
    assert_kan(dir.path(), &b, &["mark", "contested", "resolved"], None);
    git(
        dir.path(),
        &["commit", "-q", "--allow-empty", "-m", "latest"],
    );
    assert_kan(dir.path(), &c, &["mark", "contested", "open"], None);

    let shim_dir = dir.path().join("shim");
    fs::create_dir_all(&shim_dir).unwrap();
    let log = dir.path().join("git.log");
    let path = install_git_shim(&shim_dir, &log);
    let output = run_kan(
        dir.path(),
        &a,
        &["status", "contested", "--json"],
        Some(&path),
    );
    assert!(output.status.success());
    let status: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(status["subjects"][0]["state"], "Settled");
    assert_eq!(status["subjects"][0]["value"], "Open");

    let calls = ancestry_calls(&log);
    assert_eq!(
        calls.len(),
        3,
        "three linearly ordered live positions need one successful query per pair: {calls:?}"
    );

    fs::write(&log, "").unwrap();
    let issues = run_kan(dir.path(), &a, &["issues", "--json"], Some(&path));
    assert!(issues.status.success());
    let issues: serde_json::Value = serde_json::from_slice(&issues.stdout).unwrap();
    let contested = issues["subjects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|subject| subject["subject"] == "contested")
        .unwrap();
    assert_eq!(contested["state"], "Settled");
    assert_eq!(contested["value"], "Open");
    let calls = ancestry_calls(&log);
    assert_eq!(
        calls.len(),
        3,
        "issues JSON must classify once and serialize that same result: {calls:?}"
    );
}

#[test]
fn production_provider_call_sites_are_explicit_and_exhaustive() {
    let actions = fs::read_to_string("src/actions.rs").unwrap();
    let relations = fs::read_to_string("src/relations.rs").unwrap();

    assert_eq!(
        actions.matches("relations::GitAncestry.relations(").count(),
        1,
        "status classification is the sole production GitAncestry consumer"
    );
    assert_eq!(
        actions.matches("relations::GitSameFile.relations(").count(),
        1,
        "related-subject lookup is the sole production GitSameFile consumer"
    );
    assert!(!actions.contains("compute_default("));
    assert!(!actions.contains("compute_all("));
    assert!(!relations.contains("pub fn compute_default"));
    assert!(!relations.contains("pub fn compute_all"));
}

//! Which tags the migration matrix treats as HISTORICAL WRITERS.
//!
//! A cell is only a migration test if the writer and the reader are different
//! builds. kan#205 is what it looks like when they are not: a
//! `workflow_dispatch` from a HEAD sitting docs-only ahead of a released tag
//! put that tag in the matrix, both sides compiled from the same source, and
//! the keychain cell scored `ok` for a binary reading a keychain entry it had
//! created itself. Four such cells across five runs read as nondeterminism for
//! two days -- the "alternation" was dispatch-vs-tag-push and nothing else.
//!
//! These tests drive `scripts/select-migration-writers.sh` directly rather
//! than restating its rule in Rust. A second implementation of the rule is
//! exactly the drift this repo keeps paying for, and a test that agrees with
//! its own copy of the logic would have agreed with the bug.
//!
//! The repos here are synthetic: a few files, a couple of tags, no kan
//! involved. What is under test is the selection, not the migration.
//!
//! The rule these pin is ADR-91.

use std::path::Path;
use std::process::{Command, Output};

fn git(dir: &Path, args: &[&str]) {
    // Hermetic against the developer's own git config. `tag.gpgsign=true` is
    // common (this repo's author has it), and it turns a lightweight `git tag`
    // into a signed one that demands a message and a key -- so the test would
    // pass in CI and fail on the machine of anyone who signs their tags.
    let status = Command::new("git")
        .args(["-c", "tag.gpgsign=false", "-c", "commit.gpgsign=false"])
        .args(args)
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", "kan-test")
        .env("GIT_AUTHOR_EMAIL", "kan-test@example.com")
        .env("GIT_COMMITTER_NAME", "kan-test")
        .env("GIT_COMMITTER_EMAIL", "kan-test@example.com")
        .status()
        .expect("failed to run git");
    assert!(status.success(), "git {args:?} failed");
}

fn write(dir: &Path, rel: &str, body: &str) {
    let path = dir.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, body).unwrap();
}

/// Commit everything, then tag it.
fn commit_and_tag(dir: &Path, message: &str, tag: Option<&str>) {
    git(dir, &["add", "-A"]);
    git(dir, &["commit", "-q", "-m", message]);
    if let Some(t) = tag {
        git(dir, &["tag", t]);
    }
}

/// Commit with an explicit timestamp, then tag.
///
/// Lightweight tags sort by their commit's date, so a fixture whose commits all
/// land in the same second has no defined "newest tag" and `tail -1` picks
/// arbitrarily. Real releases are minutes apart; a test must not depend on that.
fn commit_and_tag_at(dir: &Path, message: &str, tag: Option<&str>, ts: u32) {
    let when = format!("2026-01-01T00:{:02}:00", ts);
    git(dir, &["add", "-A"]);
    let status = Command::new("git")
        .args(["-c", "tag.gpgsign=false", "-c", "commit.gpgsign=false"])
        .args(["commit", "-q", "-m", message])
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", "kan-test")
        .env("GIT_AUTHOR_EMAIL", "kan-test@example.com")
        .env("GIT_COMMITTER_NAME", "kan-test")
        .env("GIT_COMMITTER_EMAIL", "kan-test@example.com")
        .env("GIT_AUTHOR_DATE", &when)
        .env("GIT_COMMITTER_DATE", &when)
        .status()
        .expect("failed to run git");
    assert!(status.success(), "dated commit failed");
    if let Some(t) = tag {
        git(dir, &["tag", t]);
    }
}

fn select(dir: &Path, current: &str) -> Output {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/select-migration-writers.sh");
    Command::new("bash")
        .arg(&script)
        .arg(current)
        .current_dir(dir)
        .output()
        .expect("failed to run select-migration-writers.sh")
}

fn select_scoped(dir: &Path, current: &str, scope: &str) -> Output {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/select-migration-writers.sh");
    Command::new("bash")
        .arg(&script)
        .arg(current)
        .arg(scope)
        .current_dir(dir)
        .output()
        .expect("failed to run select-migration-writers.sh")
}

fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).to_string()
}

/// v0.1.0, then v0.2.0 (a real source change plus a version bump), then a
/// docs-only commit on top. HEAD therefore builds exactly what v0.2.0 builds.
fn repo_with_head_matching_latest_tag() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    git(p, &["init", "-q"]);

    write(p, "src/main.rs", "fn main() { println!(\"one\"); }\n");
    write(
        p,
        "Cargo.toml",
        "[package]\nname = \"kan\"\nversion = \"0.1.0\"\n",
    );
    write(p, "Cargo.lock", "# lock v1\n");
    commit_and_tag(p, "v0.1.0", Some("v0.1.0"));

    write(p, "src/main.rs", "fn main() { println!(\"two\"); }\n");
    write(
        p,
        "Cargo.toml",
        "[package]\nname = \"kan\"\nversion = \"0.2.0\"\n",
    );
    commit_and_tag(p, "v0.2.0", Some("v0.2.0"));

    // Docs only: HEAD moves, the build does not.
    write(p, "README.md", "prose that changes no binary\n");
    commit_and_tag(p, "docs: tidy the readme", None);

    dir
}

#[test]
fn a_tag_that_builds_what_head_builds_is_not_a_writer() {
    let dir = repo_with_head_matching_latest_tag();

    // A dispatch run: GITHUB_REF_NAME is a branch, so the name-based
    // exclusion matches nothing and only the content rule can save the cell.
    let out = select(dir.path(), "main");

    assert_eq!(
        stdout_of(&out),
        "[\"v0.1.0\"]",
        "v0.2.0 builds exactly what HEAD builds, so its cell would put one \
         binary in both roles and measure no upgrade (kan#205). \
         stderr:\n{}",
        stderr_of(&out)
    );
}

#[test]
fn a_genuinely_older_tag_is_still_a_writer() {
    // The negative control. An exclusion rule that is too eager empties the
    // matrix, and an empty matrix is green -- the same plausible green in a
    // new place. Stated as its own test so that failure is legible rather
    // than showing up as a confusing half of the test above.
    let dir = repo_with_head_matching_latest_tag();
    let out = select(dir.path(), "main");
    assert!(
        stdout_of(&out).contains("v0.1.0"),
        "v0.1.0 differs from HEAD in src, Cargo.toml and nothing about it is \
         this build -- it must remain a writer. got: {}",
        stdout_of(&out)
    );
}

#[test]
fn a_version_bump_alone_makes_a_tag_a_writer() {
    // v0.12.0-beta.1 and beta.2 share an identical `src` tree and differ only
    // in Cargo.lock/Cargo.toml. Reading that as "the same build" is precisely
    // the mistake that made #205 look like nondeterminism -- the earlier
    // record described the reader as "differing only by version string" and
    // concluded the outcome was random. A version string is a different
    // binary, so the triple must not be narrowed to `src`.
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    git(p, &["init", "-q"]);

    write(p, "src/main.rs", "fn main() {}\n");
    write(
        p,
        "Cargo.toml",
        "[package]\nname = \"kan\"\nversion = \"0.1.0\"\n",
    );
    write(p, "Cargo.lock", "# lock v1\n");
    commit_and_tag(p, "v0.1.0", Some("v0.1.0"));

    // Same src, version bump only -- and HEAD is here.
    write(
        p,
        "Cargo.toml",
        "[package]\nname = \"kan\"\nversion = \"0.2.0\"\n",
    );
    commit_and_tag(p, "v0.2.0", Some("v0.2.0"));

    let out = select(p, "main");
    assert_eq!(
        stdout_of(&out),
        "[\"v0.1.0\"]",
        "v0.1.0 shares HEAD's src tree but bumps the version, so it builds a \
         different binary and stays a writer. stderr:\n{}",
        stderr_of(&out)
    );
}

#[test]
fn the_version_being_released_is_excluded_on_its_own_tag_push() {
    // The original rule, still enforced: a version is not a historical writer
    // for its own release. On a tag push the content rule reaches the same
    // answer, which is why this holds by name AND by content.
    let dir = repo_with_head_matching_latest_tag();
    let p = dir.path();
    git(p, &["checkout", "-q", "v0.2.0"]);

    let out = select(p, "v0.2.0");
    assert_eq!(
        stdout_of(&out),
        "[\"v0.1.0\"]",
        "stderr:\n{}",
        stderr_of(&out)
    );
}

#[test]
fn every_exclusion_is_announced_rather_than_silent() {
    // A matrix that quietly drops rows reads as "covered everything" while
    // covering less. Whatever is excluded must say so and say why.
    let dir = repo_with_head_matching_latest_tag();
    let out = select(dir.path(), "main");
    let err = stderr_of(&out);

    assert!(
        err.contains("v0.2.0") && err.contains("excluding"),
        "the dropped tag must be named on stderr, which the workflow turns \
         into a job notice. got:\n{err}"
    );
    assert!(
        err.contains("kan#205"),
        "the announcement should carry the reason a reader can look up. \
         got:\n{err}"
    );
}

/// A repo whose era tags sit on genuinely distinct commits.
///
/// The first version of this test tagged them all at HEAD, where ADR-91's own
/// content rule excluded every one of them — the fixture failing, not the
/// feature. Each tag needs its own version so it builds something other than
/// this build.
fn repo_with_era_tags() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    git(p, &["init", "-q"]);
    write(p, "src/main.rs", "fn main() {}\n");
    write(p, "Cargo.lock", "# lock v1\n");

    for (i, tag) in [
        "v0.1.1-beta.1",
        "v0.2.0-beta.1",
        "v0.4.0-beta.1",
        "v0.6.0-beta.1",
        "v0.7.0-beta.1",
        "v0.9.0-beta.1",
        "v0.11.0-beta.1",
    ]
    .iter()
    .enumerate()
    {
        write(
            p,
            "Cargo.toml",
            &format!("[package]\nname = \"kan\"\nversion = \"0.0.{i}\"\n"),
        );
        commit_and_tag_at(p, tag, Some(tag), u32::try_from(i).unwrap() + 1);
    }
    // HEAD is past every tag, and differs from all of them.
    write(
        p,
        "Cargo.toml",
        "[package]\nname = \"kan\"\nversion = \"0.99.0\"\n",
    );
    commit_and_tag_at(p, "unreleased work", None, 50);
    dir
}

/// Era representatives: the writer set an ordinary PR runs.
/// Era representatives: the writer set an ordinary PR runs.
///
/// Pruning by RECENCY was considered and rejected on measurement. Every writer
/// from v0.7.0 through v0.12.0-beta.5 asserts an identical outcome signature —
/// thirteen tags saying the same thing — while the distinct behaviour lives in
/// the oldest ones: v0.1.1 predates keychain support, and v0.2.0..v0.6.0 use
/// the path-derived account with no pointer file that v0.7's REQ-5 replaced. A
/// recency window keeps the redundant cells and drops the informative ones.
#[test]
fn a_pull_request_runs_one_writer_per_layout_era() {
    let dir = repo_with_era_tags();
    let out = select_scoped(dir.path(), "main", "representatives");
    let listed = stdout_of(&out);
    for kept in [
        "v0.1.1-beta.1",
        "v0.2.0-beta.1",
        "v0.6.0-beta.1",
        "v0.7.0-beta.1",
        "v0.11.0-beta.1",
    ] {
        assert!(listed.contains(kept), "{kept} must be kept. got: {listed}");
    }
    for dropped in ["v0.4.0-beta.1", "v0.9.0-beta.1"] {
        assert!(
            !listed.contains(dropped),
            "{dropped} is a redundant member of an era already represented: {listed}"
        );
    }
}

/// The pruning is a PR economy, never a release one.
///
/// A row is PREDICTED until its cell executes. If the newest tags never ran as
/// writers, their predictions would never convert — and "a prediction that is
/// never converted is indistinguishable from a measurement" is the defect the
/// conversion gate exists to stop. Tag pushes stay unpruned so every release is
/// measured exactly once.
#[test]
fn a_tag_push_still_runs_every_writer() {
    let dir = repo_with_era_tags();
    let listed = stdout_of(&select_scoped(dir.path(), "", "all"));
    for kept in ["v0.4.0-beta.1", "v0.9.0-beta.1", "v0.11.0-beta.1"] {
        assert!(
            listed.contains(kept),
            "{kept} is pruned only on a PR, never at a tag push: {listed}"
        );
    }
}

/// A named representative that does not exist is an error, not a smaller
/// matrix — the same rule the workflow applies to a tag with no committed row.
#[test]
fn a_missing_representative_refuses_rather_than_shrinking_the_matrix() {
    let dir = repo_with_head_matching_latest_tag();
    let out = select_scoped(dir.path(), "main", "representatives");
    assert!(
        !out.status.success(),
        "with none of the representative tags present, the script must refuse"
    );
    assert!(
        stderr_of(&out).contains("refusing to run a smaller matrix"),
        "and say why: {}",
        stderr_of(&out)
    );
}

/// The newest release is always a writer, even on a pruned run.
///
/// The fixed era list is v0.11 and older by construction, so a pruned run
/// covered no writer from the CURRENT series at all — and N-1 → N is the
/// upgrade path every real user takes, as well as the writer closest to
/// whatever the PR changed. It also restores the conversion: a row is
/// PREDICTED until its cell executes, so a fixed-only list left each release's
/// rows waiting for a tag push, which is a post-merge red run.
#[test]
fn the_newest_release_is_a_writer_even_when_pruned() {
    let dir = repo_with_era_tags();
    let listed = stdout_of(&select_scoped(dir.path(), "main", "representatives"));
    assert!(
        listed.contains("v0.11.0-beta.1"),
        "the newest tag in this fixture must be present: {listed}"
    );
    // And the redundant middle is still pruned.
    assert!(
        !listed.contains("v0.9.0-beta.1"),
        "pruning still applies to the era's other members: {listed}"
    );
}

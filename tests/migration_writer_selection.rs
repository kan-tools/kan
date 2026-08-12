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

fn select(dir: &Path, current: &str) -> Output {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/select-migration-writers.sh");
    Command::new("bash")
        .arg(&script)
        .arg(current)
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

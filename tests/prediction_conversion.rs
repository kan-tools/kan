//! Converting a PREDICTED expectation row into a MEASURED one.
//!
//! The gate this replaces failed the run that took the measurement, so the
//! **first correct measurement was the failing case** and every release
//! inherited a scheduled red at the next release's PR. ADR-78 already condemned
//! that shape once — "a permanently red gate is one nobody reads" — and this
//! reintroduced it as a recurring one.
//!
//! The expectation stays the pass criterion: a row whose outcome does not match
//! still fails loudly, and this conversion is never reached. What changes is
//! that bookkeeping is done by the machine holding the answer rather than by a
//! red build asking a human to type it.

use std::path::Path;
use std::process::{Command, Output};

const HEADER: &str = "# tag\tmode\toutcome\twhy";

fn table(dir: &Path, rows: &[&str]) -> std::path::PathBuf {
    let path = dir.join("expectations.tsv");
    let mut body = String::from(HEADER);
    body.push('\n');
    for row in rows {
        body.push_str(row);
        body.push('\n');
    }
    std::fs::write(&path, body).unwrap();
    path
}

fn convert(tsv: &Path, tag: &str, mode: &str, run: &str) -> Output {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/convert-prediction.sh");
    Command::new("bash")
        .arg(&script)
        .args([tag, mode, run])
        .arg(tsv)
        .output()
        .expect("failed to run convert-prediction.sh")
}

fn why_of(tsv: &Path, tag: &str, mode: &str) -> String {
    for line in std::fs::read_to_string(tsv).unwrap().lines() {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() >= 4 && f[0] == tag && f[1] == mode {
            return f[3].to_string();
        }
    }
    panic!("no row for ({tag}, {mode})");
}

#[test]
fn the_leading_token_is_replaced_and_the_reasoning_survives() {
    let dir = tempfile::tempdir().unwrap();
    let tsv = table(
        dir.path(),
        &["v0.9.0-beta.1\tkeychain\tkeychain-modal\tPREDICTED at cut time. The ACL model says a protect-filed entry is unreadable by a different binary, and a future actual=ok here is kan#205 rather than a regression."],
    );

    let out = convert(&tsv, "v0.9.0-beta.1", "keychain", "999");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let why = why_of(&tsv, "v0.9.0-beta.1", "keychain");
    assert!(why.starts_with("MEASURED in run 999,"), "got: {why}");
    assert!(
        why.contains(
            "The ACL model says a protect-filed entry is unreadable by a different binary"
        ),
        "the author's reasoning must survive verbatim: {why}"
    );
    assert!(
        why.contains("kan#205 rather than a regression"),
        "including the clause that outlives the prediction: {why}"
    );
    assert!(
        why.contains("confirming what was PREDICTED at cut time"),
        "and it should read as a confirmation, not erase that a prediction was made: {why}"
    );
}

#[test]
fn converting_twice_is_a_no_op() {
    // A re-run, a retry, or two cells racing must not double-convert. The
    // second call is a success that changes nothing, not an error.
    let dir = tempfile::tempdir().unwrap();
    let tsv = table(
        dir.path(),
        &["v0.9.0-beta.1\tseed\tok\tPREDICTED at cut time. Reasoning."],
    );

    assert!(convert(&tsv, "v0.9.0-beta.1", "seed", "111")
        .status
        .success());
    let once = why_of(&tsv, "v0.9.0-beta.1", "seed");

    let out = convert(&tsv, "v0.9.0-beta.1", "seed", "222");
    assert!(out.status.success(), "a second conversion must not fail");
    assert_eq!(
        once,
        why_of(&tsv, "v0.9.0-beta.1", "seed"),
        "the row must be untouched the second time -- the first run id stands"
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("already a measurement"),
        "and it should say so"
    );
}

#[test]
fn other_rows_are_left_exactly_alone() {
    let dir = tempfile::tempdir().unwrap();
    let tsv = table(
        dir.path(),
        &[
            "v0.9.0-beta.1\tseed\tok\tPREDICTED at cut time. Row A.",
            "v0.9.0-beta.1\tkeychain\tkeychain-modal\tPREDICTED at cut time. Row B.",
            "v0.11.0-beta.1\tseed\tok\tMEASURED in run 7. Row C.",
        ],
    );
    let before = std::fs::read_to_string(&tsv).unwrap();

    convert(&tsv, "v0.9.0-beta.1", "seed", "42");

    assert!(why_of(&tsv, "v0.9.0-beta.1", "keychain").starts_with("PREDICTED"));
    assert_eq!(
        why_of(&tsv, "v0.11.0-beta.1", "seed"),
        "MEASURED in run 7. Row C."
    );
    assert_eq!(
        before.lines().count(),
        std::fs::read_to_string(&tsv).unwrap().lines().count(),
        "no line added or lost"
    );
}

#[test]
fn a_row_that_does_not_exist_is_an_error() {
    // The matrix already treats a tag with no committed row as an error rather
    // than a pass. A conversion aimed at a row that is not there means the
    // table and the run disagree about what exists, and silently succeeding
    // would hide that.
    let dir = tempfile::tempdir().unwrap();
    let tsv = table(
        dir.path(),
        &["v0.9.0-beta.1\tseed\tok\tPREDICTED at cut time."],
    );

    let out = convert(&tsv, "v0.9.0-beta.1", "keychain", "42");
    assert!(!out.status.success(), "a missing row must fail");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("no row for"),
        "and name what it could not find"
    );
}

#[test]
fn the_table_stays_tab_separated_and_parseable() {
    // The file is read by awk with -F'\t' in the workflow. A conversion that
    // introduced a stray tab or newline would break every later row's parse.
    let dir = tempfile::tempdir().unwrap();
    let tsv = table(
        dir.path(),
        &["v0.9.0-beta.1\tseed\tok\tPREDICTED at cut time. Prose with, punctuation; and -- dashes."],
    );
    convert(&tsv, "v0.9.0-beta.1", "seed", "42");

    for line in std::fs::read_to_string(&tsv).unwrap().lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        assert_eq!(
            line.split('\t').count(),
            4,
            "every row keeps exactly four fields: {line}"
        );
    }
}

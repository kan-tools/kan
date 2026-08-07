//! Both subject forms, on every claim-writing verb (#78, #94, #101).
//!
//! `observe`/`plan`/`decide` took `--subject`; `result`/`resolve`/`block`
//! took it positionally; nothing let a caller infer which was which. Two
//! independent sessions got it wrong in opposite directions, and #101 records
//! that it cost **lost writes** — a long claim retyped after `error:
//! unexpected argument '--subject'`.
//!
//! These run the real binary, because the failure was in argument parsing and
//! a library-level test would not have caught it.

use std::process::Command;

fn kan() -> Option<std::path::PathBuf> {
    let exe = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        })
        .join("kan");
    exe.exists().then_some(exe)
}

struct Repo {
    dir: tempfile::TempDir,
}

impl Repo {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        for args in [
            vec!["init", "-q", "."],
            vec!["commit", "-q", "--allow-empty", "-m", "init"],
        ] {
            Command::new("git")
                .args(&args)
                .current_dir(dir.path())
                .env("GIT_AUTHOR_NAME", "t")
                .env("GIT_AUTHOR_EMAIL", "t@example.com")
                .env("GIT_COMMITTER_NAME", "t")
                .env("GIT_COMMITTER_EMAIL", "t@example.com")
                .output()
                .unwrap();
        }
        // The selection must exist: REQ-2 means naming a missing path is an
        // error rather than a way to mint one.
        let key = dir.path().join("key");
        kan::sign::Identity::generate().save(&key).unwrap();
        Self { dir }
    }

    fn run(&self, args: &[&str]) -> std::process::Output {
        Command::new(kan().expect("binary"))
            .args(args)
            .current_dir(self.dir.path())
            // Never touch the developer's real keychain or identity.
            .env("KAN_IDENTITY_FILE", self.dir.path().join("key"))
            .output()
            .unwrap()
    }
}

/// Every claim-writing verb accepts the subject positionally *and* as a flag.
#[test]
fn both_subject_forms_work_on_every_write_verb() {
    if kan().is_none() {
        return; // binary not built; nothing to conform to
    }
    let repo = Repo::new();

    let cases: Vec<(&str, Vec<&str>)> = vec![
        ("observe positional", vec!["observe", "s1", "text"]),
        ("observe flag", vec!["observe", "text", "--subject", "s2"]),
        ("plan positional", vec!["plan", "s3", "text"]),
        ("plan flag", vec!["plan", "text", "--subject", "s4"]),
        ("decide positional", vec!["decide", "s5", "text"]),
        ("decide flag", vec!["decide", "text", "--subject", "s6"]),
        ("result positional", vec!["result", "s7", "text"]),
        ("result flag", vec!["result", "text", "--subject", "s8"]),
        ("block positional", vec!["block", "s9", "text"]),
        ("block flag", vec!["block", "text", "--subject", "s10"]),
        ("resolve positional", vec!["resolve", "s11", "text"]),
        ("resolve flag", vec!["resolve", "text", "--subject", "s12"]),
    ];

    let mut failed = Vec::new();
    for (label, args) in &cases {
        let out = repo.run(args);
        if !out.status.success() {
            failed.push(format!(
                "{label}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
    }
    assert!(
        failed.is_empty(),
        "{} of {} argument forms rejected:\n  {}",
        failed.len(),
        cases.len(),
        failed.join("\n  ")
    );
}

/// The claim lands on the subject the caller meant, whichever form was used —
/// accepting an argument shape is worthless if it files the claim elsewhere.
#[test]
fn both_forms_file_the_claim_under_the_same_subject() {
    if kan().is_none() {
        return;
    }
    let repo = Repo::new();
    repo.run(&["observe", "target", "via positional"]);
    repo.run(&["observe", "via flag", "--subject", "target"]);

    let out = repo.run(&["show", "target"]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("via positional"), "positional form: {text}");
    assert!(text.contains("via flag"), "flag form: {text}");
}

/// Giving the subject twice is refused rather than silently resolved one way.
#[test]
fn giving_the_subject_both_ways_is_refused() {
    if kan().is_none() {
        return;
    }
    let repo = Repo::new();
    let out = repo.run(&["observe", "s", "text", "--subject", "other"]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("give the subject once"),
        "the error must say what to do: {err}"
    );
}

/// A verb that needs a subject, given only text, says which forms it accepts
/// and quotes the text back — the original failure cost a retyped claim
/// because the error named neither.
#[test]
fn a_missing_subject_names_both_accepted_forms() {
    if kan().is_none() {
        return;
    }
    let repo = Repo::new();
    let out = repo.run(&["result", "an outcome worth keeping"]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--subject"), "names the flag form: {err}");
    assert!(
        err.contains("<subject>"),
        "names the positional form: {err}"
    );
    assert!(
        err.contains("an outcome worth keeping"),
        "quotes the text back so it need not be retyped: {err}"
    );
}

/// `--version` exists (#100). Without it `day` can pin a payload schema and
/// not the binary producing it, which left ADR-50's contract half-built.
#[test]
fn the_binary_reports_its_version() {
    if kan().is_none() {
        return;
    }
    let repo = Repo::new();
    let out = repo.run(&["--version"]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains(env!("CARGO_PKG_VERSION")),
        "must report Cargo.toml's version: {text}"
    );
}

/// The recovery phrase must never be accepted on the command line (#104).
#[test]
fn the_recovery_phrase_is_refused_as_an_argument() {
    if kan().is_none() {
        return;
    }
    let repo = Repo::new();
    repo.run(&["observe", "s", "seed"]);
    let out = repo.run(&["identity", "restore", "abandon", "abandon", "art"]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("must not be passed on the command line"),
        "must refuse argv: {err}"
    );
    assert!(
        err.contains("shell history"),
        "must say why, or it reads as pedantry: {err}"
    );
}

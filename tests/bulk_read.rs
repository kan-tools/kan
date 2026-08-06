//! #123 / `.design/kan-read-contract.md` REQ-5 — every subject's live claims
//! from one invocation.
//!
//! The ask was explicitly to reduce the invocation *count*, not to make reads
//! faster, and the measurement in #123 is why: `day status` spent 1.99s of
//! 2.76s inside 41 `kan` invocations, and that cost is `Workspace::open` —
//! an empty log costs ~30ms per call, and `kan identity did`, which reads no
//! log at all, costs the same. No optimisation *inside* a read touches it.
//!
//! So the property under test is agreement, not speed: one invocation must
//! return exactly what forty-one returned, or the fast path is a different
//! answer wearing the same name.

use std::process::Command;

fn kan(dir: &std::path::Path, key: &std::path::Path, args: &[&str]) -> (String, bool) {
    let output = Command::new(env!("CARGO_BIN_EXE_kan"))
        .args(args)
        .current_dir(dir)
        .env("KAN_IDENTITY_FILE", key)
        .env("KAN_NO_KEYCHAIN", "1")
        .output()
        .expect("failed to run kan binary");
    (
        String::from_utf8_lossy(&output.stdout).trim().to_string(),
        output.status.success(),
    )
}

fn git_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let status = Command::new("git")
            .args(args)
            .current_dir(dir.path())
            .status()
            .expect("failed to run git");
        assert!(status.success(), "git {args:?} failed");
    };
    run(&["init", "-q"]);
    run(&[
        "-c",
        "user.email=kan-test@example.com",
        "-c",
        "user.name=kan-test",
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        "init",
    ]);
    dir
}

/// A log with the shapes that could make a bulk read diverge: several
/// subjects, a merged pair, a retraction, a relation, and a status.
fn varied_log() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = git_repo();
    let key = dir.path().join("key");
    { std::fs::create_dir_all(key.parent().unwrap()).unwrap(); kan::sign::Identity::generate().save(&key).unwrap(); }
    let k = |args: &[&str]| {
        let (out, ok) = kan(dir.path(), &key, args);
        assert!(ok, "{args:?} failed: {out}");
        out
    };

    for i in 1..=5 {
        for j in 1..=3 {
            k(&[
                "observe",
                &format!("subject-{i}"),
                &format!("claim {j} on subject {i}"),
            ]);
        }
    }
    // A retraction: its target must be absent from both paths alike.
    let doomed = k(&["observe", "subject-1", "this one gets retracted"]);
    k(&["retract", &doomed]);
    // A merge, so a class spans two names.
    k(&["same", "subject-2", "subject-3"]);
    // A relation, so `inbound` is populated on the target.
    k(&["relate", "subject-4", "blocks", "subject-5"]);
    // A status, so `superseded` marking is exercised.
    k(&["mark", "subject-4", "blocked"]);
    k(&["mark", "subject-4", "resolved"]);
    (dir, key)
}

/// `.design/kan-read-contract.md` AC-5: one bulk invocation returns the live
/// claims of every subject a per-subject sweep would, with the same claim
/// fields.
///
/// Compared CID-for-CID rather than by count, because two responses can agree
/// on how many claims exist and disagree on which — and a consumer building
/// its whole claim graph from the fast path would inherit that silently.
#[test]
fn the_bulk_read_agrees_claim_for_claim_with_a_per_subject_sweep() {
    let (dir, key) = varied_log();

    // The slow path, as day does it today: enumerate subjects, then show each.
    let (status, ok) = kan(dir.path(), &key, &["status", "--json"]);
    assert!(ok);
    let status: serde_json::Value = serde_json::from_str(&status).unwrap();
    let names: Vec<String> = status["subjects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["subject"].as_str().unwrap().to_string())
        .collect();
    assert!(names.len() >= 4, "expected a few subjects: {names:?}");

    let mut sweep: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    for name in &names {
        let (out, ok) = kan(dir.path(), &key, &["show", name, "--json"]);
        assert!(ok, "show {name} failed");
        let one: serde_json::Value = serde_json::from_str(&out).unwrap();
        let cids: Vec<String> = one["claims"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["cid"].as_str().unwrap().to_string())
            .collect();
        sweep.insert(name.clone(), cids);
    }

    // The fast path.
    let (out, ok) = kan(dir.path(), &key, &["show", "--all", "--json"]);
    assert!(ok, "bulk read failed: {out}");
    let all: serde_json::Value = serde_json::from_str(&out).unwrap();
    let mut bulk: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    for entry in all["subjects"].as_array().unwrap() {
        let cids: Vec<String> = entry["claims"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["cid"].as_str().unwrap().to_string())
            .collect();
        bulk.insert(entry["subject"].as_str().unwrap().to_string(), cids);
    }

    assert_eq!(
        sweep.keys().collect::<Vec<_>>(),
        bulk.keys().collect::<Vec<_>>(),
        "the two paths disagree about which subjects exist"
    );
    for (name, expected) in &sweep {
        assert_eq!(
            bulk.get(name),
            Some(expected),
            "subject {name}: the bulk read returned different claims than `show` did"
        );
    }
}

/// Each entry is a full `ShowJson`, so a consumer already parsing `show
/// --json` parses these unchanged.
///
/// That reuse is the deliberate trade: repeating `trust` per entry costs a few
/// hundred bytes and saves day writing a second parser, and the ask was to
/// reduce invocation count rather than payload size.
#[test]
fn each_entry_is_shaped_exactly_like_a_single_show() {
    let (dir, key) = varied_log();
    let (single, _) = kan(dir.path(), &key, &["show", "subject-1", "--json"]);
    let single: serde_json::Value = serde_json::from_str(&single).unwrap();
    let single_keys: std::collections::BTreeSet<&String> =
        single.as_object().unwrap().keys().collect();

    let (all, _) = kan(dir.path(), &key, &["show", "--all", "--json"]);
    let all: serde_json::Value = serde_json::from_str(&all).unwrap();
    let entry = &all["subjects"].as_array().unwrap()[0];
    let entry_keys: std::collections::BTreeSet<&String> =
        entry.as_object().unwrap().keys().collect();

    assert_eq!(
        single_keys, entry_keys,
        "a bulk entry is not shaped like a single show -- day would need a second parser"
    );

    // The envelope carries the version and the shared trust base too.
    assert_eq!(all["v"], single["v"]);
    assert_eq!(all["trust"], single["trust"]);
    assert!(all["excluded_by_trust"].is_number());
}

/// The bulk read honours `--trust` like every other read verb, and reports
/// exclusions across the whole log.
#[test]
fn the_bulk_read_honours_the_trust_selector() {
    let dir = git_repo();
    let a = dir.path().join("a");
    { std::fs::create_dir_all(a.parent().unwrap()).unwrap(); kan::sign::Identity::generate().save(&a).unwrap(); }
    let b = dir.path().join("b");
    { std::fs::create_dir_all(b.parent().unwrap()).unwrap(); kan::sign::Identity::generate().save(&b).unwrap(); }
    // Both minted while the log is empty, so neither trips the #90 guard.
    for key in [&a, &b] {
        assert!(kan(dir.path(), key, &["identity", "did"]).1);
    }
    assert!(kan(dir.path(), &a, &["observe", "shared", "from a"]).1);
    assert!(kan(dir.path(), &b, &["observe", "shared", "from b"]).1);

    // v0.11 (`.design/identity-surface.md` REQ-1): the default base is
    // `Local`, so both authors are visible with no `--trust` argument and
    // nothing is excluded. This assertion previously read `Solo` / 1
    // excluded, which was #121's defect stated as an expectation -- two role
    // identities writing to one log, each seeing only itself.
    let (default, _) = kan(dir.path(), &a, &["show", "--all", "--json"]);
    let default: serde_json::Value = serde_json::from_str(&default).unwrap();
    assert_eq!(default["trust"]["base"], "Local");
    assert_eq!(
        default["excluded_by_trust"], 0,
        "nothing in the log should be excluded under Local: {default}"
    );
    let default_claims = default["subjects"].as_array().unwrap()[0]["claims"]
        .as_array()
        .unwrap();
    assert_eq!(
        default_claims.len(),
        2,
        "the default read should return both log authors' claims: {default}"
    );

    // `--trust me` is where the old default went, and it still narrows.
    let (mine, _) = kan(
        dir.path(),
        &a,
        &["show", "--all", "--json", "--trust", "me"],
    );
    let mine: serde_json::Value = serde_json::from_str(&mine).unwrap();
    assert_eq!(
        mine["excluded_by_trust"], 1,
        "`--trust me` should still exclude the other author, and disclose it: {mine}"
    );

    let b_did = kan(dir.path(), &b, &["identity", "did"]).0;
    let a_did = kan(dir.path(), &a, &["identity", "did"]).0;
    let (both, ok) = kan(
        dir.path(),
        &a,
        &[
            "show", "--all", "--json", "--trust", &a_did, "--trust", &b_did,
        ],
    );
    assert!(ok);
    let both: serde_json::Value = serde_json::from_str(&both).unwrap();
    assert_eq!(both["trust"]["base"], "PeerContested");
    assert_eq!(both["excluded_by_trust"], 0);
    let claims = both["subjects"].as_array().unwrap()[0]["claims"]
        .as_array()
        .unwrap();
    assert_eq!(claims.len(), 2, "expected both authors' claims: {both}");
}

/// `--all` without `--json` is refused rather than rendering forty subjects'
/// full claim histories at a terminal, and `show` with neither a subject nor
/// `--all` says what to type.
#[test]
fn the_bulk_read_refuses_shapes_that_would_not_help_anyone() {
    let (dir, key) = varied_log();

    let (_, ok) = kan(dir.path(), &key, &["show", "--all"]);
    assert!(!ok, "`--all` without `--json` should be refused");

    let (_, ok) = kan(dir.path(), &key, &["show"]);
    assert!(!ok, "`show` with no subject and no --all should be refused");

    // And the two are mutually exclusive at the parser, so there is no
    // ambiguous third shape to reason about.
    let (_, ok) = kan(dir.path(), &key, &["show", "subject-1", "--all", "--json"]);
    assert!(!ok, "`--all` with a subject should be rejected by clap");
}

/// #143, asked from the day side: can `show --all` omit a subject it could
/// not read?
///
/// **No — and the reason is structural rather than careful.** `show_all_json`
/// makes exactly one read (`all_stored_claims()?`) and then maps over the
/// folded merge classes. There is no per-subject operation that could fail
/// for one subject and succeed for the rest, so the only two outcomes are a
/// complete answer or a propagated error. That is the guarantee day wanted
/// stated (ADR-81), and this pins it: the subject set of `show --all` must
/// equal the subject set of `status`, always.
#[test]
fn show_all_never_omits_a_subject_that_status_reports() {
    let dir = git_repo();
    let key = dir.path().join("key");
    { std::fs::create_dir_all(key.parent().unwrap()).unwrap(); kan::sign::Identity::generate().save(&key).unwrap(); }

    for s in ["alpha", "beta", "gamma/nested", "delta with spaces"] {
        let (_, ok) = kan(dir.path(), &key, &["observe", "a claim", "--subject", s]);
        assert!(ok, "setup write failed for {s}");
    }

    let (status_out, ok) = kan(dir.path(), &key, &["status", "--json"]);
    assert!(ok, "status --json failed");
    let (show_out, ok) = kan(dir.path(), &key, &["show", "--all", "--json"]);
    assert!(ok, "show --all --json failed");

    let names = |json: &str, field: &str| -> Vec<String> {
        let v: serde_json::Value = serde_json::from_str(json).expect("valid json");
        let mut out: Vec<String> = v[field]
            .as_array()
            .expect("array")
            .iter()
            .map(|e| e["subject"].as_str().unwrap_or_default().to_string())
            .collect();
        out.sort();
        out
    };

    assert_eq!(
        names(&status_out, "subjects"),
        names(&show_out, "subjects"),
        "show --all and status disagree about which subjects exist"
    );
}

/// The second assumption day's mitigation rests on, stated in #143: a subject
/// cannot become absent by having its claims retracted, because a
/// `Retraction` is itself a claim on that subject.
///
/// Worth pinning rather than reasoning about — day's unaccounted-for check
/// produces false positives the moment it stops holding.
#[test]
fn retracting_a_subjects_only_claim_does_not_remove_the_subject() {
    let dir = git_repo();
    let key = dir.path().join("key");
    { std::fs::create_dir_all(key.parent().unwrap()).unwrap(); kan::sign::Identity::generate().save(&key).unwrap(); }

    let (cid, ok) = kan(
        dir.path(),
        &key,
        &["observe", "the only claim", "--subject", "solo"],
    );
    assert!(ok, "setup write failed");

    let (_, ok) = kan(dir.path(), &key, &["retract", cid.trim()]);
    assert!(ok, "retract failed");

    let (show_out, ok) = kan(dir.path(), &key, &["show", "--all", "--json"]);
    assert!(ok, "show --all --json failed after retraction");
    assert!(
        show_out.contains("solo"),
        "the subject vanished after its only claim was retracted: {show_out}"
    );
}

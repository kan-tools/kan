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
    {
        std::fs::create_dir_all(key.parent().unwrap()).unwrap();
        kan::sign::Identity::generate().save(&key).unwrap();
    }
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

/// Each entry carries the subject-view subset of `ShowJson`, so a consumer
/// already parsing `show --json` parses it unchanged. Workspace-open metadata
/// lives once on the bulk envelope rather than being repeated per subject.
///
/// That reuse is the deliberate trade: repeating `trust` per entry costs a few
/// hundred bytes and saves day writing a second parser, and the ask was to
/// reduce invocation count rather than payload size.
#[test]
fn each_entry_is_shaped_exactly_like_a_single_show() {
    let (dir, key) = varied_log();
    let (single, _) = kan(dir.path(), &key, &["show", "subject-1", "--json"]);
    let single: serde_json::Value = serde_json::from_str(&single).unwrap();
    let mut single_keys: std::collections::BTreeSet<&String> =
        single.as_object().unwrap().keys().collect();
    single_keys.remove(&"published_read_error_count".to_string());
    single_keys.remove(&"published_read_errors".to_string());

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
    assert!(all["published_read_error_count"].is_number());
    assert!(all["published_read_errors"].is_array());
    assert!(entry.get("published_read_error_count").is_none());
    assert!(entry.get("published_read_errors").is_none());
}

/// The bulk read honours `--trust` like every other read verb, and reports
/// exclusions across the whole log.
#[test]
fn the_bulk_read_honours_the_trust_selector() {
    let dir = git_repo();
    let a = dir.path().join("a");
    {
        std::fs::create_dir_all(a.parent().unwrap()).unwrap();
        kan::sign::Identity::generate().save(&a).unwrap();
    }
    let b = dir.path().join("b");
    {
        std::fs::create_dir_all(b.parent().unwrap()).unwrap();
        kan::sign::Identity::generate().save(&b).unwrap();
    }
    // Both minted while the log is empty, so neither trips the #90 guard.
    for key in [&a, &b] {
        assert!(kan(dir.path(), key, &["identity", "did"]).1);
    }
    assert!(kan(dir.path(), &a, &["observe", "shared", "from a"]).1);
    assert!(kan(dir.path(), &b, &["observe", "shared", "from b"]).1);
    assert!(kan(dir.path(), &b, &["observe", "secret/only-b", "hidden"]).1);

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
    let default_claims = default["subjects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["subject"] == "shared")
        .unwrap()["claims"]
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
        mine["excluded_by_trust"], 2,
        "`--trust me` should still exclude the other author, and disclose it: {mine}"
    );

    let (default_status, ok) = kan(dir.path(), &a, &["status", "--json"]);
    assert!(ok);
    let default_status: serde_json::Value = serde_json::from_str(&default_status).unwrap();
    let (mine_status, ok) = kan(dir.path(), &a, &["status", "--json", "--trust", "me"]);
    assert!(ok);
    let mine_status: serde_json::Value = serde_json::from_str(&mine_status).unwrap();
    let shared = |status: &serde_json::Value| -> serde_json::Value {
        status["subjects"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["subject"] == "shared")
            .unwrap()
            .clone()
    };
    assert_eq!(shared(&default_status)["claim_count"], 2);
    assert_eq!(shared(&mine_status)["claim_count"], 1);
    assert_ne!(
        shared(&default_status)["revision"],
        shared(&mine_status)["revision"]
    );
    assert_ne!(default_status["revision"], mine_status["revision"]);
    assert!(
        !mine_status.to_string().contains("secret/only-b"),
        "status manifest leaked a wholly excluded subject name: {mine_status}"
    );

    let (selected, ok) = kan(
        dir.path(),
        &a,
        &["show", "--json", "--prefix", "secret/", "--trust", "me"],
    );
    assert!(ok);
    let selected: serde_json::Value = serde_json::from_str(&selected).unwrap();
    assert_eq!(selected["matched_subjects"], 0);
    assert_eq!(selected["excluded_by_trust"], 2);
    assert!(
        !selected.to_string().contains("secret/only-b"),
        "prefix selection leaked a wholly excluded subject name: {selected}"
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
    let claims = both["subjects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["subject"] == "shared")
        .unwrap()["claims"]
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
    {
        std::fs::create_dir_all(key.parent().unwrap()).unwrap();
        kan::sign::Identity::generate().save(&key).unwrap();
    }

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
    {
        std::fs::create_dir_all(key.parent().unwrap()).unwrap();
        kan::sign::Identity::generate().save(&key).unwrap();
    }

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

/// kan#232: selected hydration is not a second interpretation of `show`.
/// It is client-side filtering of the complete bulk response, performed
/// before serialization and without another workspace open.
#[test]
fn selected_bulk_entries_equal_client_side_filtering() {
    let (dir, key) = varied_log();
    let (all, ok) = kan(dir.path(), &key, &["show", "--all", "--json"]);
    assert!(ok, "show --all failed: {all}");
    let all: serde_json::Value = serde_json::from_str(&all).unwrap();

    let (selected, ok) = kan(
        dir.path(),
        &key,
        &[
            "show",
            "--json",
            "--subject",
            "subject-2",
            "--prefix",
            "subject-4",
        ],
    );
    assert!(ok, "selected show failed: {selected}");
    let selected: serde_json::Value = serde_json::from_str(&selected).unwrap();

    let expected: Vec<serde_json::Value> = all["subjects"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| {
            entry["subjects"].as_array().unwrap().iter().any(|name| {
                let name = name.as_str().unwrap();
                name == "subject-2" || name.starts_with("subject-4")
            })
        })
        .cloned()
        .collect();
    assert_eq!(selected["subjects"], serde_json::Value::Array(expected));
    assert_eq!(
        selected["visible_subjects"],
        all["subjects"].as_array().unwrap().len()
    );
    assert_eq!(selected["matched_subjects"], 2);
}

#[test]
fn selectors_match_aliases_deduplicate_and_keep_external_inbound_edges() {
    let (dir, key) = varied_log();

    // subject-3 is an alias of subject-2. Exact + overlapping prefix must
    // still return that folded class once, under show-all's primary label.
    let (merged, ok) = kan(
        dir.path(),
        &key,
        &[
            "show",
            "--json",
            "--subject",
            "subject-3",
            "--prefix",
            "subject-",
            "--subject",
            "subject-2",
        ],
    );
    assert!(ok, "selected alias show failed: {merged}");
    let merged: serde_json::Value = serde_json::from_str(&merged).unwrap();
    let matching: Vec<&serde_json::Value> = merged["subjects"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| {
            entry["subjects"]
                .as_array()
                .unwrap()
                .iter()
                .any(|name| name == "subject-3")
        })
        .collect();
    assert_eq!(matching.len(), 1, "merged class was duplicated: {merged}");
    assert_eq!(matching[0]["subject"], "subject-2");

    // subject-4 points at subject-5. Selecting only the target must retain
    // the inbound edge from the unselected source.
    let (target, ok) = kan(
        dir.path(),
        &key,
        &["show", "--json", "--subject", "subject-5"],
    );
    assert!(ok, "selected target show failed: {target}");
    let target: serde_json::Value = serde_json::from_str(&target).unwrap();
    assert_eq!(target["matched_subjects"], 1);
    let inbound = target["subjects"][0]["inbound"].as_array().unwrap();
    assert!(
        inbound.iter().any(|edge| edge["source"] == "subject-4"),
        "inbound edge from unselected source disappeared: {target}"
    );
}

#[test]
fn selected_bulk_reports_zero_matches_explicitly() {
    let (dir, key) = varied_log();
    let (out, ok) = kan(
        dir.path(),
        &key,
        &["show", "--json", "--prefix", "does-not-exist/"],
    );
    assert!(ok, "zero-match selection failed: {out}");
    let out: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(out["matched_subjects"], 0);
    assert!(out["visible_subjects"].as_u64().unwrap() > 0);
    assert_eq!(out["subjects"], serde_json::json!([]));
}

#[test]
fn status_manifest_agrees_with_bulk_show_and_revisions_are_stable() {
    let (dir, key) = varied_log();
    let read = || {
        let (status, ok) = kan(dir.path(), &key, &["status", "--json"]);
        assert!(ok, "status failed: {status}");
        let (all, ok) = kan(dir.path(), &key, &["show", "--all", "--json"]);
        assert!(ok, "show --all failed: {all}");
        (
            serde_json::from_str::<serde_json::Value>(&status).unwrap(),
            serde_json::from_str::<serde_json::Value>(&all).unwrap(),
        )
    };

    let (before, all) = read();
    for row in before["subjects"].as_array().unwrap() {
        let shown = all["subjects"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["subject"] == row["subject"])
            .unwrap();
        let claims = shown["claims"].as_array().unwrap();
        assert_eq!(row["claim_count"], claims.len());
        assert_eq!(row["head"]["cid"], claims.last().unwrap()["cid"]);

        let mut expected = std::collections::BTreeMap::<String, usize>::new();
        for claim in claims {
            *expected
                .entry(claim["kind"].as_str().unwrap().to_string())
                .or_default() += 1;
        }
        assert_eq!(row["kind_counts"], serde_json::to_value(expected).unwrap());
        let revision = row["revision"].as_str().unwrap();
        assert!(revision.starts_with("sha256:"));
        assert_eq!(revision.len(), 71);
    }
    assert_eq!(before["revision"].as_str().unwrap().len(), 71);

    let (repeated, _) = read();
    assert_eq!(before["revision"], repeated["revision"]);
    assert_eq!(before["subjects"], repeated["subjects"]);

    let old_row = before["subjects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["subject"] == "subject-1")
        .unwrap()["revision"]
        .clone();
    let (_, ok) = kan(
        dir.path(),
        &key,
        &["observe", "subject-1", "a narrative-only append"],
    );
    assert!(ok);
    let (after, _) = read();
    assert_ne!(before["revision"], after["revision"]);
    let new_row = &after["subjects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["subject"] == "subject-1")
        .unwrap()["revision"];
    assert_ne!(&old_row, new_row);
}

#[test]
fn whole_view_revision_is_scoped_to_the_named_trust_frame() {
    let (dir, key) = varied_log();
    let (local, ok) = kan(dir.path(), &key, &["status", "--json"]);
    assert!(ok);
    let (solo, ok) = kan(dir.path(), &key, &["status", "--json", "--trust", "me"]);
    assert!(ok);
    let local: serde_json::Value = serde_json::from_str(&local).unwrap();
    let solo: serde_json::Value = serde_json::from_str(&solo).unwrap();
    assert_eq!(local["subjects"], solo["subjects"]);
    assert_ne!(local["trust"]["base"], solo["trust"]["base"]);
    assert_ne!(local["revision"], solo["revision"]);
}

#[test]
fn selected_bulk_has_one_whole_read_and_no_per_subject_read_loop() {
    let source = std::fs::read_to_string("src/actions.rs").unwrap();
    let selected = source
        .split("pub fn show_selected_json")
        .nth(1)
        .unwrap()
        .split("/// `kan status")
        .next()
        .unwrap();
    assert_eq!(selected.matches("all_stored_claims()?").count(), 1);
    assert_eq!(selected.matches("fold::fold(").count(), 1);
    assert!(
        !selected.contains("view.subject(") && !selected.contains("show_json("),
        "selected hydration introduced a fallible per-subject read: {selected}"
    );
}

#[tokio::test]
async fn selected_bulk_propagates_a_whole_read_failure_without_partial_json() {
    let (dir, key) = varied_log();
    let workspace = kan::workspace::Workspace::open(dir.path()).await.unwrap();
    let claims = workspace.index.all_stored_claims().unwrap();
    let trust = kan::fold::TrustBase::local(
        claims
            .iter()
            .map(|(_, stored)| stored.claim.content.author.clone()),
    );
    let connection = rusqlite::Connection::open(dir.path().join(".kan/index.sqlite")).unwrap();
    connection
        .execute("UPDATE claims_v2 SET raw = X'00'", [])
        .unwrap();

    let result =
        kan::actions::show_selected_json(&workspace, &["subject-1".to_string()], &[], &trust, None);
    let error = result.expect_err("a corrupt whole read must fail selected hydration");
    assert!(
        !error.to_string().contains("subjects"),
        "failure was disguised as a partial subjects response: {error}"
    );
    drop(key);
}

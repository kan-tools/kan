//! `.design/v0.8-milestone.md` REQ-4/REQ-6, AC-4/AC-6 — several signing
//! identities against one workspace, by explicit opt-in, and a read that
//! actually shows them all.
//!
//! This is the milestone requirement that dogfooding rescued from being
//! filed as documentation. Two `KAN_IDENTITY_FILE` roles against one
//! workspace fail in two independent ways: the `WouldMintSecondIdentity`
//! guard refuses the second role's first write once the log is non-empty,
//! and even when both roles do append, the default `Solo` fold shows each
//! role only its own claims. Neither is fixed by explaining it better.

use std::process::Command;

fn kan_as(dir: &std::path::Path, key: Option<&std::path::Path>, args: &[&str]) -> Run {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kan"));
    cmd.args(args).current_dir(dir);
    match key {
        Some(k) => {
            cmd.env("KAN_IDENTITY_FILE", k);
        }
        None => {
            cmd.env_remove("KAN_IDENTITY_FILE");
        }
    }
    let output = cmd.output().expect("failed to run kan binary");
    Run {
        stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ok: output.status.success(),
    }
}

struct Run {
    stdout: String,
    stderr: String,
    ok: bool,
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

/// A workspace whose primary identity has already written, so the log is
/// non-empty — the state in which the guard fires, and therefore the only
/// state in which the opt-in means anything.
fn workspace_with_claims() -> tempfile::TempDir {
    let dir = git_repo();
    let run = kan_as(
        dir.path(),
        None,
        &["observe", "shared", "the primary identity's claim"],
    );
    assert!(run.ok, "primary write failed: {}", run.stderr);
    dir
}

/// AC-4, first half: a declared role writes to a workspace whose log is
/// already non-empty, and both identities' claims are attributed.
#[test]
fn a_declared_role_may_write_to_a_non_empty_workspace() {
    let dir = workspace_with_claims();
    let key = dir.path().join("keys/director");

    let add = kan_as(
        dir.path(),
        None,
        &[
            "identity",
            "role",
            "add",
            "director",
            "--key",
            key.to_str().unwrap(),
        ],
    );
    assert!(add.ok, "role add failed: {}", add.stderr);
    assert!(add.stdout.contains("declared role `director`"));

    // The write the guard used to refuse.
    let write = kan_as(
        dir.path(),
        Some(&key),
        &["observe", "shared", "the director's claim"],
    );
    assert!(
        write.ok,
        "a declared role was still refused: {}",
        write.stderr
    );
}

/// AC-4's **negative control**, and the point of the whole design: without
/// the opt-in, a second identity against a non-empty log is still refused.
///
/// This is what proves the opt-in — rather than a weakening of the guard —
/// is what enables multi-role. The guard exists because a silently-minted
/// second identity took a whole log out of every read at exit 0 (#90); if
/// declaring a role were merely cosmetic, that failure would be back.
#[test]
fn an_undeclared_second_identity_is_still_refused() {
    let dir = workspace_with_claims();
    let undeclared = dir.path().join("keys/undeclared");

    let run = kan_as(
        dir.path(),
        Some(&undeclared),
        &["observe", "shared", "a claim from nowhere"],
    );
    assert!(
        !run.ok,
        "an undeclared second identity was allowed to write -- the #90 guard is gone"
    );
    assert!(
        run.stderr.contains("second identity"),
        "refusal did not name the reason: {}",
        run.stderr
    );
    // The refusal points at the supported path rather than only saying no.
    assert!(
        run.stderr.contains("kan identity role add"),
        "refusal did not point at the opt-in: {}",
        run.stderr
    );
    assert!(
        !undeclared.exists(),
        "a refused write still created the key file"
    );
}

/// AC-6: in a workspace with prover and director roles, a `PeerContested`
/// read shows **both** roles' live claims attributed, where the `Solo`
/// default shows only the active identity's.
///
/// This is the exact dogfooded gap, and the research loop's TIER 1: for a
/// director/prover loop, a read that silently drops the other role's claims
/// presents as data loss.
#[test]
fn peer_contested_over_roles_shows_every_role_where_solo_shows_one() {
    let dir = git_repo();
    let prover = dir.path().join("keys/prover");
    let director = dir.path().join("keys/director");

    for (name, key) in [("prover", &prover), ("director", &director)] {
        let add = kan_as(
            dir.path(),
            None,
            &[
                "identity",
                "role",
                "add",
                name,
                "--key",
                key.to_str().unwrap(),
            ],
        );
        assert!(add.ok, "role add {name} failed: {}", add.stderr);
    }

    for (key, text) in [
        (&prover, "the prover's evidence"),
        (&director, "the director's verdict"),
    ] {
        let run = kan_as(dir.path(), Some(key), &["observe", "finding", text]);
        assert!(run.ok, "role write failed: {}", run.stderr);
    }

    // Solo (the default): one claim, and the disclosure that says so.
    let solo = kan_as(dir.path(), Some(&prover), &["show", "finding", "--json"]);
    assert!(solo.ok);
    let solo: serde_json::Value = serde_json::from_str(&solo.stdout).unwrap();
    assert_eq!(solo["claims"].as_array().unwrap().len(), 1);
    assert_eq!(
        solo["excluded_by_trust"], 1,
        "the Solo view hid a role's claim without saying so: {solo}"
    );

    // `--trust roles`: every declared role, attributed.
    let all = kan_as(
        dir.path(),
        Some(&prover),
        &["show", "finding", "--trust", "roles", "--json"],
    );
    assert!(all.ok, "--trust roles failed");
    let all: serde_json::Value = serde_json::from_str(&all.stdout).unwrap();
    let texts: Vec<&str> = all["claims"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["text"].as_str().unwrap_or(""))
        .collect();
    assert_eq!(texts.len(), 2, "expected both roles' claims: {all}");
    assert!(texts.contains(&"the prover's evidence"));
    assert!(texts.contains(&"the director's verdict"));
    assert_eq!(all["excluded_by_trust"], 0);

    // Attribution is per-claim, not merely "two claims arrived".
    let authors: std::collections::HashSet<&str> = all["claims"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["author"].as_str().unwrap())
        .collect();
    assert_eq!(authors.len(), 2, "both claims share one author: {all}");
}

/// `--trust roles` includes the **active** identity, not only the declared
/// roles. Leaving it out would make the obvious command quietly drop the
/// caller's own claims — a smaller instance of the bug this milestone fixes.
#[test]
fn trust_roles_includes_the_active_identity() {
    let dir = workspace_with_claims(); // primary identity wrote "shared"
    let key = dir.path().join("keys/director");
    let add = kan_as(
        dir.path(),
        None,
        &[
            "identity",
            "role",
            "add",
            "director",
            "--key",
            key.to_str().unwrap(),
        ],
    );
    assert!(add.ok);
    let write = kan_as(
        dir.path(),
        Some(&key),
        &["observe", "shared", "the director's claim"],
    );
    assert!(write.ok);

    // Read as the *primary* identity, which is not itself a declared role.
    let all = kan_as(
        dir.path(),
        None,
        &["show", "shared", "--trust", "roles", "--json"],
    );
    assert!(all.ok);
    let all: serde_json::Value = serde_json::from_str(&all.stdout).unwrap();
    assert_eq!(
        all["claims"].as_array().unwrap().len(),
        2,
        "`--trust roles` dropped the active identity's own claims: {all}"
    );
}

/// Q2 of the milestone's open questions, settled empirically rather than by
/// argument: **one shared `.kan/log` for all roles**, not a log per role.
///
/// The concern is that the commit chain is signed by whichever identity made
/// each commit — `Log` takes the opening identity's DID and stamps it into
/// every `Commit` it writes, so a shared log's chain has a heterogeneous
/// `did` field. This asserts that costs nothing where it matters: the fold
/// reads *claim* authors, and `Log::get_stored` verifies each record against
/// **its own** author, so nothing on the read path consults a commit signer
/// at all.
///
/// Interleaved deliberately (A, B, A, B). Alternating writers is where a
/// shared log would break if it were going to: each process reopens from
/// disk per invocation, so a lost `reload_if_stale` would show up as one
/// role's claims overwriting the other's rather than as an error.
#[test]
fn one_shared_log_survives_roles_writing_alternately() {
    let dir = git_repo();
    let a = dir.path().join("keys/a");
    let b = dir.path().join("keys/b");
    for (name, key) in [("a", &a), ("b", &b)] {
        let add = kan_as(
            dir.path(),
            None,
            &[
                "identity",
                "role",
                "add",
                name,
                "--key",
                key.to_str().unwrap(),
            ],
        );
        assert!(add.ok, "role add {name} failed: {}", add.stderr);
    }

    for (i, key) in [(&a), (&b), (&a), (&b)].into_iter().enumerate() {
        let text = format!("claim number {i}");
        let run = kan_as(dir.path(), Some(key), &["observe", "interleaved", &text]);
        assert!(run.ok, "write {i} failed: {}", run.stderr);
    }

    let all = kan_as(
        dir.path(),
        Some(&a),
        &["show", "interleaved", "--trust", "roles", "--json"],
    );
    assert!(all.ok, "read failed: {}", all.stderr);
    let all: serde_json::Value = serde_json::from_str(&all.stdout).unwrap();
    let texts: Vec<&str> = all["claims"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["text"].as_str().unwrap_or(""))
        .collect();
    assert_eq!(
        texts.len(),
        4,
        "a shared log lost claims across alternating writers: {all}"
    );
    for i in 0..4 {
        assert!(
            texts.contains(&format!("claim number {i}").as_str()),
            "claim {i} vanished: {all}"
        );
    }

    // Every record still verifies against its own author after four writes
    // by two identities — `show` returning them at all is that proof, since
    // the read path verifies each record and errors rather than skipping.
    let authors: std::collections::HashSet<&str> = all["claims"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["author"].as_str().unwrap())
        .collect();
    assert_eq!(authors.len(), 2, "expected two distinct claim authors");
}

/// The declared role set is readable back, so an operator (or day) can
/// discover which identities a workspace expects rather than keeping the
/// list somewhere else.
#[test]
fn declared_roles_are_listed_with_their_dids() {
    let dir = workspace_with_claims();
    let key = dir.path().join("keys/director");
    let add = kan_as(
        dir.path(),
        None,
        &[
            "identity",
            "role",
            "add",
            "director",
            "--key",
            key.to_str().unwrap(),
        ],
    );
    assert!(add.ok);

    let listed = kan_as(dir.path(), None, &["identity", "role", "list", "--json"]);
    assert!(listed.ok);
    let listed: serde_json::Value = serde_json::from_str(&listed.stdout).unwrap();
    assert_eq!(listed["roles"].as_array().unwrap().len(), 1);
    assert_eq!(listed["roles"][0]["name"], "director");
    assert!(listed["roles"][0]["did"]
        .as_str()
        .unwrap()
        .starts_with("did:key:"));
    // The active identity is reported separately from the declared roles:
    // "who am I writing as" and "who has this workspace declared" are
    // different questions.
    assert!(listed["active"].as_str().unwrap().starts_with("did:key:"));
    assert_ne!(listed["active"], listed["roles"][0]["did"]);
}

/// Declaring a role is idempotent on the key: re-running against an existing
/// key file loads it rather than overwriting, so a repeated `role add` can
/// never destroy a signing key. The duplicate *registration* is what is
/// refused.
#[test]
fn re_declaring_a_role_never_overwrites_its_key() {
    let dir = workspace_with_claims();
    let key = dir.path().join("keys/director");
    let first = kan_as(
        dir.path(),
        None,
        &[
            "identity",
            "role",
            "add",
            "director",
            "--key",
            key.to_str().unwrap(),
        ],
    );
    assert!(first.ok);
    let did_before = kan_as(dir.path(), Some(&key), &["identity", "did"]).stdout;

    // Same name: refused as a name clash.
    let again = kan_as(
        dir.path(),
        None,
        &[
            "identity",
            "role",
            "add",
            "director",
            "--key",
            key.to_str().unwrap(),
        ],
    );
    assert!(!again.ok, "duplicate role name was accepted");

    // Different name, same key: refused as an already-registered identity —
    // one DID under two role names would make attribution ambiguous.
    let aliased = kan_as(
        dir.path(),
        None,
        &[
            "identity",
            "role",
            "add",
            "reviewer",
            "--key",
            key.to_str().unwrap(),
        ],
    );
    assert!(!aliased.ok, "one identity was registered under two names");

    let did_after = kan_as(dir.path(), Some(&key), &["identity", "did"]).stdout;
    assert_eq!(
        did_before, did_after,
        "a repeated `role add` changed the role's signing key"
    );
}

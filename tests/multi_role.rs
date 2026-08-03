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

/// v0.11 AC-2 — #121's reproduction, and the assertion this test used to
/// make in reverse.
///
/// In a workspace with prover and director roles, the **default** read now
/// shows both roles' live claims attributed, from either role and with no
/// `--trust` argument. Until v0.11 the default was `Solo`, so this test
/// asserted that the default showed *one* claim and disclosed the exclusion
/// — the dogfooded gap that presents as data loss in a director/prover loop.
/// v0.8 made it visible; v0.11 removes it.
///
/// `--trust me` is where that narrow frame went, and it is still exact.
#[test]
fn the_default_read_shows_every_role_where_trust_me_shows_one() {
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

    // The default (`Local`): both claims, from *either* role, nothing hidden.
    for (who, key) in [("prover", &prover), ("director", &director)] {
        let default = kan_as(dir.path(), Some(key), &["show", "finding", "--json"]);
        assert!(
            default.ok,
            "default read as {who} failed: {}",
            default.stderr
        );
        let default: serde_json::Value = serde_json::from_str(&default.stdout).unwrap();
        assert_eq!(
            default["trust"]["base"], "Local",
            "the default base should be Local: {default}"
        );
        assert_eq!(
            default["claims"].as_array().unwrap().len(),
            2,
            "the default read as {who} dropped the other role's claim -- this is #121: \
             {default}"
        );
        assert_eq!(default["excluded_by_trust"], 0);
    }

    // `--trust me`: the old default, still exact, still disclosing.
    let mine = kan_as(
        dir.path(),
        Some(&prover),
        &["show", "finding", "--trust", "me", "--json"],
    );
    assert!(mine.ok);
    let mine: serde_json::Value = serde_json::from_str(&mine.stdout).unwrap();
    assert_eq!(mine["claims"].as_array().unwrap().len(), 1);
    assert_eq!(
        mine["excluded_by_trust"], 1,
        "`--trust me` hid a role's claim without saying so: {mine}"
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

/// Found by dogfooding the real director/prover loop, not by a test that
/// was designed for it: `--trust roles`, read **as a role**, must still show
/// claims the workspace wrote *before any role existed*.
///
/// The primary identity is neither a declared role nor the active one once
/// `KAN_IDENTITY_FILE` points at a role, so it fell outside the alias and
/// every pre-roles claim vanished from the obvious "show me everything this
/// workspace wrote" command. The exclusion was disclosed — so this was never
/// the silent-loss class — but it was still the wrong answer to the obvious
/// question, and the same reasoning that put the active identity into the
/// alias applies to the identity that was active before.
#[test]
fn trust_roles_covers_claims_written_before_any_role_existed() {
    let dir = workspace_with_claims(); // primary wrote "shared" first
    for name in ["prover", "director"] {
        let add = kan_as(dir.path(), None, &["identity", "role", "add", name]);
        assert!(add.ok, "role add {name} failed: {}", add.stderr);
    }
    let prover_key = dir.path().join(".kan/roles.d/prover");
    let write = kan_as(
        dir.path(),
        Some(&prover_key),
        &["observe", "shared", "the prover's claim"],
    );
    assert!(write.ok, "role write failed: {}", write.stderr);

    // Read as the prover — the case the loop actually runs.
    let all = kan_as(
        dir.path(),
        Some(&prover_key),
        &["show", "shared", "--trust", "roles", "--json"],
    );
    assert!(all.ok, "{}", all.stderr);
    let all: serde_json::Value = serde_json::from_str(&all.stdout).unwrap();
    let texts: Vec<&str> = all["claims"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["text"].as_str().unwrap_or(""))
        .collect();
    assert!(
        texts.contains(&"the primary identity's claim"),
        "`--trust roles` dropped a claim written before the roles existed: {all}"
    );
    assert!(texts.contains(&"the prover's claim"));
    assert_eq!(
        all["excluded_by_trust"], 0,
        "`--trust roles` still excluded something: {all}"
    );
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
    let roles = listed["roles"].as_array().unwrap();
    let by_name = |n: &str| roles.iter().find(|r| r["name"] == n);

    let director = by_name("director").unwrap_or_else(|| panic!("director missing: {listed}"));
    assert!(director["did"].as_str().unwrap().starts_with("did:key:"));

    // The identity that was signing here before any role existed is
    // recorded too, so `--trust roles` covers the whole workspace rather
    // than only what was written after roles were introduced.
    let primary = by_name("primary").unwrap_or_else(|| panic!("primary missing: {listed}"));
    assert_eq!(
        primary["did"], listed["active"],
        "the `primary` row should be the identity that declared the role"
    );
    // `active` is still reported on its own line: "who am I writing as" and
    // "who has this workspace declared" stay different questions even now
    // that the answers overlap. Read as the director, `active` would be the
    // director while `primary` stayed where it is.
    assert!(listed["active"].as_str().unwrap().starts_with("did:key:"));
    assert_ne!(
        listed["active"], director["did"],
        "this read was made by the primary identity, not the director"
    );
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

/// Publish as the primary, then read as a declared role — the one supported
/// flow that puts the *same* claim on both sides of the log/overlay split.
///
/// Found by running it, not by reading the code (#146 part 2). `.claims/`
/// records are sorted into the overlay by comparing each record's author
/// against the active identity, and under a role that comparison is *correct*:
/// a role genuinely is a different author from the primary that wrote the log.
/// So every published claim looked foreign and was ingested into the overlay
/// while already sitting in the log, and the index rebuild hit
/// `UNIQUE constraint failed: claims.content_cid`.
///
/// The fix is to skip what the log already holds, whoever signed it — which
/// is why #146's suggested "assert instead of dedupe" would have been wrong
/// here: it would have made this supported flow a hard error.
#[test]
fn a_role_reading_a_published_workspace_does_not_duplicate_the_log() {
    let dir = workspace_with_claims();
    let key = dir.path().join("keys/prover");

    let published = kan_as(dir.path(), None, &["publish", "shared"]);
    assert!(published.ok, "publish failed: {}", published.stderr);

    // `.claims/` is a tracked directory, so stage and commit it the way a
    // real workspace would before another identity reads it.
    let git = |args: &[&str]| {
        let status = Command::new("git")
            .args(args)
            .current_dir(dir.path())
            .status()
            .expect("failed to run git");
        assert!(status.success(), "git {args:?} failed");
    };
    git(&["add", "-A"]);
    git(&[
        "-c",
        "user.email=kan-test@example.com",
        "-c",
        "user.name=kan-test",
        "commit",
        "-qm",
        "publish",
    ]);

    let add = kan_as(
        dir.path(),
        None,
        &[
            "identity",
            "role",
            "add",
            "prover",
            "--key",
            key.to_str().unwrap(),
        ],
    );
    assert!(add.ok, "role add failed: {}", add.stderr);

    // The read that used to abort on a UNIQUE constraint.
    let as_role = kan_as(dir.path(), Some(&key), &["status"]);
    assert!(
        as_role.ok,
        "reading as a role after publish failed: {}\n{}",
        as_role.stderr, as_role.stdout
    );
    assert!(
        !as_role
            .stderr
            .contains("both this workspace's log and its overlay"),
        "the overlap invariant fired on a supported flow: {}",
        as_role.stderr
    );

    // Under v0.11's `Local` default the primary is an author *in this log*,
    // so the role simply sees its claims -- where until v0.11 they were
    // excluded and this asserted the disclosure instead (ADR-57).
    //
    // The dedup property this test exists for is now checkable more directly
    // than "no crash": the claim is in the log and in `.claims/`, and it must
    // appear in the view exactly ONCE. A duplicate here is #146 part 2
    // reaching the view rather than the index's UNIQUE constraint.
    let as_role_json = kan_as(dir.path(), Some(&key), &["show", "shared", "--json"]);
    assert!(as_role_json.ok, "{}", as_role_json.stderr);
    let view: serde_json::Value = serde_json::from_str(&as_role_json.stdout).unwrap();
    assert_eq!(
        view["trust"]["base"], "Local",
        "expected the default base: {view}"
    );
    assert_eq!(
        view["excluded_by_trust"], 0,
        "the primary wrote this log, so a role's default read excludes nothing: {view}"
    );
    let cids: Vec<&str> = view["claims"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["cid"].as_str().unwrap())
        .collect();
    let unique: std::collections::HashSet<&&str> = cids.iter().collect();
    assert!(!cids.is_empty(), "the role saw no claims at all: {view}");
    assert_eq!(
        cids.len(),
        unique.len(),
        "a published claim was folded twice -- once from the log, once from the overlay: \
         {view}"
    );
}

//! `.design/v0.9-milestone.md` REQ-4/REQ-6/REQ-7, AC-5 — seed-rooted new
//! identities, and grandfathering every identity that already exists.
//!
//! The whole risk of this milestone is here. #90 and #107 were both a DID
//! moving out from under a log, and the only form of this change in which
//! that is *impossible* rather than merely unlikely is one where an existing
//! identity is never touched at all.
//!
//! `.github/workflows/migration-matrix.yml` covers the other half: every
//! released kan's workspace, read by this build. These tests cover what this
//! build does to a workspace of its own making.

use std::process::Command;

struct Run {
    stdout: String,
    stderr: String,
    ok: bool,
}

fn kan_env(dir: &std::path::Path, key: Option<&std::path::Path>, args: &[&str]) -> Run {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kan"));
    // These tests deliberately exercise the path where KAN_IDENTITY_FILE is
    // NOT set, which is the only way to reach fresh-workspace seed creation
    // -- and that path consults the OS keychain. On macOS a rebuilt test
    // binary is not the binary the keychain authorised, so it blocks on a
    // prompt that never arrives (#96). Forcing the file fallback keeps the
    // suite runnable on a developer machine and identical to what Linux CI
    // does anyway, where no Secret Service exists.
    cmd.args(args).current_dir(dir).env("KAN_NO_KEYCHAIN", "1");
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

/// A workspace in the shape a pre-v0.9 kan left behind: a plaintext
/// `.kan/identity`, claims signed by it, and **no seed**.
fn grandfathered_workspace() -> tempfile::TempDir {
    let dir = git_repo();
    let kan_dir = dir.path().join(".kan");
    std::fs::create_dir_all(&kan_dir).unwrap();
    // A key file written before this build ever ran, exactly as an older
    // version would have left it.
    let key = kan::sign::Identity::generate();
    key.save(&kan_dir.join("identity")).unwrap();

    for i in 1..=3 {
        let run = kan_env(
            dir.path(),
            None,
            &["observe", "legacy", &format!("claim {i} from before v0.9")],
        );
        assert!(run.ok, "legacy write failed: {}", run.stderr);
    }
    dir
}

/// REQ-4: a workspace with no identity at all gets a seed, and its signing
/// key is derived from that seed rather than generated.
#[test]
fn a_fresh_workspace_is_seed_rooted() {
    let dir = git_repo();
    let run = kan_env(dir.path(), None, &["identity", "did"]);
    assert!(run.ok, "{}", run.stderr);
    assert!(run.stdout.starts_with("did:key:"));

    // The seed lives in the OS keychain where one exists and in a 0600 file
    // where it does not, exactly as the signing key does (ADR-25). Either
    // way one of the two markers is present.
    let kan_dir = dir.path().join(".kan");
    assert!(
        kan_dir.join("seed").exists() || kan_dir.join("seed-id").exists(),
        "a fresh workspace is not seed-rooted by either route"
    );

    // The signing key is never written: it is a pure function of the seed,
    // so a copy on disk would be a second at-rest secret for no gain.
    assert!(
        !kan_dir.join("identity").exists(),
        "the derived signing key was persisted -- that is a second copy of the same secret"
    );

    // Derived, not random: reopening reproduces the same DID.
    let did_before = run.stdout;
    for _ in 0..3 {
        let again = kan_env(dir.path(), None, &["identity", "did"]);
        assert!(again.ok, "{}", again.stderr);
        assert_eq!(
            did_before, again.stdout,
            "the signing key was not re-derived from the seed -- it was regenerated"
        );
    }
}

/// AC-5, and the requirement the whole milestone rests on: a workspace that
/// already had an identity keeps it, gains no seed, and loses no claims.
#[test]
fn an_existing_identity_is_grandfathered_untouched() {
    let dir = grandfathered_workspace();
    let did_before = kan_env(dir.path(), None, &["identity", "did"]).stdout;

    // Open it repeatedly, as an upgrade would.
    for _ in 0..3 {
        assert!(kan_env(dir.path(), None, &["status"]).ok);
    }

    let did_after = kan_env(dir.path(), None, &["identity", "did"]).stdout;
    assert_eq!(
        did_before, did_after,
        "a grandfathered workspace's DID moved -- this is #90"
    );
    assert!(
        !kan::sign::Identity::is_seed_rooted(&dir.path().join(".kan")),
        "a grandfathered workspace was given a seed; its key is not seed-derived, so the \
         seed would be a root that roots nothing"
    );

    let shown = kan_env(dir.path(), None, &["show", "legacy", "--json"]);
    assert!(shown.ok, "{}", shown.stderr);
    let shown: serde_json::Value = serde_json::from_str(&shown.stdout).unwrap();
    assert_eq!(
        shown["claims"].as_array().unwrap().len(),
        3,
        "claims written before the upgrade are missing: {shown}"
    );
    assert_eq!(
        shown["excluded_by_trust"], 0,
        "claims are present but hidden by trust -- the identity moved: {shown}"
    );
}

/// AC-5's **negative control**: a fresh binary against an existing workspace
/// mints nothing, across many opens.
///
/// **The invariant is the DID, not the key file**, and that distinction cost
/// a first draft of this test. Asserting the key file's bytes fails on macOS
/// for a correct reason: once the key reaches the OS keychain, v0.7.1
/// deliberately removes the lingering plaintext copy (ADR-53), so the file is
/// *supposed* to vanish. A control keyed on it would have been red on one
/// platform and green on CI, which is worse than no control at all.
///
/// The DID is what a mint would move, it is what `TrustBase::Solo` filters
/// on, and it is the same on every platform — so the claims staying visible
/// with nothing excluded is the assertion that actually distinguishes "kept
/// the identity" from "made a new one".
#[test]
fn opening_an_existing_workspace_mints_nothing() {
    let dir = grandfathered_workspace();
    let did_before = kan_env(dir.path(), None, &["identity", "did"]).stdout;
    assert!(did_before.starts_with("did:key:"));

    for _ in 0..5 {
        assert!(kan_env(dir.path(), None, &["status"]).ok);
        assert_eq!(
            kan_env(dir.path(), None, &["identity", "did"]).stdout,
            did_before,
            "the DID moved while merely opening the workspace"
        );
    }

    assert!(
        !kan::sign::Identity::is_seed_rooted(&dir.path().join(".kan")),
        "a seed appeared for a key that was never derived from one"
    );

    // And the consequence a user would actually feel.
    let shown = kan_env(dir.path(), None, &["show", "legacy", "--json"]);
    let shown: serde_json::Value = serde_json::from_str(&shown.stdout).unwrap();
    assert_eq!(shown["claims"].as_array().unwrap().len(), 3);
    assert_eq!(shown["excluded_by_trust"], 0);
}

/// REQ-7: the guard covers the seed path too. An explicit key file that does
/// not exist is still refused against a non-empty log, and the seed work does
/// not open a way around it.
#[test]
fn the_guard_still_refuses_an_undeclared_second_identity() {
    let dir = git_repo();
    assert!(kan_env(dir.path(), None, &["identity", "did"]).ok);
    assert!(kan_env(dir.path(), None, &["observe", "s", "first claim"]).ok);
    assert!(
        kan::sign::Identity::is_seed_rooted(&dir.path().join(".kan")),
        "expected seed-rooted"
    );

    let elsewhere = dir.path().join("another-key");
    let run = kan_env(dir.path(), Some(&elsewhere), &["observe", "s", "second"]);
    assert!(
        !run.ok,
        "a second identity was minted against a seed-rooted workspace with claims"
    );
    // REQ-2: refused as a selection naming a missing path, before the
    // mint-guard is reachable. Stronger than the old refusal, which minted the
    // key first and then declined to use it.
    assert!(run.stderr.contains("does not exist"), "{}", run.stderr);
    assert!(
        !elsewhere.exists(),
        "the refused key file was created anyway"
    );
}

/// A seed-rooted workspace's phrase is the **seed**, and it reproduces the
/// DID — so one escrowed secret still recovers the identity, which is what
/// `.design/durability-log-recovery.md` IREQ-2 requires and what `kan
/// restore` depends on.
#[test]
fn the_phrase_of_a_seed_rooted_workspace_reproduces_its_identity() {
    let dir = git_repo();
    let did = kan_env(dir.path(), None, &["identity", "did"]).stdout;

    let seed = kan::sign::Seed::load(&dir.path().join(".kan"))
        .unwrap()
        .expect("a fresh workspace must be seed-rooted");
    let phrase = seed.phrase().unwrap();

    // The phrase read as a seed gives this workspace's DID.
    let candidates = kan::sign::candidate_identities(&phrase).unwrap();
    let as_seed = candidates
        .iter()
        .find(|(root, _)| *root == kan::sign::Root::Seed)
        .expect("a 24-word phrase must have a seed reading");
    assert_eq!(
        as_seed.1.did(),
        did,
        "the seed phrase does not reproduce the workspace's identity"
    );
}

/// Both readings of a phrase are offered, because nothing in the words says
/// which scheme produced them.
///
/// This is the cost of not adding a marker byte or a shorter phrase, and it
/// is paid where it can be resolved: against a workspace that knows its own
/// author. Asserting it here keeps the ambiguity a *stated* property rather
/// than a surprise for whoever next reads `candidate_identities`.
#[test]
fn a_phrase_has_both_readings_and_they_differ() {
    let dir = git_repo();
    assert!(kan_env(dir.path(), None, &["identity", "did"]).ok);
    let phrase = kan::sign::Seed::load(&dir.path().join(".kan"))
        .unwrap()
        .expect("a fresh workspace must be seed-rooted")
        .phrase()
        .unwrap();

    let candidates = kan::sign::candidate_identities(&phrase).unwrap();
    assert_eq!(
        candidates.len(),
        2,
        "expected both a seed and a signing-key reading"
    );
    assert_ne!(
        candidates[0].1.did(),
        candidates[1].1.did(),
        "the two readings collapsed to one identity -- the seed is being used as the key"
    );
}

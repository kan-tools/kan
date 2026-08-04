//! Issue #146 — the `WouldMintSecondIdentity` guard must cover *every* path
//! that can mint, not just the `KAN_IDENTITY_FILE` branch it was written in.
//!
//! The defect and this file's shape are the same argument. `KAN_NO_KEYCHAIN`
//! was added by ADR-66 so v0.9's own tests could run on macOS, and it reached
//! `load_or_create_plaintext` without passing the guard — so the escape hatch
//! reopened the exact defect (#90) that its own milestone was hardening
//! against. The condition "a new identity would be created and the log is
//! non-empty" never had anything to do with *which* mechanism was minting, so
//! the tests here drive each mechanism against one invariant.
//!
//! Note what the existing suites do and this one deliberately does not:
//! `tests/identity_adopt.rs` and `tests/bulk_read.rs` set `KAN_NO_KEYCHAIN=1`
//! in their harness for every cell. That is #146's third finding — a harness
//! that drives only one shape cannot see a defect that lives in the other —
//! so the helper below makes the variable an explicit per-call axis.

use std::path::Path;
use std::process::Command;

struct Run {
    stdout: String,
    stderr: String,
    ok: bool,
}

/// Both identity variables are an explicit axis here, never an ambient
/// default — that ambience is what hid #146.
fn kan(dir: &Path, key: Option<&Path>, no_keychain: bool, args: &[&str]) -> Run {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kan"));
    cmd.args(args).current_dir(dir);
    if no_keychain {
        cmd.env("KAN_NO_KEYCHAIN", "1");
    } else {
        cmd.env_remove("KAN_NO_KEYCHAIN");
    }
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

/// A workspace with a real, non-empty log, written under a key file so the
/// keychain is never involved in the setup.
fn workspace_with_claims() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = git_repo();
    let key = dir.path().join("key");
    let wrote = kan(
        dir.path(),
        Some(&key),
        true,
        &["observe", "a claim the log must not lose", "--subject", "s"],
    );
    assert!(wrote.ok, "setup write failed: {}", wrote.stderr);
    assert!(
        dir.path().join(".kan/log/repo.car").exists(),
        "setup did not produce a log"
    );
    (dir, key)
}

/// The probe is a **write**, and that changed in v0.11.
///
/// These tests used `kan status`, because until v0.11 every read resolved a
/// signing identity and so tripped every minting path. A read now resolves
/// none (`.design/identity-surface.md` REQ-2), which is the fix for #149 --
/// so a read is no longer capable of minting and no longer the way to catch a
/// path that would. Probing with a read here would assert the guard holds
/// while exercising nothing, which is precisely the class of test this
/// project keeps finding.
///
/// Each test below therefore does both halves: the write is refused (the
/// guard), and the read succeeds and returns the log (the milestone).
fn probe_write() -> [&'static str; 4] {
    ["observe", "a write that must be refused", "--subject", "s"]
}

/// The state these tests construct is exactly #90's, and under `Local` a read
/// of it must show the log rather than refuse or hide it -- the failure mode
/// disappearing rather than being guarded against.
fn assert_read_still_works(dir: &Path, key: Option<&Path>, no_keychain: bool) {
    let read = kan(dir, key, no_keychain, &["status"]);
    assert!(
        read.ok,
        "a read of a workspace whose identity is unresolvable was refused; under `Local` \
         it needs no identity and must simply work.\nstderr: {}",
        read.stderr
    );
    assert!(
        read.stdout.contains("a claim the log must not lose"),
        "the read did not return the log it can plainly see: {}",
        read.stdout
    );
    assert!(
        !dir.join(".kan/identity").exists(),
        "a read minted a key -- #149 exactly"
    );
}

/// The reported defect, reproduced exactly: keychain-held identity, plaintext
/// copy correctly deleted by ADR-53, `KAN_NO_KEYCHAIN=1` set.
///
/// `identity-id` is what makes this the *reported* case rather than the
/// seed-rooting one — its presence means the keychain has been used for this
/// workspace, so `load_or_create_for_workspace` reads the workspace as
/// non-fresh and hands off to `load_or_create`, which is where the hole was.
#[test]
fn no_keychain_cannot_mint_against_a_non_empty_log() {
    let (dir, _key) = workspace_with_claims();
    std::fs::write(dir.path().join(".kan/identity-id"), "some-account-id").unwrap();
    assert!(
        !dir.path().join(".kan/identity").exists(),
        "precondition: no plaintext key, as ADR-53 leaves it"
    );

    let run = kan(dir.path(), None, true, &probe_write());

    assert!(
        !run.ok,
        "KAN_NO_KEYCHAIN minted a second identity against a non-empty log.\n\
         stdout: {}\nstderr: {}",
        run.stdout, run.stderr
    );
    assert_read_still_works(dir.path(), None, true);
    assert!(
        run.stderr.contains("already has claims"),
        "refusal must explain itself: {}",
        run.stderr
    );
    assert!(
        !dir.path().join(".kan/identity").exists(),
        "refusing must not leave a minted key behind"
    );
}

/// The same invariant on the seed-rooting path: no identity file, no
/// `identity-id`, so the file-only freshness check says "fresh" while the log
/// says otherwise. The log is the tiebreaker.
#[test]
fn seed_rooting_cannot_mint_against_a_non_empty_log() {
    let (dir, _key) = workspace_with_claims();
    assert!(
        !dir.path().join(".kan/identity-id").exists(),
        "precondition: keychain never used, so the freshness check sees a fresh workspace"
    );

    let run = kan(dir.path(), None, true, &probe_write());

    assert!(
        !run.ok,
        "seed-rooting minted a new identity against a non-empty log.\n\
         stdout: {}\nstderr: {}",
        run.stdout, run.stderr
    );
    assert_read_still_works(dir.path(), None, true);
    assert!(
        !dir.path().join(".kan/seed-id").exists(),
        "refusing must not leave a seed behind"
    );
}

/// The branch the guard was originally written in — unchanged behaviour,
/// kept as a control so hoisting it cannot silently drop it.
#[test]
fn identity_file_still_cannot_mint_against_a_non_empty_log() {
    let (dir, _key) = workspace_with_claims();
    let other = dir.path().join("a-different-key");

    let run = kan(dir.path(), Some(&other), true, &probe_write());

    assert!(
        !run.ok,
        "KAN_IDENTITY_FILE minted a second identity: {}",
        run.stdout
    );
    assert!(!other.exists(), "refusing must not create the key file");
    assert_read_still_works(dir.path(), Some(&other), true);
}

/// The negative control, and the one that matters most for a guard: it must
/// refuse *only* when there is something to lose. An empty log is the normal
/// first-run state, and minting there is the whole point.
#[test]
fn an_empty_log_still_mints_freely_on_every_path() {
    for (label, key_file, no_keychain) in
        [("seed-rooting", false, true), ("identity-file", true, true)]
    {
        let dir = git_repo();
        let key = dir.path().join("key");
        let key = key_file.then_some(key);

        let run = kan(
            dir.path(),
            key.as_deref(),
            no_keychain,
            &["observe", "first claim", "--subject", "s"],
        );

        assert!(
            run.ok,
            "{label}: guard over-fired on a fresh workspace: {}",
            run.stderr
        );
    }
}

/// `kan identity role add` is the deliberate opt-in and must still work
/// against a non-empty log — that is the whole distinction the guard draws,
/// so a fix that refused here would have broken the feature rather than the
/// defect.
#[test]
fn declaring_a_role_is_still_the_deliberate_way_past_the_guard() {
    let (dir, key) = workspace_with_claims();
    let role_key = dir.path().join("prover-key");

    let run = kan(
        dir.path(),
        Some(&key),
        true,
        &[
            "identity",
            "role",
            "add",
            "prover",
            "--key",
            role_key.to_str().unwrap(),
        ],
    );

    assert!(
        run.ok,
        "the deliberate role opt-in was refused: {}",
        run.stderr
    );
    assert!(role_key.exists(), "role key should have been minted");
}

/// A guard whose remedy cannot be run is a trap, and this one nearly was.
///
/// `adopt_identity` takes a `&Workspace`, so `Workspace::open` — and with it
/// identity resolution — has to succeed before adopt can change anything.
/// The refusal therefore cannot simply say "run `kan identity adopt`": in the
/// state that produces the refusal, adopt trips the very same guard. The
/// message names the form that works, and this test is what keeps it working.
#[test]
fn the_remedy_the_refusal_names_actually_runs() {
    let (dir, key) = workspace_with_claims();
    std::fs::write(dir.path().join(".kan/identity-id"), "some-account-id").unwrap();

    // The refusal is on the WRITE path now: a read of this state succeeds
    // and returns the log, because it resolves no identity to be refused
    // over (REQ-2). The remedy still has to be runnable, which is what this
    // test is about.
    assert_read_still_works(dir.path(), None, true);
    let refused = kan(dir.path(), None, true, &probe_write());
    assert!(!refused.ok, "precondition: the guard should have fired");
    assert!(
        refused.stderr.contains("kan identity adopt --key"),
        "the refusal should name a recovery command: {}",
        refused.stderr
    );

    // v0.11 AC-4 / REQ-4: with `KAN_IDENTITY_FILE` **unset**.
    //
    // The old remedy was "name the same path twice" -- adopt had to open a
    // writable workspace before it could repoint anything, so it tripped the
    // very guard it is the remedy for, and the only way past was to hand it
    // the answer first. That was a remedy you could only run if you already
    // knew what it was going to tell you.
    //
    // Adopt now opens read-only: it needs the index and the root, and no
    // identity at all. The workaround is gone rather than documented.
    let adopted = kan(
        dir.path(),
        None,
        true,
        &["identity", "adopt", "--key", key.to_str().unwrap()],
    );
    assert!(
        adopted.ok,
        "the remedy named in the refusal did not run: {}",
        adopted.stderr
    );

    // And the workspace is genuinely recovered, not merely openable.
    let after = kan(dir.path(), None, true, &["status"]);
    assert!(
        after.ok,
        "workspace still unreadable after adopt: {}",
        after.stderr
    );
    assert!(
        !after.stdout.contains("no subjects yet"),
        "the recovered workspace still reads as empty -- the #90 shape: {}",
        after.stdout
    );
    assert!(
        !after.stdout.contains("excluded by this view's trust base"),
        "adopt opened the workspace but under the wrong identity: {}",
        after.stdout
    );
}

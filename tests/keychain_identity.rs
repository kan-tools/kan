//! What a brand-new workspace leaves at rest, checked through the binary.
//!
//! **Three tests were deleted here by v0.12 REQ-3.5 (#183), not moved.** They
//! were `load_or_create_is_idempotent_across_separate_calls`,
//! `a_migrated_plaintext_identity_is_removed_once_the_keychain_holds_it` and
//! `a_different_key_plaintext_file_survives_a_keychain_hit`, and all three
//! asserted the plaintext→keychain migration that REQ-1 removed from the
//! resolution path and REQ-3 retired as a feature (`kan identity protect` is
//! the deliberate way in now). They exercised `Identity::load_or_create`,
//! which `src/` no longer calls.
//!
//! One of them had a second problem worth recording, because it is the
//! milestone's own theme: `a_different_key_plaintext_file_survives_a_keychain_hit`
//! **self-skipped whenever no keychain served the entry** — `load_or_create`,
//! then `if path.exists() { return; }` with nothing asserted before it — so on
//! `ubuntu-latest`, which has no Secret Service, it returned early every run
//! having asserted nothing at all.
//!
//! *Corrected by a cold review, which is the point of having one.* The first
//! version of this note claimed **two of four** deleted tests never executed
//! their assertions. Both numbers were wrong: **three** tests were deleted (the
//! fourth survives, below), and only **one** asserts nothing before returning.
//! `a_migrated_plaintext_identity_is_removed_once_the_keychain_holds_it` runs
//! three assertions on CI before and inside its early-return branch. Overstating
//! what was verified is the exact failure `atom/adversarial-review` names, and
//! it is worse in a note whose subject is tests that do not check what they claim.
//!
//! What remains is the test that was always the valuable one, because it goes
//! through the **binary** rather than the library and therefore asserts what a
//! user actually gets. REQ-3.1 turns it into the canary of
//! `.design/identity-at-rest.md` AC-3.1.

use std::process::Command;

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

/// **AC-3.1 of `.design/identity-at-rest.md` — the canary, and the first test
/// in this repository that can run kan's actual default path.**
///
/// It does **not** set `KAN_NO_KEYCHAIN`. Before REQ-3 that was unrunnable:
/// a fresh workspace minted through `Seed::create`, which preferred the OS
/// keychain, so on macOS a locally-rebuilt binary blocked on an authorization
/// prompt nobody could answer (#96). Every other identity test in the suite
/// sets the flag for that reason — which is precisely why the keychain-
/// reachable plane was unreachable from the suite, and why #170, #180 and
/// ADR-88's `adopt` defect could all live there uncaught.
///
/// Its predecessor branched on whether the keychain happened to be available
/// and asserted something different in each arm, so it passed either way and
/// could not tell you which world you were in. That is no longer a property
/// of the environment: after REQ-3 a fresh workspace roots in a `0600` file
/// on every platform, so the assertion is unconditional and a keychain that
/// engages here is a **defect**, not a variation.
#[test]
fn a_fresh_workspace_roots_in_a_plaintext_seed_and_never_touches_the_keychain() {
    let dir = git_repo();

    let started = std::time::Instant::now();
    let output = Command::new(env!("CARGO_BIN_EXE_kan"))
        .args(["observe", "x"])
        .current_dir(dir.path())
        .output()
        .expect("failed to run kan binary");
    let elapsed = started.elapsed();

    assert!(
        output.status.success(),
        "a fresh workspace must be writable with no keychain and no KAN_IDENTITY_FILE.\n\
         stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let kan_dir = dir.path().join(".kan");

    assert!(
        kan_dir.join("seed").exists(),
        "a fresh workspace must root in .kan/seed -- that is REQ-3's whole claim"
    );
    assert!(
        !kan_dir.join("seed-id").exists(),
        "a fresh workspace must NOT file its seed in the OS keychain. A seed-id here \
         means Seed::create reached for the keychain again, which is #96 reopened on \
         the path every new user, every CI job and every `day` subprocess takes"
    );
    assert!(
        !kan_dir.join("identity").exists() && !kan_dir.join("identity-id").exists(),
        "a seed-rooted workspace stores no signing key at all -- it is derived, so a \
         second at-rest secret buys nothing"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(kan_dir.join("seed"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "the root secret must be owner-only");
    }

    // #96 is a HANG, not a failure -- "the worst shape", as the module doc
    // says -- so elapsed time is the only thing that distinguishes a keychain
    // that engaged and was answered from one that was never consulted. The
    // bound is loose on purpose: a first write builds an index and a CAR, and
    // this must not flake on a loaded CI box. An authorization prompt nobody
    // answers is unbounded, so anything under this is unambiguous.
    assert!(
        elapsed < std::time::Duration::from_secs(60),
        "a fresh write took {elapsed:?}; the keychain path is the only thing here that \
         can block, so this is #96 rather than slowness"
    );
}

/// The notice a fresh workspace prints is **load-bearing safety information**,
/// and nothing asserted it before REQ-3 — the flip changed it from a warning
/// to a statement of fact and the whole suite stayed green, which is how you
/// find out a user-visible string has no test.
///
/// Only the facts are pinned, not the wording: where the secret is, that the
/// phrase is the backup, and that `protect` is the way into the keychain. Plus
/// one negative — it must **not** read as a failure. The text it replaced said
/// "OS keychain unavailable", which under REQ-3 would tell every new user that
/// something went wrong on the path that is now the deliberate default.
#[test]
fn a_fresh_workspace_says_where_its_secret_is_without_implying_a_failure() {
    let dir = git_repo();
    let output = Command::new(env!("CARGO_BIN_EXE_kan"))
        .args(["observe", "x"])
        .current_dir(dir.path())
        .output()
        .expect("failed to run kan binary");
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stderr.contains(".kan/seed"),
        "the notice must name where the root secret actually is.\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("kan identity phrase"),
        "it must name the recovery phrase -- that is the only copy of this secret not \
         on this disk, and a user who never learns it has no backup at all.\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("kan identity protect"),
        "it must name the way into the keychain, or the opt-in REQ-3 is built around is \
         one nobody is told about.\nstderr: {stderr}"
    );
    assert!(
        !stderr.contains("unavailable"),
        "the notice must not read as a failure. A plaintext seed is REQ-3's DELIBERATE \
         default, not a fallback from something that did not work -- and telling every \
         new user their keychain is 'unavailable' would be both false and alarming.\n\
         stderr: {stderr}"
    );
}

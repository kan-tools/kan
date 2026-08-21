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
/// Current first-run policy performs no signing-key lookup at all: an ordinary
/// write is refused until system identity and scope initialization are
/// explicit. A keychain prompt or any `.kan` artifact is therefore a defect.
#[test]
fn a_fresh_workspace_refuses_without_touching_the_keychain_or_disk() {
    let dir = git_repo();

    let started = std::time::Instant::now();
    let output = Command::new(env!("CARGO_BIN_EXE_kan"))
        .args(["observe", "x"])
        .current_dir(dir.path())
        .output()
        .expect("failed to run kan binary");
    let elapsed = started.elapsed();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("kan identity init"), "stderr: {stderr}");
    assert!(stderr.contains("kan init"), "stderr: {stderr}");

    let kan_dir = dir.path().join(".kan");
    assert!(!kan_dir.exists(), "a refused first write created `.kan`");

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

/// The first-run refusal is load-bearing guidance: it names the two explicit
/// initialization steps and does not imply a keychain failure.
#[test]
fn a_fresh_workspace_explains_the_initialization_sequence() {
    let dir = git_repo();
    let output = Command::new(env!("CARGO_BIN_EXE_kan"))
        .args(["observe", "x"])
        .current_dir(dir.path())
        .output()
        .expect("failed to run kan binary");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stderr.contains("kan identity init"),
        "the notice must name system identity initialization.\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("kan init"),
        "the notice must name scope initialization.\nstderr: {stderr}"
    );
    assert!(
        !stderr.contains("unavailable"),
        "the notice must not claim the keychain is unavailable: no keychain lookup was \
         attempted on this path, so that would be both false and alarming.\n\
         stderr: {stderr}"
    );
}

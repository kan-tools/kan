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

/// AC-9: with no OS keychain available (simulated / CI), `kan` still works
/// non-interactively, falling back to the plaintext file with a visible
/// warning. Written to hold either way this runs: if the keychain genuinely
/// isn't available here, the warning fires and the plaintext file appears;
/// if it is available, the command still succeeds and no plaintext file is
/// created for this brand-new identity (the actual point of issue #6).
#[test]
fn keychain_or_plaintext_fallback_both_work_non_interactively() {
    let dir = git_repo();

    let output = Command::new(env!("CARGO_BIN_EXE_kan"))
        .args(["observe", "x"])
        .current_dir(dir.path())
        .output()
        .expect("failed to run kan binary");
    assert!(
        output.status.success(),
        "kan observe should succeed non-interactively regardless of keychain availability"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    let kan_dir = dir.path().join(".kan");
    let identity_path = kan_dir.join("identity");
    let seed_path = kan_dir.join("seed");

    // A brand-new workspace is seed-rooted since v0.9, so the secret that can
    // land at rest is the **seed**, and the signing key is derived from it
    // rather than stored at all. The property this test has always been about
    // is unchanged and is asserted on whichever secret is in play: a plaintext
    // copy exists if and only if the keychain was unavailable.
    assert!(
        !identity_path.exists(),
        "a seed-rooted workspace wrote a plaintext signing key -- it is derivable from the \
         seed, so storing it is a second at-rest secret for no gain"
    );

    if stderr.contains("OS keychain unavailable") {
        assert!(
            seed_path.exists(),
            "fallback warning fired, so the plaintext seed file should exist"
        );
    } else {
        assert!(
            !seed_path.exists(),
            "keychain succeeded for a brand-new identity, so no plaintext secret should have \
             been created (that's the actual point of encrypting at rest, issue #6)"
        );
        assert!(
            kan_dir.join("seed-id").exists(),
            "the keychain path must leave the marker that says where the seed went, or the \
             next open cannot tell a keychain-held seed from no seed at all -- and would \
             mint a second identity"
        );
    }
}

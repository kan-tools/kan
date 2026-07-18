//! REQ-14..16: `Identity::load_or_create` tries the OS keychain first,
//! falling back to (and migrating from) the plaintext file. These
//! assertions are written to hold regardless of which backend actually
//! engages on the machine running the test — CI (`ubuntu-latest`, per
//! `.github/workflows/ci.yml`) has no Secret Service daemon by default, so
//! it exercises the real fallback path (AC-9); local dev on macOS
//! typically has a real keychain, exercising the primary path. The one
//! test that specifically distinguishes the two branches
//! (`keychain_or_plaintext_fallback_both_work_non_interactively`) checks
//! the CLI's actual observed behavior rather than assuming which branch
//! ran, so it's meaningful either way.

use std::process::Command;

use kan::sign::Identity;

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

#[test]
fn load_or_create_is_idempotent_across_separate_calls() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity");

    let first = Identity::load_or_create(&path).unwrap();
    let second = Identity::load_or_create(&path).unwrap();
    assert_eq!(first.did(), second.did());
}

/// REQ-16: a pre-existing plaintext identity file is migrated in (read
/// correctly, same DID) and left in place afterward — deliberately not
/// deleted (ADR-25's explicit choice for this open question).
#[test]
fn a_preexisting_plaintext_identity_is_migrated_and_left_in_place() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity");

    let original = Identity::generate();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    original.save(&path).unwrap();
    assert!(path.exists());

    let loaded = Identity::load_or_create(&path).unwrap();
    assert_eq!(original.did(), loaded.did());
    assert!(
        path.exists(),
        "the plaintext file should be left in place as a fallback copy, not deleted"
    );

    // And it's stable on a second call too, whichever backend served it.
    let reloaded = Identity::load_or_create(&path).unwrap();
    assert_eq!(original.did(), reloaded.did());
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
    let identity_path = dir.path().join(".kan/identity");
    if stderr.contains("OS keychain unavailable") {
        assert!(
            identity_path.exists(),
            "fallback warning fired, so the plaintext identity file should exist"
        );
    } else {
        assert!(
            !identity_path.exists(),
            "keychain succeeded for a brand-new identity, so no plaintext file should have \
             been created (that's the actual point of encrypting the key at rest)"
        );
    }
}

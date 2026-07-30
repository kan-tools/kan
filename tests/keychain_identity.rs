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

/// A pre-existing plaintext identity is migrated in (read correctly, same
/// DID) and the plaintext copy is then **removed** — reversing ADR-25's
/// choice to keep it.
///
/// ADR-25 kept it as a fallback, with the effect that every migrated identity
/// retained an unprotected copy of the same 32 bytes beside the protected one
/// — world-readable at 0644 on this author's own machine. The keychain
/// therefore imposed its full cost and protected nothing: "encryption at
/// rest" only ever held for identities generated fresh after ADR-25, not for
/// any that were migrated. Removing the copy is what makes the default
/// actually encrypted at rest (ADR-48).
///
/// The deletion is conditional on reading the secret back and confirming it
/// matches, because deleting the sole remaining copy of a signing key on the
/// strength of a write that returned `Ok` is not a trade worth making.
///
/// Skipped where no keychain is available (headless CI, no Secret Service):
/// there the plaintext file is the only store and must stay.
#[test]
fn a_migrated_plaintext_identity_is_removed_once_the_keychain_holds_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity");

    let original = Identity::generate();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    original.save(&path).unwrap();
    assert!(path.exists());

    let loaded = Identity::load_or_create(&path).unwrap();
    assert_eq!(
        original.did(),
        loaded.did(),
        "migration must preserve the identity -- a new DID would drop every \
         existing claim out of every read"
    );

    if path.exists() {
        // No keychain here, so the file is the only copy and correctly kept.
        // Assert the fallback still round-trips rather than silently passing.
        let reloaded = Identity::load_or_create(&path).unwrap();
        assert_eq!(original.did(), reloaded.did());
        return;
    }

    // Keychain served it: the unprotected copy is gone, and the identity is
    // still reachable without it.
    let reloaded = Identity::load_or_create(&path).unwrap();
    assert_eq!(
        original.did(),
        reloaded.did(),
        "the identity must survive deletion of the plaintext copy -- if it \
         does not, that copy was load-bearing and must not have been removed"
    );
    assert!(
        !path.exists(),
        "the plaintext copy must not be recreated on a later load"
    );
}

/// #112 (the D-B negative control): a plaintext file holding a **different**
/// key than the keychain's must **survive** a keychain hit.
///
/// PR #109 fixed the keychain-hit deletion guard to read the file and delete
/// it only if its bytes equal the keychain's, replacing the tautology
/// `bytes == import(bytes).export()` that never read the file. Every existing
/// test exercises the *matching* (migration) deletion; none asserted the
/// discriminating behaviour that is the whole point — that a non-matching file
/// is kept. The tautology passed precisely because nothing distinguished, so
/// this is the test that fails when the guard is inverted (delete-when-
/// different), which for a signing key is the worst outcome: deleting a key
/// the keychain does not hold.
///
/// Environment-gated exactly like the migration test: it can only run where a
/// real keychain serves the entry (so the deletion branch is even reached).
/// On a machine with no Secret Service (headless CI) the first load keeps the
/// file, the keychain-hit branch never runs, and the test skips.
#[test]
fn a_different_key_plaintext_file_survives_a_keychain_hit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity");

    // First load establishes the keychain entry (and, where a keychain
    // exists, removes any plaintext copy). Its DID is what the keychain holds.
    let keychain_identity = Identity::load_or_create(&path).unwrap();

    if path.exists() {
        // No keychain here: the file is the only store and the keychain-hit
        // deletion branch never runs. Nothing to discriminate — skip.
        return;
    }

    // Keychain serves the identity. Drop a *different* key's file beside it.
    let other = Identity::generate();
    assert_ne!(
        keychain_identity.did(),
        other.did(),
        "the two identities must differ for this to test anything"
    );
    other.save(&path).unwrap();
    assert!(path.exists());

    // Load again: keychain hit returns its own identity; the file holds a
    // different key, so the guard must KEEP it (delete only on a byte match).
    let loaded = Identity::load_or_create(&path).unwrap();
    assert_eq!(
        keychain_identity.did(),
        loaded.did(),
        "the keychain is authoritative on a hit; the stray file must not shadow it"
    );
    assert!(
        path.exists(),
        "a plaintext file holding a DIFFERENT key than the keychain must survive — deleting it \
         would destroy a key the keychain does not hold (the D-B false-positive delete)"
    );
    // And the surviving file is untouched: still the other key, not rewritten.
    let from_file = Identity::load_or_create(&path).unwrap();
    assert_eq!(keychain_identity.did(), from_file.did());
    assert!(path.exists());
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

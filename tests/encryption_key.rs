//! `.design/v0.9-milestone.md` REQ-5/AC-4 — the derived X25519 encryption
//! key (ADR-55's Q2).
//!
//! Nothing encrypts anything yet, deliberately. The key exists so ADR-54's
//! L1 encrypted backup and #7's HPKE protocol have a recipient to address,
//! and so the property that matters for both — *one* escrowed secret
//! reproduces it — is established before anything depends on it.

use std::process::Command;

fn kan(dir: &std::path::Path, key: &std::path::Path, args: &[&str]) -> (String, bool) {
    let output = Command::new(env!("CARGO_BIN_EXE_kan"))
        .args(args)
        .current_dir(dir)
        .env("KAN_IDENTITY_FILE", key)
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

/// AC-4: one secret reproduces both slots. The same key file yields the same
/// DID **and** the same encryption key, across separate invocations.
///
/// This is the property `.design/durability-log-recovery.md` IREQ-2 demands
/// — "restore is only a restore if one escrowed secret reproduces the exact
/// signing DID" — extended to the encryption slot, so a future encrypted
/// backup is recoverable from the same 24 words and not from a second thing
/// the operator has to have kept.
#[test]
fn one_key_reproduces_both_the_did_and_the_encryption_key() {
    let dir = git_repo();
    let key = dir.path().join("key");

    let (did, ok) = kan(dir.path(), &key, &["identity", "did"]);
    assert!(ok);
    let (enc, ok) = kan(dir.path(), &key, &["identity", "encryption-key"]);
    assert!(ok, "no encryption-key command");

    let (did_again, _) = kan(dir.path(), &key, &["identity", "did"]);
    let (enc_again, _) = kan(dir.path(), &key, &["identity", "encryption-key"]);
    assert_eq!(did, did_again);
    assert_eq!(
        enc, enc_again,
        "the encryption key changed between invocations -- it is not derived, it is random"
    );

    // A real X25519 public key: 32 bytes, hex.
    assert_eq!(enc.len(), 64, "expected 32 hex-encoded bytes, got {enc:?}");
    assert!(enc.chars().all(|c| c.is_ascii_hexdigit()));
}

/// AC-4's other half: the encryption key is **not** a re-encoding of the
/// signing key.
///
/// The Ed25519→X25519 footgun is reusing one key's scalar on two curves.
/// Deriving through a KDF under a distinct label avoids it by construction,
/// and this is the observable consequence: the encryption key shares no
/// structure with the DID it accompanies.
#[test]
fn the_encryption_key_is_not_a_conversion_of_the_signing_key() {
    let dir = git_repo();
    let key = dir.path().join("key");
    let (did, _) = kan(dir.path(), &key, &["identity", "did"]);
    let (enc, _) = kan(dir.path(), &key, &["identity", "encryption-key"]);

    // The DID's multibase payload and the encryption key must not coincide.
    let did_body = did.trim_start_matches("did:key:");
    assert!(
        !did_body.contains(&enc) && !enc.contains(did_body),
        "the encryption key appears inside the DID -- it is a conversion, not a derivation"
    );

    // Two different identities differ in both slots, so neither is a
    // constant that merely looks derived.
    let other_key = dir.path().join("other");
    let (other_did, _) = kan(dir.path(), &other_key, &["identity", "did"]);
    let (other_enc, _) = kan(dir.path(), &other_key, &["identity", "encryption-key"]);
    assert_ne!(did, other_did);
    assert_ne!(
        enc, other_enc,
        "two identities share an encryption key -- the derivation ignores the root"
    );
}

/// Every existing workspace gets an encryption key with **no migration**:
/// a repo that has been writing claims under the current scheme answers
/// `identity encryption-key` immediately, and its DID is untouched.
///
/// That is the practical payoff of rooting the derivation in the signing key
/// material rather than in a newly-escrowed seed — there is nothing to
/// migrate and no second secret to write down, which is what makes this
/// deployable to workspaces that already exist.
#[test]
fn an_existing_workspace_gains_an_encryption_key_without_migrating() {
    let dir = git_repo();
    let key = dir.path().join("key");
    assert!(
        kan(
            dir.path(),
            &key,
            &["observe", "a", "written before the key existed"]
        )
        .1
    );
    let (did_before, _) = kan(dir.path(), &key, &["identity", "did"]);

    let (enc, ok) = kan(dir.path(), &key, &["identity", "encryption-key"]);
    assert!(ok);
    assert_eq!(enc.len(), 64);

    let (did_after, _) = kan(dir.path(), &key, &["identity", "did"]);
    assert_eq!(
        did_before, did_after,
        "deriving an encryption key changed the signing identity"
    );

    // And the claim written before is still readable, which is the thing
    // that would actually hurt if the DID had moved.
    let (shown, ok) = kan(dir.path(), &key, &["show", "a", "--json"]);
    assert!(ok);
    let shown: serde_json::Value = serde_json::from_str(&shown).unwrap();
    assert_eq!(shown["claims"].as_array().unwrap().len(), 1);
}

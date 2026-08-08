//! AC-3.9 of `.design/identity-at-rest.md` — `unprotect` must never write over
//! a differing secret.
//!
//! This is the only path in the at-rest design that can DESTROY a secret, and
//! it is reachable from a state kan itself creates: ADR-53 deletes a plaintext
//! copy only when it MATCHES the keychain and keeps it when it DIFFERS, which
//! is exactly what #112's negative control existed to protect. `identity-id`
//! outranks `identity`, so the keychain's key signs while the file sits there
//! as the only copy of another identity.
//!
//! The guard is tested rather than the executor because the executor reads the
//! keychain, which no test in this suite can reach (#96) — and #112's history
//! is a guard that was never exercised because it was a tautology.

use kan::sign::{refuse_to_overwrite_a_different_secret, AtRest, Identity};

/// The bytes `Identity::save` writes — which is exactly what the keychain
/// holds, so the test feeds the guard the same shape production does.
fn secret_bytes(id: &Identity, dir: &std::path::Path, name: &str) -> Vec<u8> {
    let p = dir.join(name);
    id.save(&p).unwrap();
    let b = std::fs::read(&p).unwrap();
    std::fs::remove_file(&p).unwrap();
    b
}

/// The negative control, and the reason this file exists: a DIFFERENT key at
/// the destination must survive.
#[test]
fn a_differing_secret_at_the_destination_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("identity");

    let on_disk = Identity::generate();
    on_disk.save(&dest).unwrap();
    let before = std::fs::read(&dest).unwrap();

    let in_keychain = Identity::generate();
    let incoming = secret_bytes(&in_keychain, dir.path(), "scratch");
    assert_ne!(
        on_disk.did(),
        in_keychain.did(),
        "the two identities must differ for this to test anything"
    );

    let err = refuse_to_overwrite_a_different_secret(
        &dest,
        &incoming,
        AtRest::KeyKeychain,
        &in_keychain.did(),
        "kan-test-account",
    )
    .expect_err("a differing secret at the destination must be refused");

    let msg = err.to_string();
    assert!(
        msg.contains(&on_disk.did().to_string()) && msg.contains(&in_keychain.did().to_string()),
        "the refusal must name BOTH identities -- the operator is the only one who knows \
         which they want, and a refusal that does not say what it found cannot be acted \
         on.\nmessage: {msg}"
    );
    assert_eq!(
        std::fs::read(&dest).unwrap(),
        before,
        "the file must be byte-identical after a refusal"
    );
}

/// The positive half: an identical copy is redundant, not a conflict.
#[test]
fn an_identical_secret_at_the_destination_is_allowed() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("identity");
    let identity = Identity::generate();
    identity.save(&dest).unwrap();

    refuse_to_overwrite_a_different_secret(
        &dest,
        &secret_bytes(&identity, dir.path(), "scratch"),
        AtRest::KeyKeychain,
        &identity.did(),
        "kan-test-account",
    )
    .expect("a byte-identical copy is redundant, not a conflict");
}

/// An absent destination is the ordinary case and must not be obstructed.
#[test]
fn an_absent_destination_is_allowed() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::generate();
    refuse_to_overwrite_a_different_secret(
        &dir.path().join("identity"),
        &secret_bytes(&identity, dir.path(), "scratch"),
        AtRest::KeyKeychain,
        &identity.did(),
        "kan-test-account",
    )
    .expect("nothing to overwrite");
}

/// "I cannot tell" must not collapse into "they match". A destination holding
/// bytes that are not a usable key still differs, so it is still refused —
/// and the refusal says so rather than naming a DID it could not derive.
#[test]
fn an_unreadable_secret_at_the_destination_is_also_refused() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("identity");
    std::fs::write(&dest, b"not a key at all").unwrap();

    let incoming = Identity::generate();
    let err = refuse_to_overwrite_a_different_secret(
        &dest,
        &secret_bytes(&incoming, dir.path(), "scratch"),
        AtRest::KeyKeychain,
        &incoming.did(),
        "kan-test-account",
    )
    .expect_err("an unreadable destination differs, so it must be refused");
    assert!(
        err.to_string().contains("an unreadable secret"),
        "the refusal must say it could not read the destination rather than inventing a \
         DID for it: {err}"
    );
}

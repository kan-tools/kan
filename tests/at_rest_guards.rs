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

/// **B1 + B5 of the re-review.** The `KAN_IDENTITY_FILE` refusal — the blocking
/// finding of the previous round — shipped with NO test: deleting both blocks
/// left the suite byte-for-byte green, which is the branch's own AC-3.7
/// violated by the commit answering a review.
///
/// And its predecessor here defended neither refusal it named. It asserted
/// `!out.status.success() || cmd == "unprotect"`, unconditionally true for half
/// the loop; and the `protect` half stayed green with the guard removed,
/// because `keychain_entry` independently returns `None`. A test that passes
/// when the thing it names is deleted is not a test of that thing.
///
/// So: one test per refusal, each naming the exact condition, each verified by
/// deleting its own guard.
#[test]
fn protect_refuses_when_a_selection_is_active_and_writes_nothing() {
    let (dir, kan) = workspace();
    let key = dir.path().join("role.key");
    std::fs::write(&key, [0u8; 32]).unwrap();

    let before = fingerprint(&dir.path().join(".kan"));
    let out = std::process::Command::new(&kan)
        .args(["identity", "protect", "--yes"])
        .current_dir(dir.path())
        .env("KAN_IDENTITY_FILE", &key)
        // Belt as well as braces: if the guard under test is ever removed or
        // reordered, without this `cargo test` writes a real entry into the
        // developer's login keychain. That has happened twice in this repo.
        // A cold review measured that it does not weaken the test -- with the
        // guard deleted AND this set, it still goes red.
        .env("KAN_NO_KEYCHAIN", "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        !out.status.success(),
        "protect must refuse under a selection.\n{stderr}"
    );
    assert!(
        stderr.contains("KAN_IDENTITY_FILE") && stderr.contains(&key.display().to_string()),
        "the refusal must NAME the selection -- `protect` moves the identity the WORKSPACE \
         owns, and the operator needs to see which other identity kan thinks is signing.\n{stderr}"
    );
    assert_eq!(
        before,
        fingerprint(&dir.path().join(".kan")),
        "a refusal must happen before any write"
    );
}

#[test]
fn unprotect_refuses_when_a_selection_is_active_and_writes_nothing() {
    let (dir, kan) = workspace();
    let key = dir.path().join("role.key");
    std::fs::write(&key, [0u8; 32]).unwrap();

    let before = fingerprint(&dir.path().join(".kan"));
    let out = std::process::Command::new(&kan)
        .args(["identity", "unprotect", "--yes"])
        .current_dir(dir.path())
        .env("KAN_IDENTITY_FILE", &key)
        // Belt as well as braces: if the guard under test is ever removed or
        // reordered, without this `cargo test` writes a real entry into the
        // developer's login keychain. That has happened twice in this repo.
        // A cold review measured that it does not weaken the test -- with the
        // guard deleted AND this set, it still goes red.
        .env("KAN_NO_KEYCHAIN", "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        !out.status.success(),
        "unprotect must refuse under a selection.\n{stderr}"
    );
    assert!(stderr.contains("KAN_IDENTITY_FILE"), "{stderr}");
    assert_eq!(before, fingerprint(&dir.path().join(".kan")));
}

/// `protect` under `KAN_NO_KEYCHAIN` refuses AND writes nothing.
///
/// Separated from the selection tests because the previous combined version
/// could not fail: with the guard deleted, `keychain_entry` still returns
/// `None`, so behaviour stayed safe and the test stayed green while asserting
/// it had proved the guard. This asserts the message, which only the guard
/// produces.
#[test]
fn protect_refuses_under_no_keychain_and_writes_nothing() {
    let (dir, kan) = workspace();
    let before = fingerprint(&dir.path().join(".kan"));
    let out = std::process::Command::new(&kan)
        .args(["identity", "protect", "--yes"])
        .current_dir(dir.path())
        .env("KAN_NO_KEYCHAIN", "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains("KAN_NO_KEYCHAIN is set"),
        "the refusal must come from the KAN_NO_KEYCHAIN guard specifically, not from a \
         downstream failure that happens to also stop the write.\n{stderr}"
    );
    assert_eq!(before, fingerprint(&dir.path().join(".kan")));
}

/// A workspace with one claim, and the path to the built binary.
fn workspace() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    for args in [
        vec!["init", "-q", "."],
        vec![
            "-c",
            "user.email=t@e.com",
            "-c",
            "user.name=t",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "i",
        ],
    ] {
        assert!(std::process::Command::new("git")
            .args(&args)
            .current_dir(dir.path())
            .status()
            .unwrap()
            .success());
    }
    let kan_dir = dir.path().join(".kan");
    std::fs::create_dir_all(&kan_dir).unwrap();
    Identity::generate()
        .save(&kan_dir.join("identity"))
        .unwrap();
    let kan = env!("CARGO_BIN_EXE_kan").to_string();
    assert!(std::process::Command::new(&kan)
        .args(["observe", "x", "--subject", "s"])
        .current_dir(dir.path())
        .env("KAN_NO_KEYCHAIN", "1")
        .output()
        .unwrap()
        .status
        .success());
    (dir, kan)
}

/// Every file under a directory, with its bytes — so a changed, added or
/// removed file all show up.
fn fingerprint(dir: &std::path::Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if let Ok(b) = std::fs::read(&p) {
                out.push((p.display().to_string(), b));
            }
        }
    }
    out.sort();
    out
}

// ------------------------------------------------------------ the executors
//
// Reachable at last. A cold review found the one defect here that could
// destroy a secret -- `protect` deleting the pointer it had just written --
// and observed that the seam had been drawn one layer too shallow: every
// EXTRACTED part was correct and defended, while the executor nothing could
// reach was the part that was wrong. `SecretStore` is that seam, and these
// tests drive the real `protect_from` / `unprotect_to`.

use kan::sign::{at_rest, protect_from, unprotect_to, SecretStore, Seed};
use std::sync::Mutex;

/// An in-memory store. What the reviewer proved costs almost nothing.
#[derive(Default)]
struct FakeStore(Mutex<std::collections::HashMap<(String, String), Vec<u8>>>);

impl SecretStore for FakeStore {
    fn get(&self, s: &str, a: &str) -> Result<Option<Vec<u8>>, kan::sign::Error> {
        Ok(self.0.lock().unwrap().get(&(s.into(), a.into())).cloned())
    }
    fn set(&self, s: &str, a: &str, b: &[u8]) -> Result<(), kan::sign::Error> {
        self.0
            .lock()
            .unwrap()
            .insert((s.into(), a.into()), b.to_vec());
        Ok(())
    }
}

/// THE REGRESSION TEST FOR THE POINTER BUG. A workspace holding a seed AND a
/// stale `seed-id` must come out of `protect` still resolvable.
///
/// Before the fix: `protect_from` wrote the new account into `.kan/seed-id`,
/// the caller read that file back, reported the new account as the old one,
/// and deleted it — leaving the secret in the keychain with nothing naming it.
/// The reviewer reproduced it end to end: exit 0, "protected", and every
/// subsequent write refused.
#[test]
fn protect_over_a_stale_pointer_leaves_the_workspace_resolvable() {
    let dir = tempfile::tempdir().unwrap();
    let kan_dir = dir.path().join(".kan");
    std::fs::create_dir_all(&kan_dir).unwrap();

    let seed = Seed::generate();
    seed.save(&kan_dir.join("seed")).unwrap();
    std::fs::write(kan_dir.join("seed-id"), "kan-STALEACCOUNT").unwrap();
    let before = seed.signing_identity().unwrap().did();

    let store = FakeStore::default();
    let (did, account, orphaned) = protect_from(&kan_dir, AtRest::SeedFile, &store).unwrap();

    assert_eq!(did, before, "protect must never change the DID");
    assert_eq!(
        orphaned.as_deref(),
        Some("kan-STALEACCOUNT"),
        "the displaced account must be reported so the orphaned entry is not silent -- and \
         it must be the OLD one, not the new one that was just written"
    );
    assert_eq!(
        std::fs::read_to_string(kan_dir.join("seed-id"))
            .unwrap()
            .trim(),
        account,
        "the pointer must name the NEW account. It was being deleted here, which left the \
         secret in the store with nothing naming it"
    );
    assert_eq!(
        store.get("dev.kan.seed", &account).unwrap().unwrap(),
        std::fs::read(kan_dir.join("seed")).unwrap(),
        "the store must hold exactly the bytes the file held"
    );
}

/// `unprotect` round-trips the DID, and the pointer only goes after the write.
#[test]
fn unprotect_restores_the_same_identity_and_retires_the_pointer_last() {
    let dir = tempfile::tempdir().unwrap();
    let kan_dir = dir.path().join(".kan");
    std::fs::create_dir_all(&kan_dir).unwrap();

    let seed = Seed::generate();
    let bytes = {
        let p = kan_dir.join("scratch");
        seed.save(&p).unwrap();
        let b = std::fs::read(&p).unwrap();
        std::fs::remove_file(&p).unwrap();
        b
    };
    let store = FakeStore::default();
    store.set("dev.kan.seed", "kan-ACC", &bytes).unwrap();
    std::fs::write(kan_dir.join("seed-id"), "kan-ACC").unwrap();
    assert_eq!(at_rest(&kan_dir), AtRest::SeedKeychain);

    let did = unprotect_to(&kan_dir, AtRest::SeedKeychain, "seed", &store).unwrap();

    assert_eq!(
        did,
        seed.signing_identity().unwrap().did(),
        "the DID must not move"
    );
    assert_eq!(std::fs::read(kan_dir.join("seed")).unwrap(), bytes);
    assert!(
        !kan_dir.join("seed-id").exists(),
        "the pointer is retired once the file holds the secret"
    );
    assert_eq!(at_rest(&kan_dir), AtRest::SeedFile);
}

/// The destroy-class guard, now through the real executor rather than the
/// extracted predicate: a DIFFERENT secret at the destination survives.
#[test]
fn unprotect_through_the_executor_refuses_to_clobber_a_differing_secret() {
    let dir = tempfile::tempdir().unwrap();
    let kan_dir = dir.path().join(".kan");
    std::fs::create_dir_all(&kan_dir).unwrap();

    let on_disk = Seed::generate();
    on_disk.save(&kan_dir.join("seed")).unwrap();
    let untouched = std::fs::read(kan_dir.join("seed")).unwrap();

    let in_store = Seed::generate();
    let other = {
        let p = kan_dir.join("scratch");
        in_store.save(&p).unwrap();
        let b = std::fs::read(&p).unwrap();
        std::fs::remove_file(&p).unwrap();
        b
    };
    let store = FakeStore::default();
    store.set("dev.kan.seed", "kan-ACC", &other).unwrap();
    std::fs::write(kan_dir.join("seed-id"), "kan-ACC").unwrap();

    let err = unprotect_to(&kan_dir, AtRest::SeedKeychain, "seed", &store)
        .expect_err("a differing secret at the destination must be refused");
    assert!(err.to_string().contains("DIFFERENT"), "{err}");
    assert_eq!(
        std::fs::read(kan_dir.join("seed")).unwrap(),
        untouched,
        "the file must survive byte-identical"
    );
    assert!(
        kan_dir.join("seed-id").exists(),
        "and the pointer must survive too -- a refusal that retired it would strand the \
         store's copy"
    );
}

/// **B4 of the re-review: the regression test defended the wrong hunk.**
///
/// The shipped bug was `protect_identity` calling `remove_file` on the pointer
/// after `protect_from` had just written it — the secret left in the keychain
/// with nothing naming it. The regression test added for it drives
/// `protect_from` directly, so reintroducing the bug where it actually lived
/// left the whole suite green. A cold review proved that by putting the
/// `remove_file` back.
///
/// `protect_identity` cannot be driven from here — it needs a `Workspace` and
/// the real `OsKeychain`. So this catches **the verbatim regression** and
/// nothing more: a `remove_file` on the same line as `ptr`.
///
/// It does not generalise, and a cold review showed both edges: binding the
/// path to a local first (`let stale = kan_dir.join(ptr);`) walks past it, and
/// a `write` or `rename` strands the secret just as thoroughly while passing.
/// Renaming an unrelated local to contain `ptr` makes it false-red. Stated
/// rather than repaired, because a source-text assertion cannot be made to
/// mean more than this and pretending otherwise is the failure it is guarding.
#[test]
fn the_protect_caller_never_removes_a_pointer_file() {
    let src = std::fs::read_to_string("src/actions.rs").unwrap();
    let start = src
        .find("pub fn protect_identity")
        .expect("protect_identity moved; update this test");
    let end = src[start..]
        .find("\npub fn unprotect_identity")
        .map(|o| start + o)
        .unwrap_or(src.len());
    let body = &src[start..end];

    // Narrowly: a POINTER removal. Deleting the plaintext copy is this
    // command's job and must stay allowed -- the first version of this test
    // banned every `remove_file` and failed on correct code, which is its own
    // small lesson about assertions written from the shape of a bug rather
    // than from the property being protected.
    let offenders: Vec<&str> = body
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .filter(|l| l.contains("remove_file"))
        .filter(|l| l.contains("ptr") || l.contains("_ID_FILE"))
        .collect();
    assert!(
        offenders.is_empty(),
        "`protect_identity` removes a file: {offenders:?}\n\n\
         It must not. `protect_from` writes the pointer, which IS the retirement of any \
         previous one -- a `remove_file` here deletes the reference just written and leaves \
         the secret in the keychain with nothing naming it. That shipped once, exited 0 \
         saying \"protected\", and made every subsequent write refuse."
    );
}

/// `unprotect` under `KAN_NO_KEYCHAIN` refuses, and the refusal comes from
/// that guard rather than from a downstream absence.
///
/// **B1's exact shape, surviving in the commit that answered B1.** The
/// previous round replaced a combined test with "three tests, one per guard" —
/// but there are four guards in this family (protect/unprotect × selection ×
/// no-keychain) and only three were written. Deleting this one left the full
/// suite byte-identical.
///
/// Without the guard `unprotect` still refuses, because `keychain_entry`
/// returns `None` and the executor reports an empty store — so nothing is lost.
/// It blames the keychain for an absence kan itself was told to invent, which
/// is why the assertion is on the message and not on the exit code.
#[test]
fn unprotect_refuses_under_no_keychain_and_writes_nothing() {
    let (dir, kan) = workspace();
    let kan_dir = dir.path().join(".kan");
    // A pointer, so `plan_unprotect` reaches the executor rather than
    // answering "already unprotected" before the guard is consulted.
    std::fs::write(kan_dir.join("seed-id"), "kan-TESTACCOUNT").unwrap();
    std::fs::remove_file(kan_dir.join("seed")).ok();

    let before = fingerprint(&kan_dir);
    let out = std::process::Command::new(&kan)
        .args(["identity", "unprotect", "--yes"])
        .current_dir(dir.path())
        .env("KAN_NO_KEYCHAIN", "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains("KAN_NO_KEYCHAIN is set"),
        "the refusal must come from the KAN_NO_KEYCHAIN guard, not from a downstream \
         empty-store report that happens to also stop the write.\nstderr: {stderr}"
    );
    assert_eq!(before, fingerprint(&kan_dir));
}

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

/// A REFUSED `protect` OR `unprotect` LEAVES `.kan/` BYTE-IDENTICAL.
///
/// The executors take several steps — read a secret, write it to the other
/// store, verify, then retire the old reference — and the design specifies an
/// ordering so that a death partway through cannot lose an identity. Almost
/// none of that is reachable from this suite, because both commands need a
/// real keychain (#96), and that is a stated limit rather than a gap care can
/// close.
///
/// What IS reachable is the one failure mode this suite can trigger on demand:
/// the `KAN_NO_KEYCHAIN` refusal. It happens at the very top of both
/// executors, which is where AC-8's "resolution has no side effects" argument
/// says a refusal belongs — refusing BEFORE the first write is what guarantees
/// there is no half-state to reason about at all. This asserts that placement
/// rather than trusting it, and it is worth having because the first version
/// of `protect` did NOT refuse here: it wrote a real entry to the author's
/// login keychain.
#[test]
fn a_refused_at_rest_command_writes_nothing() {
    for cmd in ["protect", "unprotect"] {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
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
                .current_dir(repo)
                .status()
                .unwrap()
                .success());
        }
        let kan = env!("CARGO_BIN_EXE_kan");
        assert!(std::process::Command::new(kan)
            .args(["observe", "x", "--subject", "s"])
            .current_dir(repo)
            .env("KAN_NO_KEYCHAIN", "1")
            .output()
            .unwrap()
            .status
            .success());

        let before = fingerprint(&repo.join(".kan"));
        let out = std::process::Command::new(kan)
            .args(["identity", cmd, "--yes"])
            .current_dir(repo)
            .env("KAN_NO_KEYCHAIN", "1")
            .output()
            .unwrap();
        let after = fingerprint(&repo.join(".kan"));

        assert!(
            !out.status.success() || cmd == "unprotect",
            "`kan identity {cmd}` must refuse under KAN_NO_KEYCHAIN -- that flag means \
             behave as though no keychain exists, and a command that writes to one anyway \
             is ignoring it rather than honouring it"
        );
        assert_eq!(
            before,
            after,
            "`kan identity {cmd}` changed .kan/ despite refusing. A refusal must happen \
             BEFORE the first write, or there is a half-state to reason about -- which is \
             the whole reason the terminal gate and this check sit at the top of the \
             executor rather than partway down.\nstderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
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

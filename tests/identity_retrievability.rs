//! `.design/v0.7-milestone.md` REQ-5 — the identity must be retrievable.
//!
//! Two independent failures, on different axes:
//!
//! 1. The keychain account was the canonicalized `.kan/identity` **path**, so
//!    moving or renaming a checkout missed the lookup, silently generated a
//!    new keypair and DID, and made every prior claim vanish from every read
//!    at exit 0 — `TrustBase::Solo` trusts exactly one `AuthorId`.
//! 2. On macOS the keychain entry is ACL'd to the **binary that created it**,
//!    so a different kan binary blocks forever on an authorization prompt
//!    that never arrives non-interactively. That is every upgrade, and every
//!    `cargo build` during development.
//!
//! (2) cannot be reproduced in-process — it needs two differently-signed
//! binaries and a GUI — so what is tested here is the escape hatch that makes
//! it survivable: an explicit key file that never touches the keychain.

use kan::sign::{Identity, IDENTITY_FILE_ENV};

/// REQ-5, axis 1: a checkout that moves keeps its identity.
///
/// The identity-id file travels with `.kan/`, so the keychain account name
/// travels with it too.
#[test]
fn a_moved_checkout_keeps_its_did() {
    let root = tempfile::tempdir().unwrap();
    let before_dir = root.path().join("before");
    std::fs::create_dir_all(&before_dir).unwrap();

    // Use the explicit-file path so this test is hermetic: it must not touch
    // (or depend on) the developer's real OS keychain.
    let key_file = before_dir.join("identity");
    let did_before = {
        temp_env_var(IDENTITY_FILE_ENV, Some(key_file.as_os_str()), || {
            Identity::load_or_create(&before_dir.join("identity"))
                .unwrap()
                .did()
        })
    };

    let after_dir = root.path().join("after");
    std::fs::rename(&before_dir, &after_dir).unwrap();

    let moved_key_file = after_dir.join("identity");
    let did_after = temp_env_var(IDENTITY_FILE_ENV, Some(moved_key_file.as_os_str()), || {
        Identity::load_or_create(&after_dir.join("identity"))
            .unwrap()
            .did()
    });

    assert_eq!(
        did_before, did_after,
        "moving a checkout must not silently mint a new identity -- every \
         prior claim would drop out of every read under Solo trust"
    );
}

/// REQ-5, axis 2: the escape hatch is real. With the override set, the
/// keychain is never consulted, so no ACL prompt can block — the property CI,
/// containers, MCP servers and `day` (ADR-42) depend on.
#[test]
fn the_explicit_key_file_is_used_and_is_stable() {
    let dir = tempfile::tempdir().unwrap();
    let key_file = dir.path().join("ci-key");

    let first = temp_env_var(IDENTITY_FILE_ENV, Some(key_file.as_os_str()), || {
        Identity::load_or_create(&dir.path().join("unused-identity"))
            .unwrap()
            .did()
    });

    assert!(
        key_file.exists(),
        "the override path must be where the key actually lands"
    );
    assert!(
        !dir.path().join("unused-identity").exists(),
        "with the override set, the default location must not be written at all"
    );

    let second = temp_env_var(IDENTITY_FILE_ENV, Some(key_file.as_os_str()), || {
        Identity::load_or_create(&dir.path().join("unused-identity"))
            .unwrap()
            .did()
    });
    assert_eq!(first, second, "the same key file must yield the same DID");
}

/// A file holding a private key must not be world-readable. This repo's own
/// `.kan/identity` shipped as `0644`, so the check runs on load as well as
/// save — an existing loose file gets tightened rather than merely not
/// re-loosened.
#[cfg(unix)]
#[test]
fn the_key_file_is_owner_only_and_loose_permissions_are_repaired() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let key_file = dir.path().join("key");

    temp_env_var(IDENTITY_FILE_ENV, Some(key_file.as_os_str()), || {
        Identity::load_or_create(&dir.path().join("identity")).unwrap();
    });
    let mode = std::fs::metadata(&key_file).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "a freshly written key must be 0600");

    // Loosen it the way a pre-v0.7 kan would have left it, then load again.
    let mut perms = std::fs::metadata(&key_file).unwrap().permissions();
    perms.set_mode(0o644);
    std::fs::set_permissions(&key_file, perms).unwrap();

    temp_env_var(IDENTITY_FILE_ENV, Some(key_file.as_os_str()), || {
        Identity::load_or_create(&dir.path().join("identity")).unwrap();
    });
    let mode = std::fs::metadata(&key_file).unwrap().permissions().mode();
    assert_eq!(
        mode & 0o777,
        0o600,
        "loading an existing world-readable key file must tighten it"
    );
}

/// Serializes every env-var manipulation in this binary. Rust runs tests in
/// one process on parallel threads, so without this the tests clobber each
/// other's `KAN_IDENTITY_FILE` and read each other's keys — which is exactly
/// what happened the first time these were run.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Set an env var for the duration of `f`, then restore it. Tests in one
/// binary share a process, so leaking this would silently redirect every
/// later test's identity.
fn temp_env_var<T>(key: &str, value: Option<&std::ffi::OsStr>, f: impl FnOnce() -> T) -> T {
    let _serialized = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let previous = std::env::var_os(key);
    match value {
        Some(v) => unsafe { std::env::set_var(key, v) },
        None => unsafe { std::env::remove_var(key) },
    }
    let out = f();
    match previous {
        Some(v) => unsafe { std::env::set_var(key, v) },
        None => unsafe { std::env::remove_var(key) },
    }
    out
}

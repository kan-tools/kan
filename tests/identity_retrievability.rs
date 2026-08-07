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
//!
//! **Rewritten by v0.12 REQ-3.5 (#183).** These tests reached
//! `Identity::load_or_create`, which `src/` no longer calls, and they drove it
//! through `KAN_IDENTITY_FILE` — which REQ-2 demoted from "redefine this
//! workspace's identity" to a *selection*. The properties are unchanged and
//! still worth asserting; what changed is that they are now asserted against
//! the functions the product actually uses (`workspace_identity`,
//! `signing_identity`), so they can fail when those break.

use kan::sign::{signing_identity, workspace_identity, Identity, Selection};

/// REQ-5, axis 1: a checkout that moves keeps its identity.
///
/// Asserted against `workspace_identity`, which is the single precedence order
/// both reads and writes now share (REQ-1/REQ-4) — so this covers `kan
/// identity did` and `--trust me` at once rather than one of them.
///
/// Hermetic by construction: the workspace is rooted in a key file inside
/// `.kan/`, so no keychain is consulted on any platform and the test cannot
/// depend on the developer's own login keychain.
#[test]
fn a_moved_checkout_keeps_its_did() {
    let root = tempfile::tempdir().unwrap();
    let before = root.path().join("before/.kan");

    let original = Identity::generate();
    original.save(&before.join("identity")).unwrap();

    let did_before = workspace_identity(&before)
        .unwrap()
        .expect("a workspace holding a key file must resolve an identity")
        .did();

    let after = root.path().join("after/.kan");
    std::fs::create_dir_all(after.parent().unwrap()).unwrap();
    std::fs::rename(before.parent().unwrap(), after.parent().unwrap()).unwrap();

    let did_after = workspace_identity(&after)
        .unwrap()
        .expect("the moved workspace must still resolve an identity")
        .did();

    assert_eq!(
        did_before, did_after,
        "moving a checkout must not silently mint a new identity -- every \
         prior claim would drop out of every read under Solo trust"
    );
    assert_eq!(
        original.did(),
        did_after,
        "and it must be the SAME key, not merely a stable one -- a resolver \
         that consistently returned the wrong identity would satisfy the \
         comparison above"
    );
}

/// REQ-5, axis 2: the escape hatch is real. With a key file selected, the
/// keychain is never consulted, so no ACL prompt can block — the property CI,
/// containers, MCP servers and `day` (ADR-42) depend on.
///
/// **The selection no longer creates the key** (REQ-2): a selection naming
/// something absent is always an error, never a mint. So the key is written
/// first and the assertion is that the selection *uses* it, which is what the
/// escape hatch was ever about.
#[test]
fn the_explicit_key_file_is_used_and_is_stable() {
    let dir = tempfile::tempdir().unwrap();
    let kan_dir = dir.path().join(".kan");
    let key_file = dir.path().join("ci-key");

    let expected = Identity::generate();
    expected.save(&key_file).unwrap();

    let selection = Selection::KeyFile(key_file.clone());
    let first = signing_identity(&kan_dir, &selection)
        .unwrap()
        .expect("a selection naming an existing key must resolve it")
        .did();

    assert_eq!(
        expected.did(),
        first,
        "the selected key file must be the one that signs"
    );
    assert!(
        !kan_dir.join("identity").exists(),
        "with a key file selected, the workspace's own location must not be written at all"
    );
    assert!(
        !kan_dir.join("seed").exists() && !kan_dir.join("seed-id").exists(),
        "and no root seed may be created either -- resolution has no side effects (AC-8)"
    );

    let second = signing_identity(&kan_dir, &selection)
        .unwrap()
        .expect("resolution must be repeatable")
        .did();
    assert_eq!(first, second, "the same key file must yield the same DID");
}

/// A file holding a private key must not be world-readable.
///
/// **The repair-on-load half of this test was deleted by v0.12 REQ-3.5**, and
/// the deletion is the point rather than a casualty. It asserted that loading
/// an existing `0644` key file tightened it to `0600` — a *read* changing a
/// file's permissions, which is exactly one of the three violations
/// `.design/v0.12-milestone.md` AC-8 required to go, and which #183 confirmed
/// by execution no longer happens.
///
/// What remains is the half that is still true and still load-bearing:
/// anything **kan itself writes** is owner-only. A key file kan did not write
/// is the operator's to chmod, and kan will no longer silently reach into it.
#[cfg(unix)]
#[test]
fn a_key_file_kan_writes_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let key_file = dir.path().join("nested/key");

    Identity::generate().save(&key_file).unwrap();

    let mode = std::fs::metadata(&key_file).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "a freshly written key must be 0600");
}

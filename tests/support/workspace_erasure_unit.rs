// Small owner-only fixture. No real workspace or capture is opened.
use super::*;
use std::os::unix::fs::PermissionsExt;
fn fixture() -> (tempfile::TempDir, Workspace) {
    let dir = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let mut seed = tempfile::NamedTempFile::new().unwrap();
    seed.write_all(&[6; 32]).unwrap();
    let w = Workspace::open(
        &dir.path().join("test.sqlite"),
        Identity::load_existing(seed.path()).unwrap(),
        [8; 32],
    )
    .unwrap();
    (dir, w)
}
#[test]
fn scoped_erasure_commitments_are_keyed_and_legacy_unknown_remains_incomplete() {
    let (dir, w) = fixture();
    let a = w
        .authored_collection_commitment("proof:collection-a")
        .unwrap();
    assert_ne!(
        a,
        w.authored_collection_commitment("proof:collection-b")
            .unwrap()
    );
    assert_eq!(a.len(), 64);
    assert!(!a.contains("collection-a"));
    drop(w);
    let mut seed = tempfile::NamedTempFile::new().unwrap();
    seed.write_all(&[6; 32]).unwrap();
    let w = Workspace::open_for_erasure(
        &dir.path().join("test.sqlite"),
        Identity::load_existing(seed.path()).unwrap(),
        [8; 32],
    )
    .unwrap();
    assert_eq!(
        a,
        w.authored_collection_commitment("proof:collection-a")
            .unwrap()
    );
    // Older/untyped annotation payloads provide no safe scope witness. Their
    // exact legacy marker shape must keep ALL collections incomplete.
    // Exercise the same missing-body marker that old binaries emitted.
    let plan = w
        .preview_erasure(
            &[("annotation".into(), "already-absent".into())],
            "b".repeat(64),
        )
        .unwrap();
    w.apply_erasure(&plan).unwrap();
    w.apply_erasure(&plan).unwrap();
    assert!(w.annotation_history_erased("proof:collection-a").unwrap());
    assert!(w.annotation_history_erased("proof:collection-b").unwrap());
    let (markers, next) = w.declarations_page("erasure", None, 100).unwrap();
    assert!(next.is_none());
    assert_eq!(markers.len(), 1);
    assert_eq!(markers[0]["version"], 1);
    assert!(markers[0].get("authored_collections").is_none());
}

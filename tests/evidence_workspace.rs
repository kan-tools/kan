#![cfg(feature = "v2-crypto")]
use kan::{evidence_workspace::Workspace, sign::Identity};
use serde_json::json;
use std::io::Write;
fn identity(n: u8) -> Identity {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(&[n; 32]).unwrap();
    Identity::load_existing(f.path()).unwrap()
}
#[test]
fn encrypted_workspace_survives_restart_and_refuses_wrong_keys_substitution_and_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("workspace.sqlite");
    let value = json!({"title":"unique private owner view","targets":["a"],"text":"hidden needle"});
    let w = Workspace::open(&path, identity(6), [8; 32]).unwrap();
    w.put("view", "first", value.clone()).unwrap();
    w.put("view", "first", value.clone()).unwrap();
    assert!(w.put("view", "first", json!({"different":true})).is_err());
    w.put("search-page", "page", json!({"raw":"source secret"}))
        .unwrap();
    drop(w);
    let bytes = std::fs::read(&path).unwrap();
    for plain in [
        "unique private owner view",
        "hidden needle",
        "source secret",
    ] {
        assert!(!bytes.windows(plain.len()).any(|b| b == plain.as_bytes()));
    }
    assert!(Workspace::open(&path, identity(7), [8; 32]).is_err());
    assert!(Workspace::open(&path, identity(6), [9; 32]).is_err());
    let w = Workspace::open(&path, identity(6), [8; 32]).unwrap();
    assert_eq!(w.get("view", "first").unwrap(), Some(value.clone()));
    assert_eq!(w.views().unwrap(), vec![value]);
    drop(w);
    let db = rusqlite::Connection::open(&path).unwrap();
    let copied: Vec<u8> = db
        .query_row(
            "SELECT body FROM entries WHERE kind='search-page'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    db.execute("UPDATE entries SET body=? WHERE kind='view'", [copied])
        .unwrap();
    drop(db);
    let w = Workspace::open(&path, identity(6), [8; 32]).unwrap();
    assert!(w.get("view", "first").is_err());
    assert!(w.views().is_err());
}
#[test]
fn large_projection_chunks_are_authenticated_and_hot_journals_are_not_implicitly_recovered() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("workspace.sqlite");
    let w = Workspace::open(&path, identity(6), [8; 32]).unwrap();
    let value = json!({"text":"x".repeat(2*1024*1024)});
    w.put("search-page", "large", value.clone()).unwrap();
    assert_eq!(w.get("search-page", "large").unwrap(), Some(value));
    assert!(w
        .put("view", "oversized", json!({"text":"x".repeat(262144)}))
        .is_err());
    drop(w);
    std::fs::write(dir.path().join("workspace.sqlite-journal"), b"interrupted").unwrap();
    assert!(Workspace::open(&path, identity(6), [8; 32]).is_err());
}
#[cfg(unix)]
#[test]
fn workspace_refuses_public_files_symlinks_and_hardlinks() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("workspace.sqlite");
    drop(Workspace::open(&path, identity(6), [8; 32]).unwrap());
    let alias = dir.path().join("alias.sqlite");
    symlink(&path, &alias).unwrap();
    assert!(Workspace::open(&alias, identity(6), [8; 32]).is_err());
    std::fs::remove_file(&alias).unwrap();
    std::fs::hard_link(&path, &alias).unwrap();
    assert!(Workspace::open(&path, identity(6), [8; 32]).is_err());
    std::fs::remove_file(&alias).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Workspace::open(&path, identity(6), [8; 32]).is_err());
}

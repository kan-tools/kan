#![cfg(feature = "v2-crypto")]
use kan::{evidence_workspace::Workspace, sign::Identity};
use serde_json::json;
use std::io::Write;
fn identity(n: u8) -> Identity {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(&[n; 32]).unwrap();
    Identity::load_existing(f.path()).unwrap()
}
fn private_directory() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    dir
}
#[test]
fn encrypted_workspace_survives_restart_and_refuses_wrong_keys_substitution_and_overwrite() {
    let dir = private_directory();
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
    let dir = private_directory();
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
    let dir = private_directory();
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

#[test]
fn workspace_crash_fixture() {
    let Some(path) = std::env::var_os("KAN_WORKSPACE_CRASH_FIXTURE") else {
        return;
    };
    let db = rusqlite::Connection::open(path).unwrap();
    db.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA cache_size=1; BEGIN IMMEDIATE; UPDATE entries SET body=zeroblob(length(body));").unwrap();
    // Deliberately bypass Drop so SQLite cannot roll back the simulated crash.
    std::process::exit(0);
}

#[test]
fn explicit_workspace_recovery_rolls_back_only_the_new_copy_and_verifies_every_entry() {
    let dir = private_directory();
    let path = dir.path().join("workspace.sqlite");
    let value = json!({"title":"preserve the owner declaration"});
    let large = json!({"text":"source evidence".repeat(12000)});
    let w = Workspace::open(&path, identity(6), [8; 32]).unwrap();
    w.put("view", "first", value.clone()).unwrap();
    w.put("search-page", "large", large.clone()).unwrap();
    assert!(Workspace::recover(
        &path,
        &dir.path().join("active.sqlite"),
        identity(6),
        [8; 32]
    )
    .is_err());
    assert!(!dir.path().join("active.sqlite").exists());
    drop(w);
    assert!(std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "workspace_crash_fixture", "--nocapture"])
        .env("KAN_WORKSPACE_CRASH_FIXTURE", &path)
        .status()
        .unwrap()
        .success());
    let journal = dir.path().join("workspace.sqlite-journal");
    let source_bytes = std::fs::read(&path).unwrap();
    let journal_bytes = std::fs::read(&journal).unwrap();
    assert_eq!(
        &journal_bytes[..8],
        &[0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7]
    );
    assert!(Workspace::open(&path, identity(6), [8; 32]).is_err());
    let output = dir.path().join("recovered.sqlite");
    let report = Workspace::recover(&path, &output, identity(6), [8; 32]).unwrap();
    assert_eq!(report["authenticated_entries"]["view"], 1);
    assert_eq!(report["rollback_journal_present"], true);
    assert_eq!(report["activation"], "not-performed");
    let restored = Workspace::open(&output, identity(6), [8; 32]).unwrap();
    assert_eq!(restored.get("view", "first").unwrap(), Some(value));
    assert_eq!(restored.get("search-page", "large").unwrap(), Some(large));
    drop(restored);
    assert_eq!(std::fs::read(&path).unwrap(), source_bytes);
    assert_eq!(std::fs::read(&journal).unwrap(), journal_bytes);
    assert!(Workspace::recover(&path, &output, identity(6), [8; 32]).is_err());
    assert!(Workspace::recover(
        &path,
        &dir.path().join("wrong-key.sqlite"),
        identity(6),
        [9; 32]
    )
    .is_err());
    assert_eq!(std::fs::read(&journal).unwrap(), journal_bytes);
}

#[test]
fn workspace_recovery_cli_preserves_history_and_rejects_corrupt_entries_and_journals() {
    let dir = private_directory();
    let path = dir.path().join("workspace.sqlite");
    let w = Workspace::open(&path, identity(6), [8; 32]).unwrap();
    w.put("annotation", "first", json!({"text":"owner note"}))
        .unwrap();
    drop(w);
    let mut signing = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
    signing.write_all(&[6; 32]).unwrap();
    let mut key = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
    key.write_all(&[8; 32]).unwrap();
    let output = dir.path().join("cli.sqlite");
    let run = std::process::Command::new(env!("CARGO_BIN_EXE_kan-v2"))
        .arg("recover-workspace")
        .arg(&path)
        .arg(&output)
        .arg("--signing-key")
        .arg(signing.path())
        .arg("--recipient-key")
        .arg(key.path())
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&run.stdout).unwrap();
    assert_eq!(report["authenticated_entries"]["annotation"], 1);
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute("UPDATE entries SET body=x'00' WHERE kind='annotation'", [])
        .unwrap();
    drop(db);
    assert!(
        Workspace::recover(&path, &dir.path().join("bad.sqlite"), identity(6), [8; 32]).is_err()
    );
    let journal = dir.path().join("workspace.sqlite-journal");
    std::fs::write(&journal, b"invalid journal").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert!(Workspace::recover(
        &path,
        &dir.path().join("bad-journal.sqlite"),
        identity(6),
        [8; 32]
    )
    .is_err());
    assert_eq!(std::fs::read(&journal).unwrap(), b"invalid journal");
}

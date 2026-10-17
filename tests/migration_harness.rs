//! Self-writer checks qualify the matrix driver, not cross-release migration.
use std::process::Command;

#[test]
fn current_writer_seed_and_identity_file_reach_reader_and_preserve_authorship() {
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("sentinel"), b"unchanged").unwrap();
    for mode in ["seed", "identity-file"] {
        let output = Command::new("bash")
            .arg("scripts/run-migration-cell.sh")
            .args([env!("CARGO_BIN_EXE_kan"), env!("CARGO_BIN_EXE_kan"), mode])
            .env("KAN_CONFIG_DIR", outside.path())
            .env("KAN_NO_KEYCHAIN", "1")
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "commit.gpgsign")
            .env("GIT_CONFIG_VALUE_0", "false")
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "ok",
            "{mode}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("all 3 pre-existing claims survived")
        );
    }
    assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 1);
    assert_eq!(
        std::fs::read(outside.path().join("sentinel")).unwrap(),
        b"unchanged"
    );
}

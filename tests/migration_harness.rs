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

#[cfg(unix)]
#[test]
fn scoped_writer_keychain_cells_are_excluded_before_any_credential_action() {
    use std::os::unix::fs::PermissionsExt;
    let t = tempfile::tempdir().unwrap();
    let fake = t.path().join("writer");
    std::fs::write(&fake,b"#!/bin/sh\ncase \"$*\" in\n 'identity init --help'|'init --help') exit 0;;\n *) echo FORBIDDEN-CREDENTIAL-ACTION >&2; exit 99;;\nesac\n").unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o700)).unwrap();
    for mode in ["keychain", "keychain-recovery"] {
        // Fake binary can only answer help probes; no real keychain API exists.
        let output = Command::new("bash")
            .arg("scripts/run-migration-cell.sh")
            .arg(&fake)
            .arg(&fake)
            .arg(mode)
            .env("CI", "true")
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "commit.gpgsign")
            .env("GIT_CONFIG_VALUE_0", "false")
            .output()
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "keychain-unused",
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!String::from_utf8_lossy(&output.stderr).contains("FORBIDDEN-CREDENTIAL-ACTION"));
    }
}

use clap::Parser;
use kan::{
    cli::{run, Cli},
    identity::{
        did_kan_update::DidKanResolution, ledger::IdentityLedger, system::SystemIdentityStore,
    },
    sign::Identity,
};

fn init_args(config: &std::path::Path) -> Vec<String> {
    vec![
        "kan".to_string(),
        "identity".to_string(),
        "init".to_string(),
        "--config-dir".to_string(),
        config.display().to_string(),
    ]
}

#[tokio::test]
async fn init_runs_without_a_repository_and_identical_retry_is_idempotent() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("system-config");
    assert!(!temp.path().join(".kan").exists());

    run(Cli::parse_from(init_args(&config))).await.unwrap();
    let store = SystemIdentityStore::at(&config);
    let first = store.default_profile().unwrap().unwrap();
    let nonce = std::fs::read(config.join("identity/profiles/enrollment-nonce")).unwrap();
    let events = IdentityLedger::at(config.join("identity/ledger"))
        .read_all()
        .unwrap();
    assert_eq!(first.alias(), "daily");
    assert!(first.principal().starts_with("did:kan:"));
    assert_eq!(events.len(), 2);

    run(Cli::parse_from(init_args(&config))).await.unwrap();
    assert_eq!(store.default_profile().unwrap(), Some(first));
    assert_eq!(
        std::fs::read(config.join("identity/profiles/enrollment-nonce")).unwrap(),
        nonce
    );
    assert_eq!(
        IdentityLedger::at(config.join("identity/ledger"))
            .read_all()
            .unwrap()
            .len(),
        2
    );
    assert!(!temp.path().join(".kan").exists());

    for name in ["recovery-daily.key", "device-daily.key"] {
        let path = config.join("credentials").join(name);
        assert!(path.is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o077,
                0
            );
        }
    }
}

#[tokio::test]
async fn public_identity_resolution_needs_neither_a_profile_nor_credentials() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("system-config");
    run(Cli::parse_from(init_args(&config))).await.unwrap();
    let store = SystemIdentityStore::at(&config);
    let principal = store
        .default_profile()
        .unwrap()
        .unwrap()
        .principal()
        .to_string();

    std::fs::remove_dir_all(config.join("identity/profiles")).unwrap();
    std::fs::remove_dir_all(config.join("credentials")).unwrap();
    assert!(store.default_profile().unwrap().is_none());

    let resolutions = store.resolve_public_identities().unwrap();
    assert_eq!(resolutions.len(), 1);
    let DidKanResolution::Active(state) = &resolutions[0] else {
        panic!("freshly initialized public identity did not resolve active");
    };
    assert_eq!(state.did, principal);
    assert!(!config.join("identity/profiles").exists());
    assert!(!config.join("credentials").exists());
}

#[tokio::test]
async fn init_imports_explicit_credentials_without_copying_the_wrong_key() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("system-config");
    let recovery_source = temp.path().join("recovery-source.key");
    let daily_source = temp.path().join("daily-source.key");
    let recovery = Identity::generate();
    let daily = Identity::generate();
    recovery.save(&recovery_source).unwrap();
    daily.save(&daily_source).unwrap();

    let mut args = init_args(&config);
    args.extend([
        "--alias".to_string(),
        "laptop".to_string(),
        "--recovery-key".to_string(),
        recovery_source.display().to_string(),
        "--daily-key".to_string(),
        daily_source.display().to_string(),
    ]);
    run(Cli::parse_from(args)).await.unwrap();

    assert_eq!(
        Identity::load_existing(&config.join("credentials/recovery-laptop.key"))
            .unwrap()
            .did(),
        recovery.did()
    );
    assert_eq!(
        Identity::load_existing(&config.join("credentials/device-laptop.key"))
            .unwrap()
            .did(),
        daily.did()
    );
    let selected = SystemIdentityStore::at(&config)
        .default_profile()
        .unwrap()
        .unwrap();
    assert_eq!(selected.alias(), "laptop");
    assert!(selected.principal().starts_with("did:kan:"));
}

#[tokio::test]
async fn invalid_alias_is_rejected_before_any_system_state_is_written() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("system-config");
    let mut args = init_args(&config);
    args.extend(["--alias".to_string(), "../escape".to_string()]);

    assert!(run(Cli::parse_from(args)).await.is_err());
    assert!(!config.exists());
}

#[cfg(unix)]
#[tokio::test]
async fn insecure_import_is_rejected_before_any_system_state_is_written() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("system-config");
    let recovery_source = temp.path().join("recovery-source.key");
    let recovery = Identity::generate();
    recovery.save(&recovery_source).unwrap();
    std::fs::set_permissions(&recovery_source, std::fs::Permissions::from_mode(0o644)).unwrap();

    let mut args = init_args(&config);
    args.extend([
        "--recovery-key".to_string(),
        recovery_source.display().to_string(),
    ]);
    assert!(run(Cli::parse_from(args)).await.is_err());
    assert!(!config.exists());
}

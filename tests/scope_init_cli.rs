use clap::Parser;
use kan::{
    cli::{run, Cli, Error as CliError},
    identity::{
        scope_inception::AnchorValue, scope_store::ScopeIdentityStore, system::SystemIdentityStore,
    },
};

fn git(repo: &std::path::Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .status()
        .unwrap();
    assert!(status.success());
}

fn committed_repo(root: &std::path::Path) {
    std::fs::create_dir_all(root).unwrap();
    git(root, &["init", "--quiet"]);
    git(
        root,
        &[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.com",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "--allow-empty",
            "-m",
            "genesis",
        ],
    );
}

fn system_init_args(config: &std::path::Path) -> Vec<String> {
    vec![
        "kan".to_string(),
        "identity".to_string(),
        "init".to_string(),
        "--config-dir".to_string(),
        config.display().to_string(),
    ]
}

fn scope_init_args(repo: &std::path::Path, config: &std::path::Path) -> Vec<String> {
    vec![
        "kan".to_string(),
        "init".to_string(),
        "--repository".to_string(),
        repo.display().to_string(),
        "--config-dir".to_string(),
        config.display().to_string(),
    ]
}

#[tokio::test]
async fn init_uses_the_system_actor_without_creating_a_legacy_workspace_identity() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("project");
    let config = temp.path().join("system-config");
    committed_repo(&repo);
    run(Cli::parse_from(system_init_args(&config)))
        .await
        .unwrap();

    run(Cli::parse_from(scope_init_args(&repo, &config)))
        .await
        .unwrap();
    let installed = ScopeIdentityStore::at(repo.join(".kan/scope"))
        .read()
        .unwrap()
        .unwrap();
    let actor = SystemIdentityStore::at(&config)
        .default_profile()
        .unwrap()
        .unwrap();
    assert_eq!(
        installed.inception.governance_roots,
        vec![actor.principal().to_string()]
    );
    assert_eq!(installed.inception.names, vec!["project"]);
    assert_eq!(installed.inception.anchors.len(), 1);
    assert_eq!(installed.inception.anchors[0].anchor_type, "gitGenesis");
    assert!(matches!(
        &installed.inception.anchors[0].value,
        AnchorValue::Text(_)
    ));
    for legacy in ["seed", "seed-id", "identity", "identity-id", "log"] {
        assert!(!repo.join(".kan").join(legacy).exists());
    }
}

#[tokio::test]
async fn identical_init_is_idempotent_and_keeps_the_same_scope_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("project");
    let config = temp.path().join("system-config");
    committed_repo(&repo);
    run(Cli::parse_from(system_init_args(&config)))
        .await
        .unwrap();
    let args = scope_init_args(&repo, &config);
    run(Cli::parse_from(args.clone())).await.unwrap();
    let inception = repo.join(".kan/scope/inception.cbor");
    let nonce = repo.join(".kan/scope/initialization-nonce");
    let first_event = std::fs::read(&inception).unwrap();
    let first_nonce = std::fs::read(&nonce).unwrap();

    std::fs::remove_dir_all(&config).unwrap();
    run(Cli::parse_from(args)).await.unwrap();
    assert_eq!(std::fs::read(inception).unwrap(), first_event);
    assert_eq!(std::fs::read(nonce).unwrap(), first_nonce);
}

#[tokio::test]
async fn explicit_reinitialization_is_idempotent_or_refuses_a_changed_inception() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("project");
    let config = temp.path().join("system-config");
    committed_repo(&repo);
    run(Cli::parse_from(system_init_args(&config)))
        .await
        .unwrap();
    let mut stable = scope_init_args(&repo, &config);
    stable.extend(["--name".to_string(), "stable-name".to_string()]);
    run(Cli::parse_from(stable.clone())).await.unwrap();
    let inception = repo.join(".kan/scope/inception.cbor");
    let first_event = std::fs::read(&inception).unwrap();

    run(Cli::parse_from(stable)).await.unwrap();
    let mut changed = scope_init_args(&repo, &config);
    changed.extend(["--name".to_string(), "changed-name".to_string()]);
    assert!(run(Cli::parse_from(changed)).await.is_err());
    assert_eq!(std::fs::read(inception).unwrap(), first_event);
}

#[tokio::test]
async fn missing_system_identity_refuses_before_scope_state_exists() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("project");
    let config = temp.path().join("missing-system-config");
    committed_repo(&repo);

    assert!(run(Cli::parse_from(scope_init_args(&repo, &config)))
        .await
        .is_err());
    assert!(!repo.join(".kan").exists());
}

#[tokio::test]
async fn pre_release_repository_state_is_never_reinterpreted_or_mutated() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("project");
    let config = temp.path().join("system-config");
    committed_repo(&repo);
    let old_state = repo.join(".kan/repository");
    std::fs::create_dir_all(&old_state).unwrap();
    let marker = old_state.join("inception.cbor");
    std::fs::write(&marker, b"pre-release bytes").unwrap();

    let error = run(Cli::parse_from(scope_init_args(&repo, &config)))
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        CliError::PreReleaseRepositoryIdentity(path) if path == old_state
    ));
    assert_eq!(std::fs::read(marker).unwrap(), b"pre-release bytes");
    assert!(!repo.join(".kan/scope").exists());
}

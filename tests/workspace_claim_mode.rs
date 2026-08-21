use kan::{
    claim::v1::{Anchor, AuthorId, ClaimBody, ClaimContent, SubjectRef},
    identity::{
        enrollment::DailyDeviceEnrollment,
        scope_inception::ScopeInception,
        scope_store::ScopeIdentityStore,
        system::{CredentialReference, ResolvedSystemActor, SystemIdentityStore},
        workspace_mode::{classify, InitializationDiagnostic, WorkspaceClaimMode},
    },
    sign::Identity,
    store::log::Log,
};

fn installed_actor(root: &std::path::Path) -> ResolvedSystemActor {
    let recovery = Identity::generate();
    let daily = Identity::generate();
    recovery
        .save(&root.join("credentials/recovery.key"))
        .unwrap();
    daily.save(&root.join("credentials/daily.key")).unwrap();
    DailyDeviceEnrollment::new(
        [0xa1; 32],
        "daily".to_string(),
        &recovery,
        CredentialReference::OwnerOnlyFile {
            path: "recovery.key".to_string(),
        },
        &daily,
        CredentialReference::OwnerOnlyFile {
            path: "daily.key".to_string(),
        },
    )
    .unwrap()
    .install(root)
    .unwrap();
    SystemIdentityStore::at(root)
        .resolve_default_actor()
        .unwrap()
        .unwrap()
}

fn legacy_content(identity: &Identity) -> ClaimContent {
    ClaimContent {
        author: AuthorId {
            did: identity.did(),
            agent: None,
        },
        workspace: Anchor::Workspace("legacy".to_string()),
        subject: SubjectRef::Local("legacy".into()),
        body: ClaimBody::Observation {
            text: "historical".to_string(),
        },
        cites: vec![],
        artifacts: vec![],
        recorded_at: None,
    }
}

#[tokio::test]
async fn empty_workspace_is_uninitialized_and_classification_creates_nothing() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("workspace");
    std::fs::create_dir(&root).unwrap();
    let mut log = Log::open_read_only(&root.join(".kan/log")).await.unwrap();

    assert!(matches!(
        classify(&root, &mut log, None).await.unwrap(),
        WorkspaceClaimMode::Uninitialized
    ));
    assert!(!root.join(".kan").exists());
}

#[tokio::test]
async fn verified_v1_claims_select_only_v1_compatibility() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("workspace");
    let identity = Identity::generate();
    let log_dir = root.join(".kan/log");
    let mut writer = Log::open_or_create(&log_dir, &identity).await.unwrap();
    writer
        .append(legacy_content(&identity), &identity)
        .await
        .unwrap();
    drop(writer);
    let mut log = Log::open_read_only(&log_dir).await.unwrap();

    let WorkspaceClaimMode::V1 { evidence } = classify(&root, &mut log, None).await.unwrap() else {
        panic!("verified legacy claim did not select v1 mode");
    };
    assert_eq!(evidence.claim_count(), 1);
}

#[tokio::test]
async fn partial_scope_state_never_falls_back_to_v1() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("workspace");
    let identity = Identity::generate();
    let log_dir = root.join(".kan/log");
    let mut writer = Log::open_or_create(&log_dir, &identity).await.unwrap();
    writer
        .append(legacy_content(&identity), &identity)
        .await
        .unwrap();
    std::fs::create_dir_all(root.join(".kan/scope")).unwrap();
    let mut log = Log::open_read_only(&log_dir).await.unwrap();

    assert!(matches!(
        classify(&root, &mut log, None).await.unwrap(),
        WorkspaceClaimMode::Incomplete { diagnostics }
            if matches!(diagnostics.as_slice(), [InitializationDiagnostic::PartialScopeState { .. }])
    ));
}

#[tokio::test]
async fn inaccessible_legacy_identity_is_incomplete_not_uninitialized() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("workspace");
    std::fs::create_dir_all(root.join(".kan")).unwrap();
    std::fs::write(root.join(".kan/identity"), b"not a p256 private key").unwrap();
    let mut log = Log::open_read_only(&root.join(".kan/log")).await.unwrap();

    assert!(matches!(
        classify(&root, &mut log, None).await.unwrap(),
        WorkspaceClaimMode::Incomplete { diagnostics }
            if matches!(diagnostics.as_slice(), [InitializationDiagnostic::LegacyIdentityUnavailable { .. }])
    ));
}

#[tokio::test]
async fn pre_release_repository_state_is_an_explicit_incomplete_mode() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("workspace");
    std::fs::create_dir_all(root.join(".kan/repository")).unwrap();
    let mut log = Log::open_read_only(&root.join(".kan/log")).await.unwrap();

    assert!(matches!(
        classify(&root, &mut log, None).await.unwrap(),
        WorkspaceClaimMode::Incomplete { diagnostics }
            if matches!(diagnostics.as_slice(), [InitializationDiagnostic::PreReleaseRepositoryState { .. }])
    ));
}

#[tokio::test]
async fn verified_scope_selects_claim_mode_even_with_v1_history() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("workspace");
    let config = temp.path().join("config");
    let actor = installed_actor(&config);
    let identity = Identity::generate();
    let log_dir = root.join(".kan/log");
    let mut writer = Log::open_or_create(&log_dir, &identity).await.unwrap();
    writer
        .append(legacy_content(&identity), &identity)
        .await
        .unwrap();

    let inception = ScopeInception::new(
        [0xa2; 32],
        vec!["classified".to_string()],
        vec![actor.principal().to_string()],
        vec![],
    )
    .unwrap();
    let system = SystemIdentityStore::at(&config);
    let proof = system
        .sign(
            actor.profile(),
            actor.method(),
            &inception.signing_input().unwrap(),
        )
        .unwrap();
    let event = inception
        .proved_event_with_did_kan_state(actor.state(), vec![proof])
        .unwrap();
    ScopeIdentityStore::at(root.join(".kan/scope"))
        .install(&event)
        .unwrap();
    drop(writer);
    let mut log = Log::open_read_only(&log_dir).await.unwrap();

    let WorkspaceClaimMode::Claim { scope } =
        classify(&root, &mut log, Some(&actor)).await.unwrap()
    else {
        panic!("verified scope did not activate current claim mode");
    };
    assert_eq!(scope.scope(), inception.scope_id().unwrap());
}

#[tokio::test]
async fn installed_scope_without_system_actor_names_the_identity_that_must_be_restored() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("workspace");
    let config = temp.path().join("config");
    let actor = installed_actor(&config);
    let inception = ScopeInception::new(
        [0xa3; 32],
        vec!["classified".to_string()],
        vec![actor.principal().to_string()],
        vec![],
    )
    .unwrap();
    let system = SystemIdentityStore::at(&config);
    let proof = system
        .sign(
            actor.profile(),
            actor.method(),
            &inception.signing_input().unwrap(),
        )
        .unwrap();
    let event = inception
        .proved_event_with_did_kan_state(actor.state(), vec![proof])
        .unwrap();
    ScopeIdentityStore::at(root.join(".kan/scope"))
        .install(&event)
        .unwrap();
    let mut log = Log::open_read_only(&root.join(".kan/log")).await.unwrap();

    let WorkspaceClaimMode::Incomplete { diagnostics } =
        classify(&root, &mut log, None).await.unwrap()
    else {
        panic!("missing system actor was not incomplete");
    };
    assert!(matches!(
        diagnostics.as_slice(),
        [InitializationDiagnostic::SystemIdentityUnavailable { governance_roots }]
            if governance_roots == &[actor.principal().to_string()]
    ));
}

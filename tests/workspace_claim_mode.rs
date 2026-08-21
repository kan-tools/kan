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
    workspace::{Workspace, WorkspaceWriterKind},
};

fn git(root: &std::path::Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .args(["-c", "commit.gpgsign=false"])
        .args(args)
        .current_dir(root)
        .status()
        .unwrap();
    assert!(status.success());
}

fn init_git(root: &std::path::Path) {
    std::fs::create_dir_all(root).unwrap();
    git(root, &["init", "-q"]);
    git(
        root,
        &[
            "-c",
            "user.email=kan-test@example.com",
            "-c",
            "user.name=kan-test",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "init",
        ],
    );
}

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

#[tokio::test]
async fn production_writer_preserves_released_transport_and_appends_current_claims() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("workspace");
    let config = temp.path().join("config");
    init_git(&root);
    let actor = installed_actor(&config);
    let released_owner = Identity::generate();
    let log_dir = root.join(".kan/log");
    let mut released_log = Log::open_or_create(&log_dir, &released_owner)
        .await
        .unwrap();
    released_log
        .append(legacy_content(&released_owner), &released_owner)
        .await
        .unwrap();
    released_owner.save(&root.join(".kan/identity")).unwrap();
    drop(released_log);

    let inception = ScopeInception::new(
        [0xa4; 32],
        vec!["activated".to_string()],
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

    let mut workspace = Workspace::open(&root).await.unwrap();
    assert_eq!(
        workspace.prepare_writer_with_system(&system).await.unwrap(),
        WorkspaceWriterKind::Claim
    );
    assert_eq!(
        kan::identity::transport::LocalRepositoryTransportStore::at(root.join(".kan/transport"))
            .read()
            .unwrap()
            .unwrap()
            .did(),
        released_owner.did()
    );

    let result = kan::actions::observe(
        &mut workspace,
        "current append".to_string(),
        Some("identity/production-writer".to_string()),
        vec![],
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    let cid = result.narrative.cid;
    assert!(workspace
        .index
        .claim_views_built_from_root()
        .unwrap()
        .is_some());
    assert_eq!(
        workspace
            .index
            .all_decoded_claims(kan::claim::codec::VerificationContext::ResolvedIdentities {
                did_kan: std::slice::from_ref(actor.state()),
            },)
            .unwrap()
            .len(),
        2
    );
    let decoded = workspace
        .log
        .get_decoded(
            cid,
            kan::claim::codec::VerificationContext::ActiveDidKan(actor.state()),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        decoded.claim,
        kan::claim::codec::DecodedClaim::Supported(kan::claim::codec::SupportedClaim::Claim(_))
    ));
    drop(workspace);

    let mut reader = Workspace::open_read_only_with_system(&root, &system)
        .await
        .unwrap();
    let projection = reader
        .mixed_local_projection_with_system(&system)
        .await
        .unwrap();
    assert_eq!(projection.claims().len(), 2);
    assert_eq!(projection.identity_resolutions().len(), 1);
    assert_eq!(
        projection.legacy_scope(),
        Some(inception.scope_id().unwrap())
    );
    let current = projection
        .claims()
        .iter()
        .find(|claim| matches!(claim.source(), kan::claim::view::ClaimSource::Claim(_)))
        .unwrap();
    assert_eq!(
        current.judgments().identity_state_standing,
        kan::identity::IdentityStateStanding::Active
    );
    assert_eq!(
        current.judgments().scope_admission,
        kan::identity::ScopeAdmission::Admitted
    );
    assert_eq!(projection.fold().classes.len(), 2);
}

#[tokio::test]
async fn production_writer_refuses_an_uninitialized_workspace_without_creating_kan_state() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("workspace");
    let config = temp.path().join("config");
    init_git(&root);
    let mut workspace = Workspace::open(&root).await.unwrap();

    assert!(matches!(
        workspace
            .prepare_writer_with_system(&SystemIdentityStore::at(&config))
            .await,
        Err(kan::workspace::Error::ClaimInitializationRequired)
    ));
    assert!(!root.join(".kan").exists());
}

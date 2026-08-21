use std::{collections::BTreeMap, path::Path};

use kan::{
    claim::view::ClaimSource,
    identity::{
        control::ControlEvent,
        enrollment::DailyDeviceEnrollment,
        scope_inception::ScopeInception,
        scope_store::ScopeIdentityStore,
        system::{CredentialReference, ResolvedSystemActor, SystemIdentityStore},
    },
    sign::Identity,
    uri::{
        local::{LocalResolver, PrincipalResolution, ResolvedResource},
        Resource,
    },
    workspace::Workspace,
};

fn git(root: &Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .args(["-c", "commit.gpgsign=false"])
        .args(args)
        .current_dir(root)
        .status()
        .unwrap();
    assert!(status.success());
}

fn init_git(root: &Path) {
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

fn installed_actor(root: &Path) -> ResolvedSystemActor {
    let recovery = Identity::generate();
    let daily = Identity::generate();
    recovery
        .save(&root.join("credentials/recovery.key"))
        .unwrap();
    daily.save(&root.join("credentials/daily.key")).unwrap();
    DailyDeviceEnrollment::new(
        [0xb1; 32],
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

async fn current_workspace() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    std::path::PathBuf,
    ResolvedSystemActor,
    atproto_dasl::Cid,
) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("workspace");
    let config = temp.path().join("config");
    init_git(&root);
    let actor = installed_actor(&config);
    let system = SystemIdentityStore::at(&config);
    let inception = ScopeInception::new(
        [0xb2; 32],
        vec!["kan-tools:kan".to_string()],
        vec![actor.principal().to_string()],
        vec![],
    )
    .unwrap();
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
    workspace.prepare_writer_with_system(&system).await.unwrap();
    let claim = kan::actions::observe(
        &mut workspace,
        "URI-native evidence".to_string(),
        Some("design/local-uri".to_string()),
        vec![],
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap()
    .narrative
    .cid;
    drop(workspace);
    let index = root.join(".kan/index.sqlite");
    if index.exists() {
        std::fs::remove_file(index).unwrap();
    }
    (temp, root, config, actor, claim)
}

#[tokio::test]
async fn named_direct_claim_subject_and_identity_routes_share_one_snapshot() {
    let (_temp, root, config, actor, claim) = current_workspace().await;
    let system = SystemIdentityStore::at(&config);
    let resolver = LocalResolver::new(&root, &system);

    let subject = resolver
        .resolve_uri("kan://local/kan-tools:kan/subject/design/local-uri")
        .await
        .unwrap();
    let scope = subject.target.scope.unwrap();
    assert!(matches!(
        subject.resource,
        ResolvedResource::Subject(ref result)
            if result.evidence.len() == 1
                && matches!(result.evidence[0].source(), ClaimSource::Claim(_))
    ));
    assert_eq!(subject.claim_evaluations.len(), 1);
    assert_eq!(subject.claim_evaluations[0].claim, claim);
    assert_eq!(
        subject.claim_evaluations[0].judgments.scope_admission,
        kan::identity::ScopeAdmission::Admitted
    );
    assert_eq!(
        subject.sources[0].access,
        kan::uri::local::SourceAccess::Available
    );
    assert!(subject.sources[0].diagnostics.is_empty());

    let claim_result = resolver
        .resolve_uri(&format!("kan://local/kan-tools:kan/claim/{claim}"))
        .await
        .unwrap();
    assert_eq!(
        claim_result.sources[0].snapshot,
        subject.sources[0].snapshot
    );
    assert!(matches!(claim_result.target.resource, Resource::Claim(_)));

    let named_scope = resolver
        .resolve_uri("kan://local/kan-tools:kan/identity/scope")
        .await
        .unwrap();
    let direct_scope = resolver
        .resolve_uri(&format!("kan://local/@id:{scope}/identity/scope"))
        .await
        .unwrap();
    assert_eq!(named_scope.target, direct_scope.target);
    assert_eq!(named_scope.sources, direct_scope.sources);
    assert!(matches!(
        direct_scope.resource,
        ResolvedResource::ScopeIdentity(ref identity)
            if identity.identifier == scope
                && identity.standing == kan::uri::local::ScopeIdentityStanding::Active
                && identity.governance.len() == 1
    ));

    let principal = resolver
        .resolve_uri(&format!(
            "kan://local/kan-tools:kan/identity/principal/did/kan/{}",
            actor.principal().strip_prefix("did:kan:").unwrap()
        ))
        .await
        .unwrap();
    assert!(matches!(
        principal.resource,
        ResolvedResource::PrincipalIdentity(ref identity)
            if matches!(identity.resolution, PrincipalResolution::DidKan(_))
    ));

    let freestanding = resolver
        .resolve_uri(&format!(
            "kan://did/kan/{}/identity",
            actor.principal().strip_prefix("did:kan:").unwrap()
        ))
        .await
        .unwrap();
    assert!(freestanding.target.scope.is_none());
    assert_ne!(
        freestanding.sources[0].snapshot,
        subject.sources[0].snapshot
    );

    let static_identity = Identity::generate().did().to_string();
    let static_freestanding = resolver
        .resolve_uri(&format!(
            "kan://did/key/{}/identity",
            static_identity.strip_prefix("did:key:").unwrap()
        ))
        .await
        .unwrap();
    assert!(matches!(
        static_freestanding.resource,
        ResolvedResource::PrincipalIdentity(ref identity)
            if identity.principal.to_string() == static_identity
                && identity.resolution == PrincipalResolution::Static
    ));

    let replay = resolver
        .resolve_uri(&subject.immutable_replay)
        .await
        .unwrap();
    assert_eq!(replay.immutable_replay, subject.immutable_replay);
    assert_eq!(replay.target, subject.target);
}

#[tokio::test]
async fn resolution_is_byte_read_only_even_when_the_disposable_index_is_absent() {
    let (_temp, root, config, _actor, _claim) = current_workspace().await;
    let before = tree_bytes(root.parent().unwrap());
    let system = SystemIdentityStore::at(&config);
    let resolver = LocalResolver::new(&root, &system);
    resolver
        .resolve_uri("kan://local/kan-tools:kan/subject/design/local-uri?trust=me")
        .await
        .unwrap();
    assert_eq!(tree_bytes(root.parent().unwrap()), before);
    assert!(!root.join(".kan/index.sqlite").exists());
}

#[tokio::test]
async fn linked_worktree_ownership_is_refused_until_issue_197_is_settled() {
    let (_temp, root, config, _actor, _claim) = current_workspace().await;
    let worktree = root.parent().unwrap().join("linked-worktree");
    git(
        &root,
        &[
            "worktree",
            "add",
            "-q",
            "-b",
            "uri-linked-worktree",
            worktree.to_str().unwrap(),
        ],
    );
    let before = tree_bytes(root.parent().unwrap());
    let system = SystemIdentityStore::at(&config);
    let resolver = LocalResolver::new(&worktree, &system);
    let error = resolver
        .resolve_uri("kan://local/kan-tools:kan/subject/design/local-uri")
        .await
        .unwrap_err();
    assert_eq!(error.code(), "unsupported");
    assert!(error.to_string().contains("workspace ownership"));
    assert_eq!(tree_bytes(root.parent().unwrap()), before);
}

#[tokio::test]
async fn scope_identity_preserves_invalid_governance_instead_of_hiding_the_scope() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("workspace");
    let config = temp.path().join("config");
    init_git(&root);
    let actor = installed_actor(&config);
    let inception = ScopeInception::new(
        [0xb4; 32],
        vec!["invalid:governance".to_string()],
        vec![actor.principal().to_string()],
        vec![],
    )
    .unwrap();
    let input = inception.signing_input().unwrap();
    let system = SystemIdentityStore::at(&config);
    let mut invalid_proof = system
        .sign(actor.profile(), actor.method(), &input)
        .unwrap();
    invalid_proof.sig[0] ^= 1;
    let unproved = ControlEvent::new(input, vec![invalid_proof]).unwrap();
    ScopeIdentityStore::at(root.join(".kan/scope"))
        .install(&unproved)
        .unwrap();

    let resolver = LocalResolver::new(&root, &system);
    let result = resolver
        .resolve_uri("kan://local/invalid:governance/identity/scope")
        .await
        .unwrap();
    assert!(matches!(
        result.resource,
        ResolvedResource::ScopeIdentity(ref identity)
            if identity.standing == kan::uri::local::ScopeIdentityStanding::Invalid
    ));
}

#[tokio::test]
async fn local_failures_do_not_fall_forward() {
    let (_temp, root, config, actor, claim) = current_workspace().await;
    let system = SystemIdentityStore::at(&config);
    let resolver = LocalResolver::new(&root, &system);
    let other_scope = ScopeInception::new(
        [0xb3; 32],
        vec!["other:scope".to_string()],
        vec![actor.principal().to_string()],
        vec![],
    )
    .unwrap()
    .scope_id()
    .unwrap();
    let cases = [
        (
            "kan://local/wrong:scope/subject/design/local-uri".to_string(),
            "scope-not-found",
        ),
        (
            format!("kan://local/@id:{other_scope}/subject/design/local-uri"),
            "scope-identifier-mismatch",
        ),
        (
            "kan://local/kan-tools:kan/subject/missing".to_string(),
            "resource-not-found-at-snapshot",
        ),
        (
            "kan://local/kan-tools:kan/subject/design/local-uri?source=missing".to_string(),
            "source-not-found",
        ),
        (
            "kan://local/kan-tools:kan/subject/design/local-uri?snapshot=bafyreidwqmyomktbm6jgsktjt6s7fa4bvjeoukvmlsqnaiktooonvnzx7q".to_string(),
            "snapshot-unavailable",
        ),
        ("kan://local/identity".to_string(), "authority-identity-unknown"),
        (
            format!("kan://local/kan-tools:kan/claim/{claim}0"),
            "non-canonical-identifier",
        ),
    ];
    for (uri, code) in cases {
        assert_eq!(
            resolver.resolve_uri(&uri).await.unwrap_err().code(),
            code,
            "{uri}"
        );
    }
}

fn tree_bytes(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(base: &Path, path: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        let mut entries = std::fs::read_dir(path)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let relative = path
                .strip_prefix(base)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                out.insert(format!("d:{relative}"), Vec::new());
                walk(base, &path, out);
            } else if kind.is_symlink() {
                out.insert(
                    format!("l:{relative}"),
                    std::fs::read_link(path)
                        .unwrap()
                        .to_string_lossy()
                        .as_bytes()
                        .to_vec(),
                );
            } else {
                out.insert(format!("f:{relative}"), std::fs::read(path).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

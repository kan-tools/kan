use atproto_dasl::{car::CarReader, Cid};
use atproto_repo::Commit;
use kan::{
    claim::{
        codec::{DecodedClaim, SupportedClaim, VerificationContext},
        CanonicalSet, ClaimBody, ClaimContent, NarrativeText, RecordedAt, SubjectPath,
        UniqueSequence,
    },
    identity::{
        authorship::Author,
        enrollment::DailyDeviceEnrollment,
        scope_inception::ScopeInception,
        scope_store::{ScopeIdentityStore, VerifiedScope},
        system::{CredentialReference, ResolvedSystemActor, SystemIdentityStore},
    },
    sign::Identity,
    store::log::{Error as LogError, Log, RepositoryTransportSigner},
};

fn installed_actor(root: &std::path::Path, nonce: u8) -> ResolvedSystemActor {
    let recovery = Identity::generate();
    let daily = Identity::generate();
    recovery
        .save(&root.join("credentials/recovery.key"))
        .unwrap();
    daily.save(&root.join("credentials/daily.key")).unwrap();
    DailyDeviceEnrollment::new(
        [nonce; 32],
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

fn content(actor: &ResolvedSystemActor, scope: &VerifiedScope) -> ClaimContent {
    ClaimContent::new(
        Author::new(
            actor.principal().to_string(),
            actor.profile().actor().verification_method().to_string(),
            actor.profile().actor().controller_state().clone(),
        )
        .unwrap(),
        scope.scope(),
        None,
        SubjectPath::new("identity/system-repository".to_string()).unwrap(),
        CanonicalSet::new(vec![]).unwrap(),
        ClaimBody::Observation {
            text: NarrativeText::new("system actor owns commit and claim".to_string()).unwrap(),
        },
        CanonicalSet::new(vec![]).unwrap(),
        UniqueSequence::new(vec![]).unwrap(),
        RecordedAt::new(1).unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn kan_actor_authorship_and_atproto_repository_approval_stay_separate() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("config");
    let scope_dir = temp.path().join("workspace");
    let actor = installed_actor(&config, 0x81);

    let inception = ScopeInception::new(
        [0x91; 32],
        vec!["system-log".to_string()],
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
    let scope_store = ScopeIdentityStore::at(scope_dir.join("scope"));
    scope_store.install(&event).unwrap();
    let scope = scope_store
        .read_verified_did_kan(actor.state())
        .unwrap()
        .unwrap();

    let claim = actor.sign_claim(content(&actor, &scope)).unwrap();
    let log_dir = scope_dir.join("log");
    let transport = Identity::generate();
    let transport_signer = RepositoryTransportSigner::LocalDidKey(&transport);
    assert_ne!(transport.did(), actor.principal());
    let mut log = Log::open_or_create_transport(&log_dir, &transport_signer)
        .await
        .unwrap();
    let id = log
        .append_current(claim.clone(), &scope, &transport_signer)
        .await
        .unwrap();
    let decoded = log
        .get_decoded(id, VerificationContext::ActiveDidKan(actor.state()))
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        decoded.claim,
        DecodedClaim::Supported(SupportedClaim::Claim(decoded)) if decoded == claim
    ));

    let head: Cid = std::fs::read_to_string(log_dir.join("HEAD"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let bytes = std::fs::read(log_dir.join("repo.car")).unwrap();
    let mut reader = CarReader::new(std::io::Cursor::new(bytes)).await.unwrap();
    let mut head_commit = None;
    while let Some(block) = reader.next_block().await.unwrap() {
        if block.cid == *head {
            head_commit = Some(Commit::from_bytes(&block.data).unwrap());
            break;
        }
    }
    let head_commit = head_commit.unwrap();
    assert_eq!(head_commit.did, transport.did());
    assert!(kan::sign::verify(
        &transport.did(),
        &head_commit.signing_bytes().unwrap(),
        &head_commit.sig
    ));

    let before = std::fs::read(log_dir.join("repo.car")).unwrap();
    let unrelated_transport = Identity::generate();
    assert!(matches!(
        Log::open_or_create_transport(
            &log_dir,
            &RepositoryTransportSigner::LocalDidKey(&unrelated_transport),
        )
        .await,
        Err(LogError::RepositoryDidMismatch { .. })
    ));
    assert_eq!(std::fs::read(log_dir.join("repo.car")).unwrap(), before);
}

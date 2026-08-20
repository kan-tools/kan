use kan::{
    claim::{
        codec::{DecodedClaim, SupportedClaim, VerificationContext},
        v1, CanonicalSet, Claim, ClaimBody, ClaimContent, NarrativeText, RecordedAt, SubjectPath,
        UniqueSequence,
    },
    identity::{
        authorship::Author,
        control::{IdentityVersion, Proof},
        scope_inception::ScopeInception,
        scope_store::{ScopeIdentityStore, VerifiedScope},
    },
    sign::Identity,
    store::log::Log,
};

fn activation(root: &std::path::Path, identity: &Identity, nonce: u8) -> VerifiedScope {
    let inception = ScopeInception::new(
        [nonce; 32],
        vec!["mixed".to_string()],
        vec![identity.did()],
        vec![],
    )
    .unwrap();
    let input = inception.signing_input().unwrap();
    let did = identity.did();
    let proof = Proof {
        method: format!("{did}#{}", did.strip_prefix("did:key:").unwrap()),
        controller_state: IdentityVersion::Static,
        alg: "P256".to_string(),
        sig: identity.sign(&input.canonical_bytes().unwrap()).unwrap(),
    };
    let event = inception.proved_event(vec![proof]).unwrap();
    let store = ScopeIdentityStore::at(root.join("scope"));
    store.install(&event).unwrap();
    store.read_verified_static().unwrap().unwrap()
}

fn current(identity: &Identity, scope: &VerifiedScope, subject: &str) -> Claim {
    let principal = identity.did();
    let fingerprint = principal.strip_prefix("did:key:").unwrap();
    let author = Author::new(
        principal.clone(),
        format!("{principal}#{fingerprint}"),
        IdentityVersion::Static,
    )
    .unwrap();
    let content = ClaimContent::new(
        author,
        scope.scope(),
        None,
        SubjectPath::new(subject.to_string()).unwrap(),
        CanonicalSet::new(vec![]).unwrap(),
        ClaimBody::Observation {
            text: NarrativeText::new("current observation".to_string()).unwrap(),
        },
        CanonicalSet::new(vec![]).unwrap(),
        UniqueSequence::new(vec![]).unwrap(),
        RecordedAt::new(1).unwrap(),
    )
    .unwrap();
    Claim::sign_static(content, identity).unwrap()
}

fn legacy(identity: &Identity) -> v1::ClaimContent {
    v1::ClaimContent {
        author: v1::AuthorId {
            did: identity.did(),
            agent: None,
        },
        workspace: v1::Anchor::Workspace("legacy-workspace".to_string()),
        subject: v1::SubjectRef::Local("legacy-subject".to_string()),
        body: v1::ClaimBody::Observation {
            text: "legacy observation".to_string(),
        },
        cites: vec![],
        artifacts: vec![],
        recorded_at: None,
    }
}

#[tokio::test]
async fn one_collection_reads_v1_and_v2_without_rewriting_v1() {
    let temp = tempfile::tempdir().unwrap();
    let identity = Identity::generate();
    let mut log = Log::open_or_create(&temp.path().join("log"), &identity)
        .await
        .unwrap();
    let legacy_id = log.append(legacy(&identity), &identity).await.unwrap();
    let before = std::fs::read(temp.path().join("log/repo.car")).unwrap();

    let scope = activation(temp.path(), &identity, 0x41);
    let current = current(&identity, &scope, "design/current");
    let current_id = log
        .append_current(current.clone(), &scope, &identity)
        .await
        .unwrap();
    let after = std::fs::read(temp.path().join("log/repo.car")).unwrap();
    assert!(after.starts_with(&before));

    let mut records = log
        .iter_decoded(VerificationContext::StaticDidKey)
        .await
        .unwrap();
    records.sort_by_key(|record| record.0.to_string());
    assert_eq!(records.len(), 2);
    assert!(records.iter().any(|(id, record)| {
        id == &legacy_id && matches!(record.claim, DecodedClaim::Supported(SupportedClaim::V1(_)))
    }));
    assert!(records.iter().any(|(id, record)| {
        id == &current_id
            && matches!(
                &record.claim,
                DecodedClaim::Supported(SupportedClaim::Claim(decoded)) if decoded == &current
            )
    }));

    // Legacy folds remain available during the ClaimView transition and do
    // not misdecode v2 as v1.
    let legacy_view = log.iter_all().await.unwrap();
    assert_eq!(legacy_view.len(), 1);
    assert_eq!(legacy_view[0].0, legacy_id);

    drop(log);
    let mut reopened = Log::open_read_only(&temp.path().join("log")).await.unwrap();
    assert_eq!(
        reopened
            .iter_decoded(VerificationContext::StaticDidKey)
            .await
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn activated_scope_token_cannot_authorize_a_different_scope() {
    let temp = tempfile::tempdir().unwrap();
    let identity = Identity::generate();
    let mut log = Log::open_or_create(&temp.path().join("log"), &identity)
        .await
        .unwrap();
    let activated = activation(&temp.path().join("a"), &identity, 0x51);
    let different = activation(&temp.path().join("b"), &identity, 0x52);
    let claim = current(&identity, &different, "design/current");

    assert!(matches!(
        log.append_current(claim, &activated, &identity).await,
        Err(kan::store::log::Error::ClaimScopeMismatch { .. })
    ));
    assert!(log.current_root().is_none());
}

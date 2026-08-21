use kan::{
    claim::{
        codec::{DecodedClaim, DecodedRecord, SupportedClaim},
        v1, view, CanonicalSet, Claim, ClaimBody, ClaimContent, NarrativeText, RecordedAt,
        SubjectPath, UniqueSequence,
    },
    fold::claim_view,
    identity::{
        authorship::Author, control::IdentityVersion, scope_inception::ScopeId,
        IdentityStateStanding, ScopeAdmission,
    },
    sign::Identity,
};

fn scope() -> ScopeId {
    ScopeId::from_bytes({
        let mut bytes = [0x61; 34];
        bytes[..2].copy_from_slice(&[0x12, 0x20]);
        bytes
    })
    .unwrap()
}

fn current_claim(identity: &Identity, subject: &str, body: ClaimBody, recorded_at: u64) -> Claim {
    let principal = identity.did();
    let fingerprint = principal.strip_prefix("did:key:").unwrap();
    Claim::sign_static(
        ClaimContent::new(
            Author::new(
                principal.clone(),
                format!("{principal}#{fingerprint}"),
                IdentityVersion::Static,
            )
            .unwrap(),
            scope(),
            None,
            SubjectPath::new(subject.to_string()).unwrap(),
            CanonicalSet::new(vec![]).unwrap(),
            body,
            CanonicalSet::new(vec![]).unwrap(),
            UniqueSequence::new(vec![]).unwrap(),
            RecordedAt::new(recorded_at).unwrap(),
        )
        .unwrap(),
        identity,
    )
    .unwrap()
}

fn legacy_claim(identity: &Identity, subject: &str, body: v1::ClaimBody) -> v1::Claim {
    let content = v1::ClaimContent {
        author: v1::AuthorId {
            did: identity.did(),
            agent: Some(b"historical-agent".to_vec()),
        },
        workspace: v1::Anchor::Workspace("historical".to_string()),
        subject: v1::SubjectRef::Local(subject.to_string()),
        body,
        cites: vec![],
        artifacts: vec![],
        recorded_at: None,
    };
    let id = kan::cid::content_cid(&content).unwrap();
    v1::Claim {
        sig: identity.sign(&id.to_bytes()).unwrap(),
        content,
    }
}

fn views(records: Vec<DecodedRecord>) -> Vec<view::ClaimView> {
    let authors = records.iter().filter_map(|record| match &record.claim {
        DecodedClaim::Supported(SupportedClaim::V1(claim)) => {
            Some(view::ClaimAuthor::V1(claim.content.author.clone()))
        }
        DecodedClaim::Supported(SupportedClaim::Claim(claim)) => Some(
            view::ClaimAuthor::Principal(claim.content().author().principal().to_string()),
        ),
        DecodedClaim::Unsupported(_) => None,
    });
    let trust = view::ClaimTrustBase::local(authors);
    view::project(records, &trust, |_| view::CurrentEvaluation {
        identity_state_standing: IdentityStateStanding::Static,
        scope_admission: ScopeAdmission::Admitted,
    })
    .unwrap()
}

#[test]
fn legacy_local_path_joins_current_scope_only_with_explicit_scope_projection() {
    let identity = Identity::generate();
    let legacy = legacy_claim(
        &identity,
        "design/identity",
        v1::ClaimBody::Observation {
            text: "before".to_string(),
        },
    );
    let current = current_claim(
        &identity,
        "design/identity",
        ClaimBody::Observation {
            text: NarrativeText::new("after".to_string()).unwrap(),
        },
        2,
    );
    let records = vec![
        DecodedRecord {
            claim: DecodedClaim::Supported(SupportedClaim::V1(legacy)),
            rev: "2222222222222".to_string(),
        },
        DecodedRecord {
            claim: DecodedClaim::Supported(SupportedClaim::Claim(current)),
            rev: "2222222222223".to_string(),
        },
    ];

    assert_eq!(
        claim_view::fold(views(records.clone()), None).classes.len(),
        2
    );
    let projected = claim_view::fold(views(records), Some(scope()));
    assert_eq!(projected.classes.len(), 1);
    assert_eq!(projected.classes[0].claims.len(), 2);
}

#[test]
fn current_principal_may_retract_matching_legacy_did_but_not_the_reverse() {
    let identity = Identity::generate();
    let legacy_target = legacy_claim(
        &identity,
        "migration",
        v1::ClaimBody::Observation {
            text: "legacy target".to_string(),
        },
    );
    let legacy_id = kan::cid::content_cid(&legacy_target.content).unwrap();
    let current_retraction = current_claim(
        &identity,
        "migration",
        ClaimBody::Retraction {
            claim: kan::claim::ClaimId::new(legacy_id),
        },
        2,
    );
    let forward = claim_view::fold(
        views(vec![
            DecodedRecord {
                claim: DecodedClaim::Supported(SupportedClaim::V1(legacy_target)),
                rev: "2222222222222".to_string(),
            },
            DecodedRecord {
                claim: DecodedClaim::Supported(SupportedClaim::Claim(current_retraction)),
                rev: "2222222222223".to_string(),
            },
        ]),
        Some(scope()),
    );
    assert_eq!(forward.classes[0].claims.len(), 1);
    assert!(matches!(
        forward.classes[0].claims[0].source(),
        view::ClaimSource::Claim(_)
    ));

    let current_target = current_claim(
        &identity,
        "migration",
        ClaimBody::Observation {
            text: NarrativeText::new("current target".to_string()).unwrap(),
        },
        3,
    );
    let current_id = current_target.id().unwrap().cid().clone();
    let legacy_retraction = legacy_claim(
        &identity,
        "migration",
        v1::ClaimBody::Retraction {
            supersedes: current_id,
        },
    );
    let reverse = claim_view::fold(
        views(vec![
            DecodedRecord {
                claim: DecodedClaim::Supported(SupportedClaim::Claim(current_target)),
                rev: "2222222222224".to_string(),
            },
            DecodedRecord {
                claim: DecodedClaim::Supported(SupportedClaim::V1(legacy_retraction)),
                rev: "2222222222225".to_string(),
            },
        ]),
        Some(scope()),
    );
    assert_eq!(reverse.classes[0].claims.len(), 2);
}

use kan::{
    claim::{
        codec::{DecodedClaim, DecodedRecord, SupportedClaim},
        v1, view, CanonicalSet, Claim, ClaimBody, ClaimContent, ClaimId, RecordedAt, StatusValue,
        SubjectPath, UniqueSequence,
    },
    fold::claim_view_state::{self, StateView},
    identity::{
        authorship::Author, control::IdentityVersion, scope_inception::ScopeId,
        IdentityStateStanding, ScopeAdmission,
    },
    sign::Identity,
};

fn scope() -> ScopeId {
    ScopeId::from_bytes({
        let mut bytes = [0x71; 34];
        bytes[..2].copy_from_slice(&[0x12, 0x20]);
        bytes
    })
    .unwrap()
}

fn current_status(
    identity: &Identity,
    value: StatusValue,
    cites: Vec<ClaimId>,
    recorded_at: u64,
) -> Claim {
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
            SubjectPath::new("roadmap/identity".to_string()).unwrap(),
            CanonicalSet::new(vec![]).unwrap(),
            ClaimBody::Status { value },
            CanonicalSet::new(cites).unwrap(),
            UniqueSequence::new(vec![]).unwrap(),
            RecordedAt::new(recorded_at).unwrap(),
        )
        .unwrap(),
        identity,
    )
    .unwrap()
}

fn legacy_status(identity: &Identity, value: v1::StatusValue) -> v1::Claim {
    let content = v1::ClaimContent {
        author: v1::AuthorId {
            did: identity.did(),
            agent: Some(b"v1-agent".to_vec()),
        },
        workspace: v1::Anchor::Workspace("historical".to_string()),
        subject: v1::SubjectRef::Local("roadmap/identity".to_string()),
        body: v1::ClaimBody::Status { value },
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

fn project(records: Vec<DecodedRecord>) -> Vec<view::ClaimView> {
    let authors: Vec<_> = records
        .iter()
        .filter_map(|record| match &record.claim {
            DecodedClaim::Supported(SupportedClaim::V1(claim)) => {
                Some(view::ClaimAuthor::V1(claim.content.author.clone()))
            }
            DecodedClaim::Supported(SupportedClaim::Claim(claim)) => Some(
                view::ClaimAuthor::Principal(claim.content().author().principal().to_string()),
            ),
            DecodedClaim::Unsupported(_) => None,
        })
        .collect();
    view::project(records, &view::ClaimTrustBase::local(authors), |_| {
        view::CurrentEvaluation {
            identity_state_standing: IdentityStateStanding::Static,
            scope_admission: ScopeAdmission::Admitted,
        }
    })
    .unwrap()
}

#[test]
fn mixed_statuses_agree_without_collapsing_their_author_keys() {
    let legacy_identity = Identity::generate();
    let current_identity = Identity::generate();
    let claims = project(vec![
        DecodedRecord {
            claim: DecodedClaim::Supported(SupportedClaim::V1(legacy_status(
                &legacy_identity,
                v1::StatusValue::Open,
            ))),
            rev: "2222222222222".to_string(),
        },
        DecodedRecord {
            claim: DecodedClaim::Supported(SupportedClaim::Claim(current_status(
                &current_identity,
                StatusValue::Open,
                vec![],
                2,
            ))),
            rev: "2222222222223".to_string(),
        },
    ]);

    assert!(matches!(
        claim_view_state::classify(&claims, &[]),
        StateView::Confirmed {
            value: StatusValue::Open,
            by,
        } if by.len() == 2
    ));
}

#[test]
fn mixed_disagreement_is_contested_until_a_citation_orders_it() {
    let legacy_identity = Identity::generate();
    let current_identity = Identity::generate();
    let legacy = legacy_status(&legacy_identity, v1::StatusValue::Open);
    let legacy_id = kan::cid::content_cid(&legacy.content).unwrap();
    let open_current = current_status(&current_identity, StatusValue::Closed, vec![], 2);
    let unordered = project(vec![
        DecodedRecord {
            claim: DecodedClaim::Supported(SupportedClaim::V1(legacy.clone())),
            rev: "2222222222222".to_string(),
        },
        DecodedRecord {
            claim: DecodedClaim::Supported(SupportedClaim::Claim(open_current)),
            rev: "2222222222223".to_string(),
        },
    ]);
    assert!(matches!(
        claim_view_state::classify(&unordered, &[]),
        StateView::Contested { open, .. } if open.len() == 2
    ));

    let ordered = project(vec![
        DecodedRecord {
            claim: DecodedClaim::Supported(SupportedClaim::V1(legacy)),
            rev: "2222222222222".to_string(),
        },
        DecodedRecord {
            claim: DecodedClaim::Supported(SupportedClaim::Claim(current_status(
                &current_identity,
                StatusValue::Closed,
                vec![ClaimId::new(legacy_id)],
                3,
            ))),
            rev: "2222222222224".to_string(),
        },
    ]);
    assert!(matches!(
        claim_view_state::classify(&ordered, &[]),
        StateView::Settled {
            value: StatusValue::Closed,
            ..
        }
    ));
}

#[test]
fn latest_status_wins_within_one_current_stable_principal() {
    let identity = Identity::generate();
    let claims = project(vec![
        DecodedRecord {
            claim: DecodedClaim::Supported(SupportedClaim::Claim(current_status(
                &identity,
                StatusValue::Open,
                vec![],
                1,
            ))),
            rev: "2222222222222".to_string(),
        },
        DecodedRecord {
            claim: DecodedClaim::Supported(SupportedClaim::Claim(current_status(
                &identity,
                StatusValue::Resolved,
                vec![],
                2,
            ))),
            rev: "2222222222223".to_string(),
        },
    ]);
    assert!(matches!(
        claim_view_state::classify(&claims, &[]),
        StateView::Settled {
            value: StatusValue::Resolved,
            ..
        }
    ));
}

use kan::{
    claim::{
        codec::{DecodedClaim, DecodedRecord, SupportedClaim},
        v1, view, CanonicalSet, Claim, ClaimBody, ClaimContent, NarrativeText, RecordedAt,
        SubjectPath, UniqueSequence,
    },
    fold::TrustBase,
    identity::{
        authorship::Author, control::IdentityVersion, ClaimJudgments, CryptographicValidity,
        IdentityStateStanding, ScopeAdmission, ViewTrust,
    },
    sign::Identity,
};

fn unsupported_record() -> DecodedRecord {
    use std::collections::BTreeMap;

    let claim_id = kan::cid::content_cid(&"future claim").unwrap();
    let content = BTreeMap::from([
        (
            "$type".to_string(),
            atproto_dasl::Ipld::String("tools.kan.defs#claimContentV3".to_string()),
        ),
        (
            "future".to_string(),
            atproto_dasl::Ipld::String("preserve me".to_string()),
        ),
    ]);
    let envelope = atproto_dasl::Ipld::Map(BTreeMap::from([
        (
            "$type".to_string(),
            atproto_dasl::Ipld::String("tools.kan.claim".to_string()),
        ),
        (
            "claimCid".to_string(),
            atproto_dasl::Ipld::String(claim_id.to_string()),
        ),
        (
            "codec".to_string(),
            atproto_dasl::Ipld::String("kan-claim-v3".to_string()),
        ),
        ("content".to_string(), atproto_dasl::Ipld::Map(content)),
        (
            "rev".to_string(),
            atproto_dasl::Ipld::String("2222222222222".to_string()),
        ),
        (
            "signature".to_string(),
            atproto_dasl::Ipld::Bytes(vec![1, 2, 3]),
        ),
    ]));
    kan::claim::codec::decode_record(
        &atproto_dasl::to_vec(&envelope).unwrap(),
        kan::claim::codec::VerificationContext::StaticDidKey,
    )
    .unwrap()
}

fn legacy(identity: &Identity) -> v1::Claim {
    let content = v1::ClaimContent {
        author: v1::AuthorId {
            did: identity.did(),
            agent: Some(b"historical-agent".to_vec()),
        },
        workspace: v1::Anchor::Workspace("historical".to_string()),
        subject: v1::SubjectRef::Local("identity/legacy".to_string()),
        body: v1::ClaimBody::Observation {
            text: "legacy".to_string(),
        },
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

fn current(identity: &Identity) -> Claim {
    let principal = identity.did();
    let fingerprint = principal.strip_prefix("did:key:").unwrap();
    let content = ClaimContent::new(
        Author::new(
            principal.clone(),
            format!("{principal}#{fingerprint}"),
            IdentityVersion::Static,
        )
        .unwrap(),
        kan::identity::scope_inception::ScopeId::from_bytes({
            let mut bytes = [0x71; 34];
            bytes[..2].copy_from_slice(&[0x12, 0x20]);
            bytes
        })
        .unwrap(),
        None,
        SubjectPath::new("identity/current".to_string()).unwrap(),
        CanonicalSet::new(vec![]).unwrap(),
        ClaimBody::Observation {
            text: NarrativeText::new("current".to_string()).unwrap(),
        },
        CanonicalSet::new(vec![]).unwrap(),
        UniqueSequence::new(vec![]).unwrap(),
        RecordedAt::new(1).unwrap(),
    )
    .unwrap();
    Claim::sign_static(content, identity).unwrap()
}

fn admitted() -> ClaimJudgments {
    ClaimJudgments {
        cryptographic_validity: CryptographicValidity::Valid,
        identity_state_standing: IdentityStateStanding::Static,
        scope_admission: ScopeAdmission::Admitted,
        view_trust: ViewTrust::Included,
    }
}

#[test]
fn mixed_projection_preserves_each_source_ontology_and_judgments() {
    let identity = Identity::generate();
    let legacy = legacy(&identity);
    let current = current(&identity);
    let trust = TrustBase::local([legacy.content.author.clone()]);
    let views = view::project(
        vec![
            DecodedRecord {
                claim: DecodedClaim::Supported(SupportedClaim::V1(legacy.clone())),
                rev: "2222222222222".to_string(),
            },
            DecodedRecord {
                claim: DecodedClaim::Supported(SupportedClaim::Claim(current.clone())),
                rev: "2222222222223".to_string(),
            },
        ],
        &trust,
        |_| admitted(),
    )
    .unwrap();

    assert_eq!(views[0].codec(), "kan-claim-v1");
    assert!(matches!(
        views[0].source(),
        view::ClaimSource::V1(source) if source == &legacy
    ));
    assert!(matches!(
        views[0].subject(),
        Some(view::ClaimSubject::V1(v1::SubjectRef::Local(subject)))
            if subject == "identity/legacy"
    ));
    assert_eq!(
        views[0].judgments().scope_admission,
        ScopeAdmission::Unknown
    );

    assert_eq!(views[1].codec(), "kan-claim-v2");
    assert!(matches!(
        views[1].source(),
        view::ClaimSource::Claim(source) if source == &current
    ));
    assert!(matches!(
        views[1].subject(),
        Some(view::ClaimSubject::Claim { subject, .. })
            if subject.as_str() == "identity/current"
    ));
    assert_eq!(views[1].judgments(), admitted());
}

#[test]
fn verified_current_source_cannot_be_reclassified_as_cryptographically_invalid() {
    let identity = Identity::generate();
    let current = current(&identity);
    let trust = TrustBase::local([]);
    let result = view::project(
        [DecodedRecord {
            claim: DecodedClaim::Supported(SupportedClaim::Claim(current)),
            rev: "2222222222222".to_string(),
        }],
        &trust,
        |_| ClaimJudgments {
            cryptographic_validity: CryptographicValidity::Invalid,
            ..admitted()
        },
    );

    assert!(matches!(
        result,
        Err(view::Error::ContradictoryCurrentValidity(
            CryptographicValidity::Invalid
        ))
    ));
}

#[test]
fn unsupported_codec_remains_visible_without_inventing_an_author_or_subject() {
    let trust = TrustBase::local(Vec::<v1::AuthorId>::new());
    let views = view::project([unsupported_record()], &trust, |_| admitted()).unwrap();

    assert_eq!(views[0].codec(), "kan-claim-v3");
    assert!(matches!(
        views[0].source(),
        view::ClaimSource::Unsupported(_)
    ));
    assert_eq!(views[0].principal(), None);
    assert_eq!(views[0].subject(), None);
    assert_eq!(
        views[0].judgments(),
        ClaimJudgments {
            cryptographic_validity: CryptographicValidity::Unsupported,
            identity_state_standing: IdentityStateStanding::Unknown,
            scope_admission: ScopeAdmission::Unknown,
            view_trust: ViewTrust::Excluded,
        }
    );
}

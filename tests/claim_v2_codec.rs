use std::{collections::BTreeMap, num::NonZeroU32};

use atproto_dasl::Ipld;
use kan::{
    claim::{
        codec::{self, DecodedClaim, SupportedClaim, VerificationContext},
        v1, ArtifactRef, CanonicalSet, Claim, ClaimBody, ClaimContent, ClaimId, ClaimSigningInput,
        ControlRef, DelegationId, Did, GitObjectId, GitPath, GovernanceEventId, IdentityEventId,
        LineRange, LineageRelationship, NarrativeText, PublicationTarget, RecordedAt, RelationKind,
        ResourceRef, RevocationId, RoleName, ScopedSubjectRef, Sha1Digest, Sha256Digest,
        StatusValue, SubjectKind, SubjectPath, Title, UniqueSequence,
    },
    identity::{authorship::Author, control::IdentityVersion, scope_inception::ScopeId},
    sign::{self, Identity},
};

const REV: &str = "3jzfcijpj2z2a";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn scope() -> ScopeId {
    let mut bytes = [0_u8; 34];
    bytes[..2].copy_from_slice(&[0x12, 0x20]);
    ScopeId::from_bytes(bytes).unwrap()
}

fn author(identity: &Identity) -> Author {
    let principal = identity.did();
    let fingerprint = principal.strip_prefix("did:key:").unwrap();
    Author::new(
        principal.clone(),
        format!("{principal}#{fingerprint}"),
        IdentityVersion::Static,
    )
    .unwrap()
}

fn content(identity: &Identity) -> ClaimContent {
    ClaimContent::new(
        author(identity),
        scope(),
        None,
        SubjectPath::new("identity/codec".to_string()).unwrap(),
        CanonicalSet::new(vec![]).unwrap(),
        ClaimBody::Observation {
            text: NarrativeText::new("the current claim codec is explicit".to_string()).unwrap(),
        },
        CanonicalSet::new(vec![]).unwrap(),
        UniqueSequence::new(vec![]).unwrap(),
        RecordedAt::new(1).unwrap(),
    )
    .unwrap()
}

fn signed_claim(identity: &Identity) -> Claim {
    Claim::sign_static(content(identity), identity).unwrap()
}

#[test]
fn current_claim_round_trips_through_the_typed_codec_arm() {
    let identity = Identity::generate();
    let claim = signed_claim(&identity);
    let bytes = codec::encode_claim(&claim, REV).unwrap();

    let decoded = codec::decode(&bytes, VerificationContext::StaticDidKey).unwrap();
    let DecodedClaim::Supported(SupportedClaim::Claim(decoded)) = decoded else {
        panic!("current claim decoded through the wrong codec arm");
    };
    assert_eq!(decoded, claim);
    assert_eq!(codec::encode_claim(&decoded, REV).unwrap(), bytes);
}

#[test]
fn v2_signature_is_bound_to_the_codec_and_claim_input_shape() {
    #[derive(serde::Serialize)]
    struct OtherCodecInput<'a> {
        codec: &'a str,
        claim: &'a atproto_dasl::Cid,
    }

    let identity = Identity::generate();
    let claim = signed_claim(&identity);
    let id = claim.id().unwrap();
    let signature = claim.signature().as_bytes();
    let signing_bytes = ClaimSigningInput::new(&id).canonical_bytes().unwrap();
    assert!(sign::verify(&identity.did(), &signing_bytes, signature));
    assert!(!sign::verify(
        &identity.did(),
        &id.cid().to_bytes(),
        signature
    ));

    let v1_bytes = atproto_dasl::to_vec(&OtherCodecInput {
        codec: codec::V1_CODEC,
        claim: id.cid(),
    })
    .unwrap();
    assert!(!sign::verify(&identity.did(), &v1_bytes, signature));

    let control_bytes = kan::identity::control::SigningInput::new(
        "tools.kan.claim.v2",
        "claim",
        Ipld::Map(BTreeMap::from([(
            "claim".to_string(),
            Ipld::Link(id.cid().clone()),
        )])),
    )
    .unwrap()
    .canonical_bytes()
    .unwrap();
    assert!(!sign::verify(&identity.did(), &control_bytes, signature));
}

#[test]
fn claim_signing_input_has_fixed_canonical_bytes() {
    let id = kan::claim::ClaimId::new(
        "bafyreiec2aamsiue2cy5uqgdbxln4fvwywhk3735cwmsrav3jsfgi4ziou"
            .parse()
            .unwrap(),
    );
    assert_eq!(
        hex(&ClaimSigningInput::new(&id).canonical_bytes().unwrap()),
        "a265636c61696dd82a5825000171122082d000c92284d0b1da40c30dd6de16b6c58eadff7d15992882bb4c8a6473287565636f6465636c6b616e2d636c61696d2d7632"
    );
}

#[test]
fn future_codec_and_arm_are_preserved_byte_exactly() {
    let identity = Identity::generate();
    let bytes = codec::encode_claim(&signed_claim(&identity), REV).unwrap();
    let mut raw: Ipld = atproto_dasl::from_reader(&bytes[..]).unwrap();
    let Ipld::Map(fields) = &mut raw else {
        unreachable!()
    };
    fields.insert(
        "codec".to_string(),
        Ipld::String("kan-claim-v3".to_string()),
    );
    let Some(Ipld::Map(content)) = fields.get_mut("content") else {
        unreachable!()
    };
    content.insert(
        "$type".to_string(),
        Ipld::String("tools.kan.defs#claimContentV3".to_string()),
    );
    content.insert("futureField".to_string(), Ipld::Bool(true));
    let future = atproto_dasl::to_vec(&raw).unwrap();

    let DecodedClaim::Unsupported(preserved) =
        codec::decode(&future, VerificationContext::StaticDidKey).unwrap()
    else {
        panic!("future codec was interpreted as supported");
    };
    assert_eq!(preserved.codec(), "kan-claim-v3");
    assert_eq!(preserved.content_type(), "tools.kan.defs#claimContentV3");
    assert_eq!(preserved.canonical_bytes(), future);
}

#[test]
fn contradictory_or_malformed_known_content_is_invalid() {
    let identity = Identity::generate();
    let bytes = codec::encode_claim(&signed_claim(&identity), REV).unwrap();
    let raw: Ipld = atproto_dasl::from_reader(&bytes[..]).unwrap();

    let mut mismatch = raw.clone();
    let Ipld::Map(fields) = &mut mismatch else {
        unreachable!()
    };
    fields.insert(
        "codec".to_string(),
        Ipld::String(codec::V1_CODEC.to_string()),
    );
    assert!(matches!(
        codec::decode(
            &atproto_dasl::to_vec(&mismatch).unwrap(),
            VerificationContext::StaticDidKey
        ),
        Err(codec::DecodeError::CodecContentMismatch { .. })
    ));

    let mut malformed = raw;
    let Ipld::Map(fields) = &mut malformed else {
        unreachable!()
    };
    let Some(Ipld::Map(content)) = fields.get_mut("content") else {
        unreachable!()
    };
    let Some(Ipld::Map(body)) = content.get_mut("body") else {
        unreachable!()
    };
    body.insert("kind".to_string(), Ipld::String("future-kind".to_string()));
    assert!(codec::decode(
        &atproto_dasl::to_vec(&malformed).unwrap(),
        VerificationContext::StaticDidKey
    )
    .is_err());
}

#[test]
fn noncanonical_dag_cbor_is_rejected_before_semantic_decode() {
    let identity = Identity::generate();
    let bytes = codec::encode_claim(&signed_claim(&identity), REV).unwrap();
    let needle = b"\x6arecordedAt\x01";
    let offset = bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("fixture contains recordedAt encoded as the preferred integer form");
    let mut noncanonical = bytes;
    let value = offset + needle.len() - 1;
    noncanonical.splice(value..=value, [0x18, 0x01]);
    let result = codec::decode(&noncanonical, VerificationContext::StaticDidKey);
    assert!(
        matches!(result, Err(codec::DecodeError::NonCanonical)),
        "{result:?}"
    );
}

#[test]
fn v1_round_trips_without_adopting_v2_signature_rules() {
    let identity = Identity::generate();
    let content = v1::ClaimContent {
        author: v1::AuthorId {
            did: identity.did(),
            agent: None,
        },
        workspace: v1::Anchor::Workspace("legacy-workspace".to_string()),
        subject: v1::SubjectRef::Local("legacy-subject".to_string()),
        body: v1::ClaimBody::Observation {
            text: "legacy claim".to_string(),
        },
        cites: vec![],
        artifacts: vec![],
        recorded_at: Some(1),
    };
    let id = kan::cid::content_cid(&content).unwrap();
    let original = v1::Claim {
        content,
        sig: identity.sign(&id.to_bytes()).unwrap(),
    };
    let bytes = codec::encode_v1(original.clone(), REV.to_string()).unwrap();
    let decoded = codec::decode(&bytes, VerificationContext::StaticDidKey).unwrap();
    assert_eq!(
        decoded,
        DecodedClaim::Supported(SupportedClaim::V1(original))
    );
}

#[test]
fn selected_static_key_cannot_substitute_for_the_declared_author() {
    let declared = Identity::generate();
    let selected = Identity::generate();
    assert!(matches!(
        Claim::sign_static(content(&declared), &selected),
        Err(kan::claim::Error::SignerMismatch(_))
    ));
}

#[test]
fn ordinary_subject_paths_cannot_claim_the_uri_selector_sigil() {
    for path in ["@cid:bafy", "parent/@reserved", "email@example.com"] {
        assert!(SubjectPath::new(path.to_string()).is_err(), "{path}");
    }
    assert!(SubjectPath::new("design/rfc-3".to_string()).is_ok());
}

#[test]
fn every_current_body_arm_has_one_fixed_kind_discriminator() {
    let claim_id = ClaimId::new(
        "bafyreiec2aamsiue2cy5uqgdbxln4fvwywhk3735cwmsrav3jsfgi4ziou"
            .parse()
            .unwrap(),
    );
    let subject = SubjectPath::new("design/rfc-3".to_string()).unwrap();
    let principal =
        Did::new("did:key:zDnaenWDM6qp5Ra829d9wPUzBKBA3V6fm2cg4KVP3WFKqsYTv".to_string()).unwrap();
    let narrative = || NarrativeText::new("text".to_string()).unwrap();
    let bodies = vec![
        (
            "subject",
            ClaimBody::Subject {
                title: Title::new("RFC 3".to_string()).unwrap(),
                subject_kind: SubjectKind::Issue,
            },
        ),
        ("observation", ClaimBody::Observation { text: narrative() }),
        ("plan", ClaimBody::Plan { text: narrative() }),
        ("decision", ClaimBody::Decision { text: narrative() }),
        ("blocker", ClaimBody::Blocker { text: narrative() }),
        ("resolution", ClaimBody::Resolution { text: narrative() }),
        ("result", ClaimBody::Result { text: narrative() }),
        (
            "status",
            ClaimBody::Status {
                value: StatusValue::InProgress,
            },
        ),
        (
            "relation",
            ClaimBody::Relation {
                relation: RelationKind::About,
                target: ScopedSubjectRef {
                    scope: scope(),
                    subject: subject.clone(),
                },
            },
        ),
        (
            "retraction",
            ClaimBody::Retraction {
                claim: claim_id.clone(),
            },
        ),
        (
            "rejection",
            ClaimBody::Rejection {
                claim: claim_id.clone(),
            },
        ),
        (
            "publication-intent",
            ClaimBody::PublicationIntent {
                target: PublicationTarget::new(
                    "kan://local/kan-tools:kan/subject/design/rfc-3".to_string(),
                    scope(),
                    subject,
                )
                .unwrap(),
            },
        ),
        (
            "lineage",
            ClaimBody::Lineage {
                child: principal.clone(),
                relationship: LineageRelationship::Invoked,
            },
        ),
        (
            "role-naming",
            ClaimBody::RoleNaming {
                principal,
                name: RoleName::new("reviewer".to_string()).unwrap(),
            },
        ),
    ];

    for (expected, body) in bodies {
        let bytes = atproto_dasl::to_vec(&body).unwrap();
        let Ipld::Map(fields) = atproto_dasl::from_reader(&bytes[..]).unwrap() else {
            panic!("{expected} body is not a map");
        };
        assert_eq!(
            fields.get("kind"),
            Some(&Ipld::String(expected.to_string()))
        );
        let decoded: ClaimBody = atproto_dasl::from_reader(&bytes[..])
            .unwrap_or_else(|error| panic!("{expected}: {error}"));
        assert_eq!(decoded, body);
    }
}

#[test]
fn every_structured_reference_arm_round_trips_with_typed_binary_ids() {
    let cid: atproto_dasl::Cid = "bafyreiec2aamsiue2cy5uqgdbxln4fvwywhk3735cwmsrav3jsfgi4ziou"
        .parse()
        .unwrap();
    let controls = vec![
        ControlRef::IdentityEvent {
            event: IdentityEventId::new(cid.clone()),
        },
        ControlRef::GovernanceEvent {
            event: GovernanceEventId::new(cid.clone()),
        },
        ControlRef::Delegation {
            delegation: DelegationId::new(cid.clone()),
        },
        ControlRef::Revocation {
            revocation: RevocationId::new(cid.clone()),
        },
    ];
    for value in controls {
        let bytes = atproto_dasl::to_vec(&value).unwrap();
        assert_eq!(
            atproto_dasl::from_reader::<_, ControlRef>(&bytes[..]).unwrap(),
            value
        );
    }

    let artifacts = vec![
        ArtifactRef::GitCommit {
            commit: GitObjectId::Sha1 {
                digest: Sha1Digest::new([1; 20]),
            },
        },
        ArtifactRef::Blob { cid: cid.clone() },
        ArtifactRef::FileAt {
            path: GitPath::new(b"src/lib.rs".to_vec()).unwrap(),
            commit: GitObjectId::Sha256 {
                digest: Sha256Digest::new([2; 32]),
            },
        },
        ArtifactRef::LineRangeAt {
            path: GitPath::new(b"src/lib.rs".to_vec()).unwrap(),
            commit: GitObjectId::Sha1 {
                digest: Sha1Digest::new([3; 20]),
            },
            lines: LineRange::new(NonZeroU32::new(2).unwrap(), NonZeroU32::new(4).unwrap())
                .unwrap(),
        },
        ArtifactRef::ToolOutput { cid: cid.clone() },
    ];
    for value in artifacts.clone() {
        let bytes = atproto_dasl::to_vec(&value).unwrap();
        assert_eq!(
            atproto_dasl::from_reader::<_, ArtifactRef>(&bytes[..]).unwrap(),
            value
        );
    }

    let principal =
        Did::new("did:key:zDnaenWDM6qp5Ra829d9wPUzBKBA3V6fm2cg4KVP3WFKqsYTv".to_string()).unwrap();
    let resources = vec![
        ResourceRef::Scope { scope: scope() },
        ResourceRef::Subject {
            subject: ScopedSubjectRef {
                scope: scope(),
                subject: SubjectPath::new("design/rfc-3".to_string()).unwrap(),
            },
        },
        ResourceRef::Claim {
            claim: ClaimId::new(cid),
        },
        ResourceRef::Principal { principal },
        ResourceRef::Control {
            control: ControlRef::Delegation {
                delegation: DelegationId::new(
                    "bafyreiec2aamsiue2cy5uqgdbxln4fvwywhk3735cwmsrav3jsfgi4ziou"
                        .parse()
                        .unwrap(),
                ),
            },
        },
        ResourceRef::Artifact {
            artifact: artifacts[0].clone(),
        },
    ];
    for value in resources {
        let bytes = atproto_dasl::to_vec(&value).unwrap();
        assert_eq!(
            atproto_dasl::from_reader::<_, ResourceRef>(&bytes[..]).unwrap(),
            value
        );
    }
}

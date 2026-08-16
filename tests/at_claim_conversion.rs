use atproto_dasl::Cid;
use kan::{
    at_claim::{Error, Record, RelationKindValue, StatusValueWire, SubjectKindValue},
    cid::content_cid,
    claim::*,
    sign::Identity,
};

fn cid(s: &str) -> Cid {
    content_cid(&s).unwrap()
}
fn content(did: String, body: ClaimBody, recorded_at: Option<u64>) -> ClaimContent {
    ClaimContent {
        author: AuthorId {
            did,
            agent: Some(vec![1, 2, 3]),
        },
        workspace: Anchor::LineRangeAt(
            "src/lib.rs".into(),
            "abc".into(),
            Span { start: 1, end: 2 },
        ),
        subject: SubjectRef::Anchor(Anchor::Blob(cid("subject"))),
        body,
        cites: vec![cid("cite")],
        artifacts: vec![
            ArtifactRef::Commit("a".into()),
            ArtifactRef::FileAt("a".into(), "b".into()),
            ArtifactRef::LineRangeAt("a".into(), "b".into(), Span { start: 3, end: 4 }),
            ArtifactRef::ToolOutput(cid("tool")),
        ],
        recorded_at,
    }
}
fn bodies() -> Vec<ClaimBody> {
    vec![
        ClaimBody::Subject {
            title: "t".into(),
            subject_kind: SubjectKind::Issue,
        },
        ClaimBody::Observation { text: "o".into() },
        ClaimBody::Plan { text: "p".into() },
        ClaimBody::Decision { text: "d".into() },
        ClaimBody::Blocker { text: "b".into() },
        ClaimBody::Resolution { text: "r".into() },
        ClaimBody::Result { text: "r".into() },
        ClaimBody::Status {
            value: StatusValue::InProgress,
        },
        ClaimBody::Relation {
            kind: RelationKind::SameAs,
            target: SubjectRef::Local("x".into()),
        },
        ClaimBody::Retraction {
            supersedes: cid("r"),
        },
        ClaimBody::Rejects { claim: cid("j") },
        ClaimBody::Publication {
            layer: Layer::GitTree,
        },
        ClaimBody::RoleDeclaration {
            did: "did:key:z6Mkf".into(),
            name: "n".into(),
        },
    ]
}

#[test]
fn every_known_body_round_trips_with_absent_and_present_recorded_at() {
    let id = Identity::generate();
    for body in bodies() {
        for timestamp in [None, Some(42)] {
            let original = content(id.did(), body.clone(), timestamp);
            let c = content_cid(&original).unwrap();
            let sig = id.sign(&c.to_bytes()).unwrap();
            let record = Record::from_claim(
                Claim {
                    content: original.clone(),
                    sig,
                },
                "3jzfcijpj2z2a".into(),
            )
            .unwrap();
            let restored = record.verify().unwrap();
            assert_eq!(restored.content, original);
            assert_eq!(content_cid(&restored.content).unwrap(), c);
        }
    }
}

#[test]
fn every_anchor_subject_and_artifact_variant_round_trips() {
    let id = Identity::generate();
    let anchors = [
        Anchor::Workspace("w".into()),
        Anchor::Commit("s".into()),
        Anchor::Blob(cid("b")),
        Anchor::FileAt("p".into(), "s".into()),
        Anchor::LineRangeAt("p".into(), "s".into(), Span { start: 0, end: 1 }),
    ];
    for anchor in anchors {
        for subject in [
            SubjectRef::Local("x".into()),
            SubjectRef::Anchor(anchor.clone()),
        ] {
            let mut c = content(id.did(), ClaimBody::Observation { text: "x".into() }, None);
            c.workspace = anchor.clone();
            c.subject = subject;
            let cc = content_cid(&c).unwrap();
            let sig = id.sign(&cc.to_bytes()).unwrap();
            assert_eq!(
                Record::from_claim(
                    Claim {
                        content: c.clone(),
                        sig
                    },
                    "tid".into()
                )
                .unwrap()
                .verify()
                .unwrap()
                .content,
                c
            );
        }
    }
}

#[test]
fn hostile_records_fail_closed() {
    let id = Identity::generate();
    let c = content(id.did(), ClaimBody::Observation { text: "x".into() }, None);
    let cc = content_cid(&c).unwrap();
    let sig = id.sign(&cc.to_bytes()).unwrap();
    let mut record = Record::from_claim(Claim { content: c, sig }, "tid".into()).unwrap();
    record.codec = "other".into();
    assert!(matches!(
        record.verify(),
        Err(Error::UnsupportedClaimCodec(_))
    ));
    let unknown = content(
        id.did(),
        ClaimBody::Unknown {
            kind: "Future".into(),
            raw: vec![0xa0],
        },
        None,
    );
    assert!(matches!(
        Record::from_claim(
            Claim {
                content: unknown,
                sig: vec![]
            },
            "tid".into()
        ),
        Err(Error::UnsupportedClaimCodec(_))
    ));
}

#[test]
fn tampering_cid_content_or_signature_is_rejected() {
    let id = Identity::generate();
    let c = content(id.did(), ClaimBody::Observation { text: "x".into() }, None);
    let cc = content_cid(&c).unwrap();
    let sig = id.sign(&cc.to_bytes()).unwrap();
    let base = Record::from_claim(Claim { content: c, sig }, "tid".into()).unwrap();
    let mut r = base.clone();
    r.claim_cid = cid("wrong").to_string();
    assert_eq!(r.verify(), Err(Error::CidMismatch));
    let mut r = base.clone();
    r.content.recorded_at = Some(9);
    assert_eq!(r.verify(), Err(Error::CidMismatch));
    let mut r = base;
    r.signature[0] ^= 1;
    assert_eq!(r.verify(), Err(Error::BadSignature));
}

#[test]
fn wire_projection_uses_lexicon_discriminator_and_omits_absent_timestamp() {
    let id = Identity::generate();
    let c = content(id.did(), ClaimBody::Observation { text: "x".into() }, None);
    let cc = content_cid(&c).unwrap();
    let value = serde_json::to_value(
        Record::from_claim(
            Claim {
                content: c,
                sig: id.sign(&cc.to_bytes()).unwrap(),
            },
            "tid".into(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        value["content"]["body"]["$type"],
        "tools.kan.defs#observationBody"
    );
    assert!(value["content"].get("recordedAt").is_none());
    assert_eq!(
        value["content"]["workspace"]["$type"],
        "tools.kan.defs#lineRangeAtAnchor"
    );
    assert_eq!(
        value["content"]["subject"]["$type"],
        "tools.kan.defs#anchorSubject"
    );
    assert_eq!(
        value["content"]["subject"]["anchor"]["$type"],
        "tools.kan.defs#blobAnchor"
    );
    assert!(value["content"]["subject"]["anchor"]["cid"]["$link"]
        .as_str()
        .unwrap()
        .starts_with('b'));
    assert!(value["content"]["cites"][0]["$link"]
        .as_str()
        .unwrap()
        .starts_with('b'));
    assert_eq!(
        value["content"]["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["$type"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "tools.kan.defs#commitArtifact",
            "tools.kan.defs#fileAtArtifact",
            "tools.kan.defs#lineRangeAtArtifact",
            "tools.kan.defs#toolOutputArtifact"
        ]
    );
}

#[test]
fn wire_projection_covers_every_closed_union_discriminator_and_enum_spelling() {
    let id = Identity::generate();
    let body_types = [
        "subjectBody",
        "observationBody",
        "planBody",
        "decisionBody",
        "blockerBody",
        "resolutionBody",
        "resultBody",
        "statusBody",
        "relationBody",
        "retractionBody",
        "rejectsBody",
        "publicationBody",
        "roleDeclarationBody",
    ];
    for (body, suffix) in bodies().into_iter().zip(body_types) {
        let c = content(id.did(), body, None);
        let cc = content_cid(&c).unwrap();
        let v = serde_json::to_value(
            Record::from_claim(
                Claim {
                    content: c,
                    sig: id.sign(&cc.to_bytes()).unwrap(),
                },
                "tid".into(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            v["content"]["body"]["$type"],
            format!("tools.kan.defs#{suffix}")
        );
    }

    let anchors = [
        Anchor::Workspace("w".into()),
        Anchor::Commit("s".into()),
        Anchor::Blob(cid("b")),
        Anchor::FileAt("p".into(), "s".into()),
        Anchor::LineRangeAt("p".into(), "s".into(), Span { start: 0, end: 1 }),
    ];
    let anchor_types = [
        "workspaceAnchor",
        "commitAnchor",
        "blobAnchor",
        "fileAtAnchor",
        "lineRangeAtAnchor",
    ];
    for (anchor, suffix) in anchors.into_iter().zip(anchor_types) {
        let mut c = content(id.did(), ClaimBody::Observation { text: "x".into() }, None);
        c.workspace = anchor;
        let cc = content_cid(&c).unwrap();
        let v = serde_json::to_value(
            Record::from_claim(
                Claim {
                    content: c,
                    sig: id.sign(&cc.to_bytes()).unwrap(),
                },
                "tid".into(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            v["content"]["workspace"]["$type"],
            format!("tools.kan.defs#{suffix}")
        );
    }

    let c = content(
        id.did(),
        ClaimBody::Subject {
            title: "x".into(),
            subject_kind: SubjectKind::Question,
        },
        None,
    );
    let cc = content_cid(&c).unwrap();
    let v = serde_json::to_value(
        Record::from_claim(
            Claim {
                content: c,
                sig: id.sign(&cc.to_bytes()).unwrap(),
            },
            "tid".into(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(v["content"]["body"]["subjectKind"], "question");

    let c = content(
        id.did(),
        ClaimBody::Status {
            value: StatusValue::InProgress,
        },
        None,
    );
    let cc = content_cid(&c).unwrap();
    let v = serde_json::to_value(
        Record::from_claim(
            Claim {
                content: c,
                sig: id.sign(&cc.to_bytes()).unwrap(),
            },
            "tid".into(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(v["content"]["body"]["value"], "in-progress");

    let c = content(
        id.did(),
        ClaimBody::Relation {
            kind: RelationKind::InTensionWith,
            target: SubjectRef::Local("x".into()),
        },
        None,
    );
    let cc = content_cid(&c).unwrap();
    let v = serde_json::to_value(
        Record::from_claim(
            Claim {
                content: c,
                sig: id.sign(&cc.to_bytes()).unwrap(),
            },
            "tid".into(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(v["content"]["body"]["kind"], "in-tension-with");
    assert_eq!(
        v["content"]["body"]["target"]["$type"],
        "tools.kan.defs#localSubject"
    );

    for (value, spelling) in [
        (SubjectKindValue::Issue, "issue"),
        (SubjectKindValue::Idea, "idea"),
        (SubjectKindValue::Question, "question"),
    ] {
        assert_eq!(serde_json::to_value(value).unwrap(), spelling);
    }
    for (value, spelling) in [
        (StatusValueWire::Open, "open"),
        (StatusValueWire::InProgress, "in-progress"),
        (StatusValueWire::Blocked, "blocked"),
        (StatusValueWire::Resolved, "resolved"),
        (StatusValueWire::Closed, "closed"),
    ] {
        assert_eq!(serde_json::to_value(value).unwrap(), spelling);
    }
    for (value, spelling) in [
        (RelationKindValue::SameAs, "same-as"),
        (RelationKindValue::Blocks, "blocks"),
        (RelationKindValue::About, "about"),
        (RelationKindValue::ManifestsAt, "manifests-at"),
        (RelationKindValue::DependsOn, "depends-on"),
        (RelationKindValue::Accepts, "accepts"),
        (RelationKindValue::InTensionWith, "in-tension-with"),
        (RelationKindValue::Supersedes, "supersedes"),
        (RelationKindValue::Refutes, "refutes"),
    ] {
        assert_eq!(serde_json::to_value(value).unwrap(), spelling);
    }
}

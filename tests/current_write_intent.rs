use kan::{
    claim::{
        compat::{self, UnsupportedIntent},
        v1, ArtifactRef, ClaimBody, RelationKind, StatusValue,
    },
    identity::{authorship::Author, control::IdentityVersion, scope_inception::ScopeId},
    sign::Identity,
};

fn scope() -> ScopeId {
    ScopeId::from_bytes({
        let mut bytes = [0x81; 34];
        bytes[..2].copy_from_slice(&[0x12, 0x20]);
        bytes
    })
    .unwrap()
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

#[test]
fn structural_and_git_intent_compiles_into_current_types() {
    let identity = Identity::generate();
    let cited = kan::cid::content_cid(&"cited").unwrap();
    let commit = "0123456789abcdef0123456789abcdef01234567".to_string();
    let content = compat::compile_write_intent(
        author(&identity),
        scope(),
        v1::SubjectRef::Local("work/compiler".to_string()),
        v1::ClaimBody::Relation {
            kind: v1::RelationKind::DependsOn,
            target: v1::SubjectRef::Local("work/prerequisite".to_string()),
        },
        vec![cited.clone()],
        vec![
            v1::ArtifactRef::Commit(commit.clone()),
            v1::ArtifactRef::LineRangeAt(
                "src/lib.rs".into(),
                commit,
                v1::Span { start: 3, end: 7 },
            ),
        ],
        42,
    )
    .unwrap();

    assert_eq!(content.subject().as_str(), "work/compiler");
    assert!(matches!(
        content.body(),
        ClaimBody::Relation {
            relation: RelationKind::DependsOn,
            target,
        } if target.scope == scope() && target.subject.as_str() == "work/prerequisite"
    ));
    assert_eq!(content.cites().as_slice()[0].cid(), &cited);
    assert!(matches!(
        content.artifacts().as_slice(),
        [
            ArtifactRef::GitCommit { .. },
            ArtifactRef::LineRangeAt { .. }
        ]
    ));
}

#[test]
fn status_values_compile_without_a_stringly_intermediate() {
    let identity = Identity::generate();
    let content = compat::compile_write_intent(
        author(&identity),
        scope(),
        v1::SubjectRef::Local("work/status".to_string()),
        v1::ClaimBody::Status {
            value: v1::StatusValue::Resolved,
        },
        vec![],
        vec![],
        42,
    )
    .unwrap();
    assert!(matches!(
        content.body(),
        ClaimBody::Status {
            value: StatusValue::Resolved
        }
    ));
}

#[test]
fn uri_dependent_and_anchor_intents_are_explicitly_unsupported() {
    let identity = Identity::generate();
    assert!(matches!(
        compat::compile_write_intent(
            author(&identity),
            scope(),
            v1::SubjectRef::Local("work/publish".to_string()),
            v1::ClaimBody::Publication {
                layer: v1::Layer::GitTree,
            },
            vec![],
            vec![],
            42,
        ),
        Err(compat::Error::Unsupported(
            UnsupportedIntent::PublicationNeedsUri
        ))
    ));
    assert!(matches!(
        compat::compile_write_intent(
            author(&identity),
            scope(),
            v1::SubjectRef::Anchor(v1::Anchor::Workspace("legacy".to_string())),
            v1::ClaimBody::Observation {
                text: "not path-addressed".to_string(),
            },
            vec![],
            vec![],
            42,
        ),
        Err(compat::Error::Unsupported(
            UnsupportedIntent::AnchorSubject { .. }
        ))
    ));
}

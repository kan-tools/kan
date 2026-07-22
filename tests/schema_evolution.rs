//! `.design/schema-evolution.md` — the compatibility contract from
//! `docs/SPEC.md` §7.1 and ADR-44, pinned so it cannot regress silently.
//!
//! These are not incidental tests. Each one holds down a property the
//! contract *asserts*, and the contract is only worth writing down if the
//! assertions are enforced.

use kan::{
    cid::content_cid,
    claim::{Anchor, AuthorId, Claim, ClaimBody, ClaimContent, ClaimKind, SubjectRef},
    sign::Identity,
};
use serde::Serialize;

fn content(body: ClaimBody, identity: &Identity) -> ClaimContent {
    ClaimContent {
        author: AuthorId {
            did: identity.did(),
            agent: None,
        },
        workspace: Anchor::Workspace("genesis".to_string()),
        subject: SubjectRef::Local("bug-42".to_string()),
        body,
        cites: vec![],
        artifacts: vec![],
        recorded_at: None,
    }
}

/// AC-2. The rule that makes evolution possible at all: a field added as
/// `Option<T>` with `skip_serializing_if` leaves existing CIDs
/// byte-identical, so every claim written before the field existed keeps its
/// exact identity.
#[test]
fn ac2_an_additive_optional_field_does_not_change_existing_cids() {
    #[derive(Serialize)]
    struct Before {
        a: u32,
        b: String,
    }

    #[derive(Serialize)]
    struct After {
        a: u32,
        b: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        c: Option<u32>,
    }

    let before = content_cid(&Before {
        a: 1,
        b: "x".into(),
    })
    .unwrap();
    let after_absent = content_cid(&After {
        a: 1,
        b: "x".into(),
        c: None,
    })
    .unwrap();
    assert_eq!(
        before, after_absent,
        "an absent additive field must not perturb the CID -- this is what \
         makes schema evolution possible without invalidating history"
    );

    let after_present = content_cid(&After {
        a: 1,
        b: "x".into(),
        c: Some(5),
    })
    .unwrap();
    assert_ne!(
        before, after_present,
        "a claim that actually uses the new field is a different claim"
    );
}

/// AC-3. Without `deny_unknown_fields`, an older reader meeting a newer
/// record deserializes it, silently drops the field it does not know,
/// recomputes a different CID, and reports the claim as altered since it was
/// signed — accusing a legitimate claim of tampering. The contract requires
/// the honest failure instead.
#[test]
fn ac3_an_unexpected_field_fails_by_name_not_as_a_cid_mismatch() {
    #[derive(Serialize)]
    struct NewerContent {
        author: AuthorId,
        workspace: Anchor,
        subject: SubjectRef,
        body: ClaimBody,
        cites: Vec<atproto_dasl::Cid>,
        artifacts: Vec<kan::claim::ArtifactRef>,
        /// A field this build has never heard of.
        occasion: String,
    }

    let id = Identity::generate();
    let known = content(
        ClaimBody::Observation {
            text: "hello".to_string(),
        },
        &id,
    );
    let newer = NewerContent {
        author: known.author.clone(),
        workspace: known.workspace.clone(),
        subject: known.subject.clone(),
        body: known.body.clone(),
        cites: known.cites.clone(),
        artifacts: known.artifacts.clone(),
        occasion: "from a future kan".to_string(),
    };

    let bytes = atproto_dasl::to_vec(&newer).unwrap();
    let decoded: Result<ClaimContent, _> = atproto_dasl::from_reader(&bytes[..]);

    let err = decoded.expect_err("an unexpected field must not decode silently");
    let message = err.to_string();
    assert!(
        message.contains("occasion") || message.to_lowercase().contains("unknown field"),
        "the error should name the unknown field rather than being a generic \
         failure, got: {message}"
    );
}

/// AC-6 and AC-7. An unrecognized claim kind is preserved, stays
/// CID-verifiable, and re-encodes to exactly the bytes it came from. A
/// preserved claim that could not re-encode would be unverifiable, which is
/// worse than an honest hard failure.
#[test]
fn ac6_and_ac7_an_unknown_kind_is_preserved_verifiable_and_re_encodes_exactly() {
    /// A body shape from a hypothetical future kan.
    #[derive(Serialize)]
    enum FutureBody {
        Prophecy { omen: String, confidence: u32 },
    }

    #[derive(Serialize)]
    struct FutureContent {
        author: AuthorId,
        workspace: Anchor,
        subject: SubjectRef,
        body: FutureBody,
        cites: Vec<atproto_dasl::Cid>,
        artifacts: Vec<kan::claim::ArtifactRef>,
    }

    let id = Identity::generate();
    let known = content(
        ClaimBody::Observation {
            text: "placeholder".to_string(),
        },
        &id,
    );
    let future = FutureContent {
        author: known.author.clone(),
        workspace: known.workspace.clone(),
        subject: known.subject.clone(),
        body: FutureBody::Prophecy {
            omen: "the parser will drop trailing commas".to_string(),
            confidence: 7,
        },
        cites: vec![],
        artifacts: vec![],
    };

    let stated = content_cid(&future).unwrap();
    let bytes = atproto_dasl::to_vec(&future).unwrap();

    // This build decodes it rather than rejecting it.
    let decoded: ClaimContent = atproto_dasl::from_reader(&bytes[..])
        .expect("an unknown kind must be preserved, not rejected");
    match &decoded.body {
        ClaimBody::Unknown { kind, raw } => {
            assert_eq!(kind, "Prophecy");
            assert!(!raw.is_empty());
        }
        other => panic!("expected Unknown, got {other:?}"),
    }
    assert_eq!(decoded.body.kind(), ClaimKind::Unknown);

    // AC-7: exact re-encoding, which is what keeps it verifiable.
    let reencoded = atproto_dasl::to_vec(&decoded).unwrap();
    assert_eq!(
        reencoded, bytes,
        "an Unknown claim must re-encode to the bytes it was decoded from"
    );

    // AC-6: and therefore its CID still checks out.
    assert_eq!(
        content_cid(&decoded).unwrap(),
        stated,
        "a preserved claim must remain CID-verifiable"
    );

    // And its signature still verifies, so it is attributable despite being
    // uninterpretable.
    let sig = id.sign(&stated.to_bytes()).unwrap();
    assert!(kan::sign::verify(
        &decoded.author.did,
        &stated.to_bytes(),
        &sig
    ));
    let _ = Claim {
        content: decoded,
        sig,
    };
}

/// AC-4. The `deny_unknown_fields` annotation must be backward-compatible:
/// every claim shape kan has ever written still decodes and verifies.
#[test]
fn ac4_every_known_body_still_round_trips_unchanged() {
    let id = Identity::generate();
    for body in known_bodies() {
        let content = content(body.clone(), &id);
        let cid = content_cid(&content).unwrap();
        let bytes = atproto_dasl::to_vec(&content).unwrap();
        let decoded: ClaimContent = atproto_dasl::from_reader(&bytes[..])
            .unwrap_or_else(|e| panic!("{body:?} should decode: {e}"));
        assert_eq!(decoded, content, "{body:?}");
        assert_eq!(content_cid(&decoded).unwrap(), cid, "{body:?}");
    }
}

/// Guards the `KnownBody` mirror in `src/claim.rs` against drifting from
/// `ClaimBody`. If a variant is added to one and not the other, its round
/// trip fails here rather than silently becoming an `Unknown` in
/// production.
#[test]
fn body_kinds_all_round_trip() {
    let id = Identity::generate();
    let mut seen = Vec::new();
    for body in known_bodies() {
        let content = content(body.clone(), &id);
        let bytes = atproto_dasl::to_vec(&content).unwrap();
        let decoded: ClaimContent = atproto_dasl::from_reader(&bytes[..]).unwrap();
        assert_ne!(
            decoded.body.kind(),
            ClaimKind::Unknown,
            "{body:?} decoded as Unknown -- the KnownBody mirror is missing it"
        );
        seen.push(decoded.body.kind());
    }
    assert_eq!(
        seen.len(),
        12,
        "every known ClaimKind should be covered by this test"
    );
}

fn known_bodies() -> Vec<ClaimBody> {
    let cid = content_cid(&"anything").unwrap();
    vec![
        ClaimBody::Subject {
            title: "t".into(),
            subject_kind: kan::claim::SubjectKind::Issue,
        },
        ClaimBody::Observation { text: "o".into() },
        ClaimBody::Plan { text: "p".into() },
        ClaimBody::Decision { text: "d".into() },
        ClaimBody::Blocker { text: "b".into() },
        ClaimBody::Resolution { text: "r".into() },
        ClaimBody::Result { text: "res".into() },
        ClaimBody::Status {
            value: kan::claim::StatusValue::Resolved,
        },
        ClaimBody::Relation {
            kind: kan::claim::RelationKind::About,
            target: SubjectRef::Local("other".into()),
        },
        ClaimBody::Retraction {
            supersedes: cid.clone(),
        },
        ClaimBody::Rejects { claim: cid },
        ClaimBody::Publication {
            layer: kan::claim::Layer::GitTree,
        },
    ]
}

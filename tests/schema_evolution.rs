//! `.design/schema-evolution.md` — the compatibility contract from
//! `docs/SPEC.md` §7.1 and ADR-44, pinned so it cannot regress silently.
//!
//! These are not incidental tests. Each one holds down a property the
//! contract *asserts*, and the contract is only worth writing down if the
//! assertions are enforced.

use kan::{
    cid::content_cid,
    claim::v1::{Anchor, AuthorId, Claim, ClaimBody, ClaimContent, ClaimKind, SubjectRef},
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
        artifacts: Vec<kan::claim::v1::ArtifactRef>,
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
        artifacts: Vec<kan::claim::v1::ArtifactRef>,
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
        13,
        "every known ClaimKind should be covered by this test -- note this counts \
         `known_bodies` against a literal, so it cannot notice a variant nobody added \
         there. `_every_kind_is_accounted_for` below is what makes that a build error."
    );
}

fn known_bodies() -> Vec<ClaimBody> {
    let cid = content_cid(&"anything").unwrap();
    vec![
        ClaimBody::Subject {
            title: "t".into(),
            subject_kind: kan::claim::v1::SubjectKind::Issue,
        },
        ClaimBody::Observation { text: "o".into() },
        ClaimBody::Plan { text: "p".into() },
        ClaimBody::Decision { text: "d".into() },
        ClaimBody::Blocker { text: "b".into() },
        ClaimBody::Resolution { text: "r".into() },
        ClaimBody::Result { text: "res".into() },
        ClaimBody::Status {
            value: kan::claim::v1::StatusValue::Resolved,
        },
        ClaimBody::Relation {
            kind: kan::claim::v1::RelationKind::About,
            target: SubjectRef::Local("other".into()),
        },
        ClaimBody::Retraction {
            supersedes: cid.clone(),
        },
        ClaimBody::Rejects { claim: cid },
        ClaimBody::Publication {
            layer: kan::claim::v1::Layer::GitTree,
        },
        ClaimBody::RoleDeclaration {
            did: "did:key:zDnaeSezF2t8gTQrOFpVmvSMPFsxqRDzZL6JGjTxjJ2TvNqYe".into(),
            name: "prover".into(),
        },
    ]
}

/// `.design/role-declarations.md` AC-1, downgrade half — the **precondition**,
/// stated as exactly that.
///
/// A kan older than v0.12 must preserve a `RoleDeclaration` as
/// `ClaimBody::Unknown` rather than dropping or rejecting it. That cannot be
/// tested here, because this build knows the kind and will always decode it as
/// known; running a real older binary against a real v0.12 log is the
/// migration matrix's job, and AC-12 is marked **intent** in the design for
/// that reason.
///
/// What *is* checkable is the structural precondition the preservation path
/// depends on: `src/claim.rs`'s `Deserialize` impl captures an unrecognized
/// body only when it is a **single-key map** keyed by the variant name, and
/// re-encodes it from those bytes. If `RoleDeclaration` encoded any other
/// shape — say by carrying two top-level keys — an older reader would fail the
/// single-key check and reject the claim outright rather than preserving it,
/// and nothing else in the suite would notice.
///
/// So this asserts the shape, and deliberately does not claim to have tested
/// the downgrade.
#[test]
fn a_role_declaration_has_the_shape_an_older_reader_can_preserve() {
    let id = Identity::generate();
    let body = ClaimBody::RoleDeclaration {
        did: "did:key:zDnaeSezF2t8gTQrOFpVmvSMPFsxqRDzZL6JGjTxjJ2TvNqYe".into(),
        name: "prover".into(),
    };
    let bytes = atproto_dasl::to_vec(&content(body, &id)).unwrap();

    let decoded: atproto_dasl::Ipld = atproto_dasl::from_reader(&bytes[..]).unwrap();
    let atproto_dasl::Ipld::Map(fields) = &decoded else {
        panic!("a claim's content must encode as a map: {decoded:?}");
    };
    let Some(atproto_dasl::Ipld::Map(body_entries)) = fields.get("body") else {
        panic!("a claim's body must encode as a map: {decoded:?}");
    };

    assert_eq!(
        body_entries.len(),
        1,
        "a body must be a single-key map or an older reader rejects it instead of \
         preserving it: {body_entries:?}"
    );
    assert!(
        body_entries.contains_key("RoleDeclaration"),
        "the single key must be the variant name, which is what an older reader records \
         as the unreadable kind: {body_entries:?}"
    );
}

/// A compile fence, not a test: `known_bodies` above is a hand-maintained
/// list, and `body_kinds_all_round_trip` asserts its length against a literal.
/// Both only move when someone edits them, so a new `ClaimKind` was invisible
/// to a test whose own comment claims "every known ClaimKind should be covered
/// by this test" — it counted the list against a number describing the list.
///
/// This match is **exhaustive over `ClaimKind`**, so adding a variant stops
/// compiling here until someone states whether it has a known body. That makes
/// the compiler do the enumeration, the same way `src/context.rs`'s two matches
/// already force a new variant to be given a rendering and a budget rank.
/// Added when `RoleDeclaration` was, because it was the variant that revealed
/// the gap.
fn _every_kind_is_accounted_for(kind: ClaimKind) -> bool {
    match kind {
        ClaimKind::Subject
        | ClaimKind::Observation
        | ClaimKind::Plan
        | ClaimKind::Decision
        | ClaimKind::Blocker
        | ClaimKind::Resolution
        | ClaimKind::Result
        | ClaimKind::Status
        | ClaimKind::Relation
        | ClaimKind::Retraction
        | ClaimKind::Rejects
        | ClaimKind::Publication
        | ClaimKind::RoleDeclaration => true,
        // Has no known body by definition, so it is deliberately absent from
        // `known_bodies` rather than missing from it.
        ClaimKind::Unknown => false,
    }
}

/// #95 / `docs/SPEC.md` §7.1 (as amended in ADR-49): the mandated test that
/// a *known* kind carrying a field from a newer kan survives **through the
/// GitTree transport** with a matching CID — not only at the type level.
///
/// ADR-49 recorded that the behaviour worked but this exact test did not
/// exist: `tests/recorded_at.rs` covers the `KnownBody` case at the type
/// level, and `tests/schema_evolution.rs` covered an unknown *kind* at the
/// `ClaimContent` level, but nothing exercised a known kind + unknown field
/// across `to_record`/`from_record`. A spec that mandates a test, in the
/// release that added the mandate, and then does not have it, is the same
/// class of gap the release exists to close.
#[test]
fn a_known_kind_with_an_unknown_field_round_trips_through_gittree() {
    use kan::transport::git_tree;

    // An `Observation` as a newer kan writes it: the field this build knows,
    // plus one it does not. Externally tagged, matching `ClaimBody`'s own
    // encoding, so this is exactly what arrives on the wire.
    #[derive(serde::Serialize)]
    enum FutureBody {
        Observation { text: String, confidence: u8 },
    }
    #[derive(serde::Serialize)]
    struct FutureContent {
        author: AuthorId,
        workspace: Anchor,
        subject: SubjectRef,
        body: FutureBody,
        cites: Vec<atproto_dasl::Cid>,
        artifacts: Vec<kan::claim::v1::ArtifactRef>,
        #[serde(skip_serializing_if = "Option::is_none")]
        recorded_at: Option<u64>,
    }

    let id = Identity::generate();
    let future = FutureContent {
        author: AuthorId {
            did: id.did(),
            agent: None,
        },
        workspace: Anchor::Workspace("genesis".to_string()),
        subject: SubjectRef::Local(kan::claim::v1::Rkey::from("bug-42")),
        body: FutureBody::Observation {
            text: "written by a newer kan".to_string(),
            confidence: 9,
        },
        cites: vec![],
        artifacts: vec![],
        recorded_at: Some(1_700_000_000_000_000),
    };

    // The CID a newer kan computed and signed over.
    let stated = content_cid(&future).unwrap();
    let sig = id.sign(&stated.to_bytes()).unwrap();

    // This build decodes the future content: the known kind with an unknown
    // field falls through to `Unknown`, preserving the bytes.
    let bytes = atproto_dasl::to_vec(&future).unwrap();
    let decoded_content: ClaimContent = atproto_dasl::from_reader(&bytes[..]).unwrap();
    assert!(
        matches!(decoded_content.body, ClaimBody::Unknown { .. }),
        "a known kind + unknown field must be preserved as Unknown"
    );
    let claim = kan::claim::v1::Claim {
        content: decoded_content,
        sig,
    };

    // Through the transport: serialize to a record, parse it back, and the
    // CID this build recomputes must equal the one the newer kan signed --
    // otherwise the record reads as "altered since it was signed" against an
    // honest claim, the failure §7.1 exists to prevent.
    // Unknown bodies cannot be described honestly by v3's structured `kind`
    // field, but old v2 records carrying them remain part of the read contract.
    let record = git_tree::to_record_at_version(&claim, None, None, 2).unwrap();
    let (parsed_cid, parsed) = git_tree::from_record("bug-42.md", &record)
        .expect("a known kind + unknown field must round-trip, not be rejected");
    assert_eq!(
        parsed_cid, stated,
        "the recomputed CID must match the one the newer kan signed"
    );
    assert!(matches!(parsed.content.body, ClaimBody::Unknown { .. }));

    // The writer must preserve it too. v3 has no honest wire name for a kind
    // this build does not know, so this one record falls back to v2 inside the
    // nested per-author file rather than blocking its known sibling.
    let known_content = content(
        ClaimBody::Observation {
            text: "known beside future".to_string(),
        },
        &id,
    );
    let known_cid = content_cid(&known_content).unwrap();
    let known = Claim {
        content: known_content,
        sig: id.sign(&known_cid.to_bytes()).unwrap(),
    };
    let dir = tempfile::tempdir().unwrap();
    let written = git_tree::write_subject(
        dir.path(),
        &SubjectRef::Local("bug-42".to_string()),
        &[(claim, None), (known, None)],
    )
    .expect("an opaque future claim must not make its subject unpublishable");
    let text = std::fs::read_to_string(written.path()).unwrap();
    let records = git_tree::split_records(&text);
    assert_eq!(records.len(), 2, "neither claim may be omitted");
    assert!(records.iter().any(|record| record.contains("\"v\": 2")));
    assert!(records.iter().any(|record| record.contains("\"v\": 3")));
    for record in records {
        git_tree::from_record("bug-42.md", record).expect("every mixed-version record must read");
    }
}

/// `.design/role-declarations.md` AC-1, second half — ADR-48's mandated case
/// for the **new** kind: a `RoleDeclaration` carrying a field from a newer kan
/// is preserved as `Unknown` with its bytes intact, rather than decoded,
/// silently shorn of the field, and then reported as altered since it was
/// signed.
///
/// AC-1 named this test and it did not exist; three review rounds passed
/// before a fourth said so. The sibling above proves the mechanism for
/// `Observation`, and the mechanism is kind-agnostic — but ADR-48's rule is
/// that the test must construct a *known* kind, and after this branch
/// `RoleDeclaration` is one. It is also the only kind whose body carries a
/// DID, so a build that dropped an unknown field here would be re-encoding
/// identity data.
#[test]
fn a_role_declaration_with_an_unknown_field_is_preserved_verbatim() {
    #[derive(serde::Serialize)]
    enum FutureBody {
        RoleDeclaration {
            did: String,
            name: String,
            // A field a newer kan added -- an expiry, say.
            expires_at: u64,
        },
    }
    #[derive(serde::Serialize)]
    struct FutureContent {
        author: AuthorId,
        workspace: Anchor,
        subject: SubjectRef,
        body: FutureBody,
        cites: Vec<atproto_dasl::Cid>,
        artifacts: Vec<kan::claim::v1::ArtifactRef>,
        #[serde(skip_serializing_if = "Option::is_none")]
        recorded_at: Option<u64>,
    }

    let id = Identity::generate();
    let future = FutureContent {
        author: AuthorId {
            did: id.did(),
            agent: None,
        },
        workspace: Anchor::Workspace("genesis".to_string()),
        subject: SubjectRef::Local(kan::claim::v1::Rkey::from("role/prover")),
        body: FutureBody::RoleDeclaration {
            did: "did:key:zDnaeSezF2t8gTQrOFpVmvSMPFsxqRDzZL6JGjTxjJ2TvNqYe".to_string(),
            name: "prover".to_string(),
            expires_at: 1_900_000_000,
        },
        cites: vec![],
        artifacts: vec![],
        recorded_at: Some(1_700_000_000_000_000),
    };

    let stated = content_cid(&future).unwrap();
    let bytes = atproto_dasl::to_vec(&future).unwrap();

    let content: ClaimContent = atproto_dasl::from_reader(&bytes[..])
        .expect("a known kind with an unknown field must decode, not fail");
    assert!(
        matches!(content.body, ClaimBody::Unknown { .. }),
        "a RoleDeclaration carrying an unknown field must be preserved as Unknown, not \
         decoded with the field dropped: {:?}",
        content.body
    );

    // The whole point: it re-encodes to the same bytes, so the CID the newer
    // kan signed still checks out here.
    assert_eq!(
        atproto_dasl::to_vec(&content).unwrap(),
        bytes,
        "the preserved claim did not re-encode to the bytes it was decoded from"
    );
    assert_eq!(
        content_cid(&content).unwrap(),
        stated,
        "the CID moved, which would report a legitimate claim as altered since signing"
    );
}

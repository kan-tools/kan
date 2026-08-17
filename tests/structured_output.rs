//! kan's machine-readable read surface (`--json`), and the contract it makes.
//!
//! `day` shells out to the `kan` binary (ADR-42) and parsed kan's *prose* to
//! get claims back, because prose was the only thing on offer. That made
//! every word kan prints a de-facto API with no contract, and v0.7's
//! read-surface work broke it silently: `day assess docs` reported "no docs
//! schema is declared" against a log that plainly declared one.
//!
//! These tests hold the properties that make prose-parsing unnecessary.

use kan::{
    claim::{Anchor, AuthorId, ClaimBody, ClaimContent, Rkey, StatusValue, SubjectRef},
    json,
};

fn claim(subject: &str, body: ClaimBody) -> (atproto_dasl::Cid, kan::claim::Claim) {
    let content = ClaimContent {
        author: AuthorId {
            did: "did:key:zTest".to_string(),
            agent: None,
        },
        workspace: Anchor::Workspace("g".to_string()),
        subject: SubjectRef::Local(Rkey::from(subject)),
        body,
        cites: vec![],
        artifacts: vec![],
        recorded_at: Some(1_700_000_000_000_000),
    };
    let cid = kan::cid::content_cid(&content).unwrap();
    (
        cid,
        kan::claim::Claim {
            content,
            sig: vec![],
        },
    )
}

/// Narrative text survives verbatim, including the things prose rendering
/// cannot round-trip.
///
/// This is the property `day` actually needed: it extracts fenced code blocks
/// (`day-docs`, `day-schema`, `day-atom`) out of claim text, so newlines,
/// backticks and braces have to arrive exactly as written.
#[test]
fn claim_text_survives_verbatim() {
    let text = "Docs schema.\n\n```day-docs\n{\n  \"version_source\": \"Cargo.toml\"\n}\n```";
    let (cid, c) = claim(
        "schema/docs",
        ClaimBody::Observation {
            text: text.to_string(),
        },
    );
    let out = json::ClaimJson::new(&cid, &c, false);
    let value: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&out).unwrap()).unwrap();
    assert_eq!(
        value["text"].as_str().unwrap(),
        text,
        "text must round-trip byte-exactly -- a consumer extracting a fenced \
         block from it cannot tolerate reflowing"
    );
}

/// The kind is a stable string, not a Rust `Debug` rendering, and it is not
/// the subject label. `day`'s parser read the subject where the kind used to
/// be, which is exactly the failure a named field prevents.
#[test]
fn kind_and_subject_are_separate_named_fields() {
    let (cid, c) = claim(
        "some-subject",
        ClaimBody::Observation {
            text: "x".to_string(),
        },
    );
    let out = json::ClaimJson::new(&cid, &c, false);
    assert_eq!(out.kind, "Observation");
    assert_eq!(out.subject, "some-subject");
}

/// Under a `SameAs` merge, each claim keeps the subject it was filed under.
/// The prose renderer attributed every claim in a class to the queried name.
#[test]
fn a_merged_claim_keeps_its_own_subject() {
    let (cid, c) = claim(
        "alpha",
        ClaimBody::Observation {
            text: "about alpha".to_string(),
        },
    );
    let out = json::ClaimJson::new(&cid, &c, false);
    assert_eq!(out.subject, "alpha");
}

/// Every payload carries a schema version, so a consumer can refuse a shape
/// it does not understand rather than silently misparsing it — which is what
/// `day` did, for want of a version to check.
#[test]
fn every_payload_is_versioned() {
    let out = json::StatusJson {
        v: json::SCHEMA_VERSION,
        revision: "sha256:test".to_string(),
        subjects: vec![],
        trust: json::TrustJson::new(&kan::fold::TrustBase::solo(kan::claim::AuthorId {
            did: "did:key:zTest".to_string(),
            agent: None,
        })),
        excluded_by_trust: 0,
        published_read_error_count: 0,
        published_read_errors: vec![],
    };
    let value: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&out).unwrap()).unwrap();
    assert_eq!(value["v"], json::SCHEMA_VERSION);
}

/// Absent optional fields are omitted, not emitted as null — the same
/// additive-only discipline `docs/SPEC.md` §7.1 applies to claims, so a
/// consumer pinned to an older shape keeps working.
#[test]
fn absent_fields_are_omitted_rather_than_null() {
    let (cid, c) = claim(
        "s",
        ClaimBody::Status {
            value: StatusValue::Open,
        },
    );
    let encoded = serde_json::to_string(&json::ClaimJson::new(&cid, &c, false)).unwrap();
    assert!(!encoded.contains("null"), "no null fields: {encoded}");
    assert!(!encoded.contains("\"text\""), "a Status carries no text");
    assert!(encoded.contains("\"status\":\"Open\""));
    // And the fields that *are* present stay present.
    assert!(encoded.contains("\"kind\":\"Status\""));
}

/// A superseded status is flagged, so a consumer does not have to re-derive
/// supersession from ordering it cannot see.
#[test]
fn supersession_is_explicit() {
    let (cid, c) = claim(
        "s",
        ClaimBody::Status {
            value: StatusValue::Blocked,
        },
    );
    let live = json::ClaimJson::new(&cid, &c, false);
    let dead = json::ClaimJson::new(&cid, &c, true);
    assert!(!live.superseded);
    assert!(dead.superseded);
    // Omitted when false, so the common case stays quiet.
    assert!(!serde_json::to_string(&live).unwrap().contains("superseded"));
    assert!(serde_json::to_string(&dead).unwrap().contains("superseded"));
}

/// Relations, retractions and subject titles are structured rather than
/// stringified into prose a consumer would have to re-parse.
#[test]
fn structural_bodies_expose_their_parts() {
    let (cid, c) = claim(
        "a",
        ClaimBody::Relation {
            kind: kan::claim::RelationKind::Blocks,
            target: SubjectRef::Local(Rkey::from("b")),
        },
    );
    let out = json::ClaimJson::new(&cid, &c, false);
    assert_eq!(out.relation.as_deref(), Some("Blocks"));
    assert_eq!(out.target.as_deref(), Some("b"));

    let (cid, c) = claim(
        "a",
        ClaimBody::Subject {
            title: "a real title".to_string(),
            subject_kind: kan::claim::SubjectKind::Issue,
        },
    );
    assert_eq!(
        json::ClaimJson::new(&cid, &c, false).title.as_deref(),
        Some("a real title")
    );
}

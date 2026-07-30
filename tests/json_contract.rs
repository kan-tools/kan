//! `.design/v0.8-milestone.md` REQ-5/AC-5 — the `--json` contract, pinned.
//!
//! `tests/structured_output.rs` asserts what the shapes *mean*. This file
//! asserts what they *are*: the exact field names a consumer may rely on,
//! and the version it checks to know it may.
//!
//! **The rule these tests encode is additive-only.** Every pinned name must
//! be present; new names may appear freely. So adding a field passes,
//! renaming or removing one fails — which is the whole contract, because a
//! consumer pinned to an older shape has to keep working.
//!
//! This exists because the alternative already happened. `day` parsed kan's
//! prose for want of anything else, v0.7's read-surface improvements changed
//! that prose, and `day assess docs` began reporting "no docs schema is
//! declared" against a log that plainly declared one — a silent breaking
//! change delivered by a change that improved every measure a human cares
//! about. The research loop is about to build an external linter on this
//! surface, so it needs to be a contract rather than a shape that happens to
//! hold today.

use kan::{
    claim::{
        Anchor, AuthorId, ClaimBody, ClaimContent, Layer, RelationKind, Rkey, StatusValue,
        SubjectRef,
    },
    json,
};

fn author() -> AuthorId {
    AuthorId {
        did: "did:key:zTest".to_string(),
        agent: None,
    }
}

fn claim(subject: &str, body: ClaimBody) -> (atproto_dasl::Cid, kan::claim::Claim) {
    let content = ClaimContent {
        author: author(),
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

fn claim_json_keys(body: ClaimBody) -> Vec<String> {
    let (cid, c) = claim("s", body);
    let value = serde_json::to_value(json::ClaimJson::new(&cid, &c, false)).unwrap();
    value
        .as_object()
        .expect("a ClaimJson must serialize as an object")
        .keys()
        .cloned()
        .collect()
}

/// Assert `pinned` ⊆ `actual`, naming precisely what went missing.
///
/// Subset rather than equality on purpose: equality would fail on every
/// added field, turning the additive-only rule into a frozen-shape rule and
/// making this test something people delete rather than heed.
fn assert_pinned(pinned: &[&str], actual: &[String], what: &str) {
    let missing: Vec<&&str> = pinned
        .iter()
        .filter(|p| !actual.iter().any(|a| a == **p))
        .collect();
    assert!(
        missing.is_empty(),
        "{what}: pinned field(s) {missing:?} are gone. Fields are additive-only -- a rename \
         or removal breaks every consumer pinned to this schema version. If the change is \
         genuinely necessary, it is a SCHEMA_VERSION bump, not an edit to this list.\n\
         present: {actual:?}"
    );
}

/// AC-5: `ClaimJson`'s field set, for the fields every claim carries.
#[test]
fn claim_json_core_fields_are_pinned() {
    let keys = claim_json_keys(ClaimBody::Observation {
        text: "t".to_string(),
    });
    assert_pinned(
        &["cid", "kind", "subject", "author", "recorded_at", "text"],
        &keys,
        "ClaimJson (Observation)",
    );
}

/// AC-5: the per-kind fields. Each is `skip_serializing_if`, so each has to
/// be provoked by the body kind that carries it — a single specimen claim
/// could never exercise them all, since they are mutually exclusive.
#[test]
fn claim_json_per_kind_fields_are_pinned() {
    assert_pinned(
        &["title"],
        &claim_json_keys(ClaimBody::Subject {
            title: "T".to_string(),
            subject_kind: kan::claim::SubjectKind::Issue,
        }),
        "ClaimJson (Subject)",
    );
    assert_pinned(
        &["status"],
        &claim_json_keys(ClaimBody::Status {
            value: StatusValue::Open,
        }),
        "ClaimJson (Status)",
    );
    assert_pinned(
        &["relation", "target"],
        &claim_json_keys(ClaimBody::Relation {
            kind: RelationKind::Blocks,
            target: SubjectRef::Local(Rkey::from("other")),
        }),
        "ClaimJson (Relation)",
    );
    let (target_cid, _) = claim(
        "x",
        ClaimBody::Observation {
            text: "target".to_string(),
        },
    );
    assert_pinned(
        &["supersedes"],
        &claim_json_keys(ClaimBody::Retraction {
            supersedes: target_cid,
        }),
        "ClaimJson (Retraction)",
    );
}

/// AC-5: `ShowJson`'s field set, including the two v0.8 additions a consumer
/// now depends on to know what it was handed.
#[test]
fn show_json_fields_are_pinned() {
    let value = serde_json::to_value(json::ShowJson {
        v: json::SCHEMA_VERSION,
        subject: "s".to_string(),
        subjects: vec!["s".to_string()],
        claims: vec![],
        flagged_oversized: false,
        inbound: vec![],
        trust: json::TrustJson::new(&kan::fold::TrustBase::solo(author())),
        excluded_by_trust: 0,
    })
    .unwrap();
    let keys: Vec<String> = value.as_object().unwrap().keys().cloned().collect();
    assert_pinned(
        &[
            "v",
            "subject",
            "subjects",
            "claims",
            "trust",
            "excluded_by_trust",
        ],
        &keys,
        "ShowJson",
    );

    // `excluded_by_trust` is emitted even at zero. "Nothing was excluded"
    // and "this kan is too old to say" must not look alike to a consumer,
    // which is why it is not `skip_serializing_if`.
    assert_eq!(value["excluded_by_trust"], 0);

    // The trust envelope's own shape is part of the contract: day reads
    // `base` to tell a Solo view from a PeerContested one, and `authors` to
    // check the frame it asked for is the frame it got.
    let trust_keys: Vec<String> = value["trust"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    assert_pinned(&["base", "authors"], &trust_keys, "TrustJson");
    let author_keys: Vec<String> = value["trust"]["authors"][0]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    assert_pinned(&["did", "weight"], &author_keys, "TrustAuthorJson");
}

/// AC-5: the schema version a consumer checks. Bumping it is a deliberate
/// act that breaks pinned consumers, so it is pinned here too — this test
/// failing is the prompt to ask whether the change really required a bump.
#[test]
fn the_schema_version_is_pinned() {
    assert_eq!(
        json::SCHEMA_VERSION,
        1,
        "SCHEMA_VERSION changed. It is bumped only for a change a consumer must react to; \
         additive fields do not bump it, which is the point of the additive-only rule. If \
         this is deliberate, update this test and say so in the ADR -- every consumer \
         pinned to the old version stops trusting the payload."
    );
}

/// AC-5's second half: a claim kind this build does not recognize still
/// **serializes** rather than aborting the whole payload.
///
/// `ClaimBody::Unknown` (SPEC §7.1, ADR-44) preserves an unrecognized body's
/// canonical DAG-CBOR so the claim stays CID-verifiable and
/// signature-checkable while being uninterpretable. The `--json` surface has
/// to render it as *a claim with a kind it cannot explain*, because the
/// alternative — one unknown claim failing the read — would make a newer
/// actor's claims take out an older actor's entire view of a shared tree,
/// the exact divergence unknown-kind tolerance exists to prevent.
#[test]
fn an_unknown_claim_kind_still_serializes() {
    let keys = claim_json_keys(ClaimBody::Unknown {
        kind: "dev.kan.claim.somethingNewer".to_string(),
        raw: vec![0xa0],
    });
    assert_pinned(
        &["cid", "kind", "subject", "author"],
        &keys,
        "ClaimJson (Unknown)",
    );

    let (cid, c) = claim(
        "s",
        ClaimBody::Unknown {
            kind: "dev.kan.claim.somethingNewer".to_string(),
            raw: vec![0xa0],
        },
    );
    let value = serde_json::to_value(json::ClaimJson::new(&cid, &c, false)).unwrap();
    // It reports *a* kind rather than pretending to be a known one — a
    // consumer must be able to tell it apart and skip it deliberately.
    assert_eq!(value["kind"], "Unknown");
    // And it carries no invented narrative: an unknown body has no text
    // this build can read, so claiming one would be fabrication.
    assert!(
        value.get("text").is_none(),
        "an unknown claim body reported narrative text it cannot possibly have read: {value}"
    );
}

/// The remaining payload envelopes carry the version too, so a consumer can
/// check any of them rather than only `show`.
#[test]
fn every_payload_envelope_is_pinned() {
    let trust = || json::TrustJson::new(&kan::fold::TrustBase::solo(author()));

    let status = serde_json::to_value(json::StatusJson {
        v: json::SCHEMA_VERSION,
        subjects: vec![],
        trust: trust(),
        excluded_by_trust: 0,
    })
    .unwrap();
    let keys: Vec<String> = status.as_object().unwrap().keys().cloned().collect();
    assert_pinned(
        &["v", "subjects", "trust", "excluded_by_trust"],
        &keys,
        "StatusJson",
    );

    let context = serde_json::to_value(json::ContextJson {
        v: json::SCHEMA_VERSION,
        claims: vec![],
        tokens: 0,
        budget: 100,
        omitted_claims: 0,
        omitted_subjects: vec![],
        trust: trust(),
        excluded_by_trust: 0,
    })
    .unwrap();
    let keys: Vec<String> = context.as_object().unwrap().keys().cloned().collect();
    assert_pinned(
        &[
            "v",
            "claims",
            "tokens",
            "budget",
            "omitted_claims",
            "trust",
            "excluded_by_trust",
        ],
        &keys,
        "ContextJson",
    );

    // `omitted_claims` (what the budget withheld) and `excluded_by_trust`
    // (what the trust base never offered) are separate fields on purpose:
    // raising `--budget` recovers the first and never the second, so
    // conflating them would point a consumer at the wrong lever.
    assert!(context.get("omitted_claims").is_some() && context.get("excluded_by_trust").is_some());

    let publication = serde_json::to_value(json::ClaimJson::new(
        &claim(
            "s",
            ClaimBody::Publication {
                layer: Layer::GitTree,
            },
        )
        .0,
        &claim(
            "s",
            ClaimBody::Publication {
                layer: Layer::GitTree,
            },
        )
        .1,
        false,
    ))
    .unwrap();
    assert_eq!(publication["kind"], "Publication");
}

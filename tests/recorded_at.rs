//! `.design/v0.7-milestone.md` REQ-1/REQ-2/REQ-11 — `ClaimContent::recorded_at`,
//! and the defect it exists to fix.
//!
//! Before this field, `ClaimContent` had nothing time-varying in it, so
//! recording the same observation twice produced one content CID, one MST
//! key, and one surviving claim: an append-only log silently dropping an
//! append, at exit 0. Every test here fails against the pre-v0.7 shape.

use kan::{
    claim::{Anchor, AuthorId, ClaimBody, ClaimContent, Rkey, SubjectRef},
    fold::{self, TrustBase},
    sign::Identity,
    store::log::Log,
};

fn author(identity: &Identity) -> AuthorId {
    AuthorId {
        did: identity.did(),
        agent: None,
    }
}

fn content(identity: &Identity, subject: &str, body: ClaimBody) -> ClaimContent {
    ClaimContent {
        author: author(identity),
        workspace: Anchor::Workspace("genesis".to_string()),
        subject: SubjectRef::Local(Rkey::from(subject)),
        body,
        cites: vec![],
        artifacts: vec![],
        recorded_at: None,
    }
}

fn observation(text: &str) -> ClaimBody {
    ClaimBody::Observation {
        text: text.to_string(),
    }
}

async fn fresh() -> (tempfile::TempDir, Log, Identity) {
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::load_or_create(&dir.path().join("identity")).unwrap();
    let log = Log::open_or_create(&dir.path().join("log"), &identity)
        .await
        .unwrap();
    (dir, log, identity)
}

/// AC-1. The headline defect: appending identical content twice must yield
/// two distinct claims, not one.
#[tokio::test]
async fn identical_content_appended_twice_yields_two_distinct_claims() {
    let (_dir, mut log, identity) = fresh().await;
    let make = || content(&identity, "bug-42", observation("deploy is broken"));

    let first = log.append(make(), &identity).await.unwrap();
    let second = log.append(make(), &identity).await.unwrap();

    assert_ne!(
        first, second,
        "identical content must still produce distinct CIDs -- otherwise the \
         second append overwrites the first at the same MST key"
    );

    let stored = log.iter_all().await.unwrap();
    assert_eq!(
        stored.len(),
        2,
        "both appends must be reachable from the log root, not just the last writer"
    );
    let mut times: Vec<u64> = stored
        .iter()
        .map(|(_, s)| s.claim.content.recorded_at.expect("append must stamp"))
        .collect();
    times.sort_unstable();
    assert!(
        times[0] < times[1],
        "recorded_at must strictly increase even within the same microsecond"
    );
}

/// AC-1, at the fold. Two claims in the log are worth nothing if the fold
/// still shows one.
#[tokio::test]
async fn the_fold_shows_both_of_two_identical_recordings() {
    let (_dir, mut log, identity) = fresh().await;
    let make = || content(&identity, "bug-42", observation("deploy is broken"));
    log.append(make(), &identity).await.unwrap();
    log.append(make(), &identity).await.unwrap();

    let trust = TrustBase::solo(author(&identity));
    let view = fold::fold(log.iter_all().await.unwrap(), &trust);
    let class = view
        .subject(&SubjectRef::Local(Rkey::from("bug-42")))
        .expect("subject should be present");
    assert_eq!(class.claims.len(), 2);
}

/// AC-2. The nastiest consequence of the old collision: re-recording a
/// retracted claim pushed the target past its own retraction in `rev` order,
/// so `excluded_by_retraction` stopped recognizing it and the retraction went
/// inert — leaving a live `Retraction` beside its live target, toggling
/// indefinitely as either side was re-asserted.
#[tokio::test]
async fn re_recording_a_retracted_claim_does_not_resurrect_it() {
    let (_dir, mut log, identity) = fresh().await;
    let make = || content(&identity, "bug-42", observation("deploy is broken"));

    let target = log.append(make(), &identity).await.unwrap();
    log.append(
        content(
            &identity,
            "bug-42",
            ClaimBody::Retraction {
                supersedes: target.clone(),
            },
        ),
        &identity,
    )
    .await
    .unwrap();

    // The same words again. A new claim, not a resurrection of the old one.
    let reasserted = log.append(make(), &identity).await.unwrap();
    assert_ne!(reasserted, target);

    let trust = TrustBase::solo(author(&identity));
    let view = fold::fold(log.iter_all().await.unwrap(), &trust);
    let class = view
        .subject(&SubjectRef::Local(Rkey::from("bug-42")))
        .expect("subject should be present");

    let live: Vec<_> = class.claims.iter().map(|(cid, _)| cid).collect();
    assert!(
        !live.contains(&&target),
        "the retracted claim must stay retracted -- re-recording the same text \
         creates a new claim, it does not revive the superseded one"
    );
    assert!(
        live.contains(&&reasserted),
        "the newly recorded claim is its own claim and must be live"
    );
}

/// AC-3. It fired on ordinary traffic, not exotic input: `artifacts` pins
/// `HEAD`, so any two identical writes between commits collided.
#[tokio::test]
async fn repeating_the_same_status_three_times_records_three_claims() {
    let (_dir, mut log, identity) = fresh().await;
    for _ in 0..3 {
        log.append(
            content(
                &identity,
                "task",
                ClaimBody::Status {
                    value: kan::claim::StatusValue::Open,
                },
            ),
            &identity,
        )
        .await
        .unwrap();
    }
    assert_eq!(log.iter_all().await.unwrap().len(), 3);
}

/// `docs/SPEC.md` §7.1's coexistence contract, at the field level: a claim
/// written before this field existed has no `recorded_at` key at all, and
/// must re-encode to exactly the bytes it was signed over — otherwise every
/// pre-v0.7 claim in every existing log would be reported as altered since
/// it was signed. `skip_serializing_if` is what makes that true, and this
/// test is what stops someone removing it.
#[test]
fn a_claim_without_recorded_at_round_trips_byte_identically() {
    let legacy = ClaimContent {
        author: AuthorId {
            did: "did:key:zLegacy".to_string(),
            agent: None,
        },
        workspace: Anchor::Workspace("genesis".to_string()),
        subject: SubjectRef::Local(Rkey::from("bug-42")),
        // Deliberately does not mention the field name: the assertion below
        // greps the encoded bytes, and narrative text lands in those bytes.
        body: observation("written by a kan that predates the time field"),
        cites: vec![],
        artifacts: vec![],
        recorded_at: None,
    };

    let bytes = atproto_dasl::to_vec(&legacy).unwrap();
    let decoded: ClaimContent = atproto_dasl::from_slice(&bytes).unwrap();
    assert_eq!(decoded, legacy);
    assert_eq!(
        atproto_dasl::to_vec(&decoded).unwrap(),
        bytes,
        "a claim with no recorded_at must re-encode byte-identically, or every \
         pre-v0.7 claim becomes unverifiable"
    );

    let encoded = String::from_utf8_lossy(&bytes).to_string();
    assert!(
        !encoded.contains("recorded_at"),
        "None must be omitted from the encoding entirely, not written as null"
    );
}

/// REQ-11. ADR-44 put `deny_unknown_fields` on `ClaimContent` and missed
/// `KnownBody`, so a *known* kind carrying a field from a newer kan
/// deserialized fine, silently dropped the field, and was then reported as
/// altered since it was signed — the contract's own worst case, live one
/// level down. With the attribute, deserialization of the known shape fails
/// and `ClaimBody` falls through to `Unknown`, preserving the bytes.
#[test]
fn a_known_kind_with_an_unknown_field_is_preserved_not_reported_as_tampered() {
    // An `Observation` as a newer kan might write it: the field this build
    // knows, plus one it does not. Same shape as `ClaimBody`'s own encoding
    // (externally tagged), so this is exactly what would arrive on the wire.
    #[derive(serde::Serialize)]
    enum FutureKnownBody {
        Observation { text: String, confidence: u8 },
    }

    let bytes = atproto_dasl::to_vec(&FutureKnownBody::Observation {
        text: "hello".to_string(),
        confidence: 9,
    })
    .unwrap();

    let decoded: ClaimBody = atproto_dasl::from_reader(&bytes[..])
        .expect("a known kind with an unknown field must decode, not be rejected");
    assert!(
        matches!(decoded, ClaimBody::Unknown { .. }),
        "a known kind carrying an unknown field must be preserved as Unknown, \
         not silently narrowed to the fields this build happens to understand; \
         got {decoded:?}"
    );
    assert_eq!(
        atproto_dasl::to_vec(&decoded).unwrap(),
        bytes,
        "preserved bytes must re-encode identically -- that is what stops the \
         claim being reported as altered since it was signed"
    );
}

/// The stale-binary error must tell an operator what to do.
///
/// Honest about its reach: this message lives in the *reader*, so it helps
/// every kan from v0.7 forward that meets a log from a newer one. It cannot
/// retroactively improve what v0.6 says — that binary is already shipped, and
/// upgrading past it is exactly the advice this message would have given.
#[test]
fn an_out_of_date_reader_is_told_to_upgrade_rather_than_suspect_corruption() {
    #[derive(serde::Serialize)]
    struct FutureContent {
        author: AuthorId,
        workspace: Anchor,
        subject: SubjectRef,
        body: ClaimBody,
        cites: Vec<atproto_dasl::Cid>,
        artifacts: Vec<kan::claim::ArtifactRef>,
        /// A field no released kan knows about.
        invented_by_a_newer_kan: u64,
    }

    let bytes = atproto_dasl::to_vec(&FutureContent {
        author: AuthorId {
            did: "did:key:zX".to_string(),
            agent: None,
        },
        workspace: Anchor::Workspace("g".to_string()),
        subject: SubjectRef::Local(Rkey::from("s")),
        body: observation("from the future"),
        cites: vec![],
        artifacts: vec![],
        invented_by_a_newer_kan: 7,
    })
    .unwrap();

    let decode_err = atproto_dasl::from_reader::<_, ClaimContent>(&bytes[..])
        .expect_err("deny_unknown_fields must reject a field this build does not know");
    let wrapped: kan::store::index::Error = decode_err.into();
    let msg = wrapped.to_string();

    assert!(
        msg.contains("older than the log"),
        "the message must name the actual cause: {msg}"
    );
    assert!(
        msg.contains("not damaged"),
        "it must say the log is fine, or it reads as corruption: {msg}"
    );
    assert!(msg.contains("cargo install"), "it must name the fix: {msg}");
}

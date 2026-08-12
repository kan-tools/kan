//! The v3 record format: declared wire shapes instead of `Debug`, base64
//! instead of hex, and a separator with no `---` run.
//!
//! `review/f4-debug-wire-contract`: v1 and v2 wrote `format!("{:?}")` into
//! `subject` and `kind` and then *strictly compared* those strings on read, so
//! `std`'s formatting became a wire contract nobody declared. An enum rename, a
//! variant reorder, or a change in how `std` escapes a string invalidates every
//! file ever published — and the failure surfaces as `HeaderMismatch`, which
//! reads as tampering rather than as a format change.
//!
//! These tests pin the reader. **The writer still emits v2** — `FORMAT_VERSION`
//! lags `MAX_READABLE_VERSION` on purpose, so a released kan can read v3 before
//! any tree contains it. `to_record_at_version` is what lets the tests write
//! what the writer will not yet.

use kan::{
    claim::{Anchor, AuthorId, ClaimBody, ClaimContent, Rkey, Span, SubjectRef},
    sign::Identity,
    transport::git_tree,
};

fn signed_subject(identity: &Identity, subject: SubjectRef, text: &str) -> kan::claim::Claim {
    let content = ClaimContent {
        author: AuthorId {
            did: identity.did(),
            agent: None,
        },
        workspace: Anchor::Workspace("genesis".to_string()),
        subject,
        body: ClaimBody::Observation {
            text: text.to_string(),
        },
        cites: vec![],
        artifacts: vec![],
        recorded_at: Some(1_700_000_000_000_000),
    };
    let cid = kan::cid::content_cid(&content).unwrap();
    let sig = identity.sign(&cid.to_bytes()).unwrap();
    kan::claim::Claim { content, sig }
}

fn signed(identity: &Identity, text: &str) -> kan::claim::Claim {
    signed_subject(identity, SubjectRef::Local(Rkey::from("bug-42")), text)
}

fn header_of(record: &str) -> serde_json::Value {
    let rest = record.trim_start().strip_prefix("---").unwrap();
    let end = rest.find("\n---").unwrap();
    serde_json::from_str(rest[..end].trim()).unwrap()
}

/// Every subject shape, because the point of a declared wire form is that it
/// covers the variants `Debug` was covering by accident. `Anchor::Blob` is the
/// one that forces an explicit encoding at all: it holds a `Cid`, which through
/// `serde_json` becomes `{"": [0, 1, 113, …]}` and does not deserialize back
/// (ADR-44 measurement 1).
fn every_subject() -> Vec<(&'static str, SubjectRef)> {
    let cid = kan::cid::content_cid(&ClaimContent {
        author: AuthorId {
            did: "did:key:zzz".to_string(),
            agent: None,
        },
        workspace: Anchor::Workspace("g".to_string()),
        subject: SubjectRef::Local(Rkey::from("x")),
        body: ClaimBody::Observation {
            text: String::new(),
        },
        cites: vec![],
        artifacts: vec![],
        recorded_at: None,
    })
    .unwrap();
    vec![
        ("local", SubjectRef::Local(Rkey::from("bug-42"))),
        (
            "local with slashes",
            SubjectRef::Local(Rkey::from("telos/legible-process")),
        ),
        (
            "local with quotes and escapes",
            SubjectRef::Local(Rkey::from(r#"a"b\c"#)),
        ),
        (
            "workspace",
            SubjectRef::Anchor(Anchor::Workspace("genesis".to_string())),
        ),
        (
            "commit",
            SubjectRef::Anchor(Anchor::Commit("abc123".to_string())),
        ),
        ("blob", SubjectRef::Anchor(Anchor::Blob(cid))),
        (
            "file at",
            SubjectRef::Anchor(Anchor::FileAt("src/lib.rs".into(), "deadbeef".to_string())),
        ),
        (
            "line range at",
            SubjectRef::Anchor(Anchor::LineRangeAt(
                "src/lib.rs".into(),
                "deadbeef".to_string(),
                Span { start: 3, end: 9 },
            )),
        ),
    ]
}

#[test]
fn a_v3_record_round_trips_for_every_subject_shape() {
    let identity = Identity::generate();
    for (name, subject) in every_subject() {
        let claim = signed_subject(&identity, subject.clone(), "a finding");
        let record = git_tree::to_record_at_version(&claim, None, None, 3).unwrap();
        let (_, read) = git_tree::from_record("t", &record)
            .unwrap_or_else(|e| panic!("{name}: v3 record did not read back: {e}"));
        assert_eq!(read.content.subject, subject, "{name}: subject");
        assert_eq!(read.content, claim.content, "{name}: content");
    }
}

#[test]
fn a_v3_subject_is_a_structured_value_not_a_debug_string() {
    let identity = Identity::generate();
    let claim = signed(&identity, "a finding");
    let record = git_tree::to_record_at_version(&claim, None, None, 3).unwrap();
    let header = header_of(&record);

    assert!(
        header["subject"].is_object(),
        "v3 `subject` must be a declared shape, not `Debug` output. got: {}",
        header["subject"]
    );
    assert!(
        !record.contains(r#"Local(""#),
        "no `Debug`-shaped subject may appear anywhere in a v3 record"
    );
    assert_eq!(header["kind"], "observation", "v3 kind is the wire name");
}

#[test]
fn a_v2_record_still_reads_and_still_uses_debug_and_hex() {
    // The compatibility half. v0.6.0..v0.12.x published these, and a peer's
    // file cannot be rewritten by us, so this is a contract rather than a
    // deprecation window.
    let identity = Identity::generate();
    let claim = signed(&identity, "an older finding");
    let record = git_tree::to_record_at_version(&claim, None, None, 2).unwrap();
    let header = header_of(&record);

    assert_eq!(header["subject"], r#"Local("bug-42")"#);
    assert_eq!(header["kind"], "Observation");
    let (_, read) = git_tree::from_record("t", &record).unwrap();
    assert_eq!(read.content, claim.content);
}

#[test]
fn the_writer_never_emits_a_version_the_reader_cannot_read() {
    // The durable form of the reader-before-writer rule.
    //
    // This asserted `the writer still emits v2` while v0.12.0-beta.5 shipped
    // the v3 reader alone. That invariant is now DISCHARGED -- beta.5 is
    // released, so a clone one version old already reads v3 and the writer
    // flipped. Deleting the test would lose the rule; pinning "v2" would pin a
    // moment. What survives every flip is that the writer must never lead the
    // reader, because a tree in a shape no released kan can read is unreadable
    // by every clone that has not upgraded, and `.claims/` exists for other
    // people.
    let identity = Identity::generate();
    let claim = signed(&identity, "a finding");
    let emitted = header_of(&git_tree::to_record(&claim).unwrap())["v"]
        .as_u64()
        .expect("a record carries a numeric version");

    // Whatever the writer emits, this build must be able to read it back.
    let round_tripped = git_tree::from_record("t", &git_tree::to_record(&claim).unwrap());
    assert!(
        round_tripped.is_ok(),
        "this build must read what it writes: {round_tripped:?}"
    );

    // And a version one beyond must still be refused by number, which is what
    // makes the gap between writer and reader legible rather than implicit.
    let future =
        git_tree::to_record_at_version(&claim, None, None, u32::try_from(emitted).unwrap())
            .unwrap()
            .replace(
                &format!("\"v\": {emitted}"),
                &format!("\"v\": {}", emitted + 1),
            );
    assert!(
        git_tree::from_record("t", &future).is_err(),
        "a version beyond this build must not be accepted silently"
    );
}

#[test]
fn a_v3_record_carrying_a_hex_payload_is_rejected_rather_than_misread() {
    // The encoding is chosen by the header's `v`, never by sniffing. A decoder
    // that tried both would turn a corrupt v3 record into a different *valid*
    // v2 one, and the CID check would then report an honest claim as altered
    // since it was signed.
    let identity = Identity::generate();
    let claim = signed(&identity, "a finding");
    let v2 = git_tree::to_record_at_version(&claim, None, None, 2).unwrap();
    let hex_payload = header_of(&v2)["content"].as_str().unwrap().to_string();

    let v3 = git_tree::to_record_at_version(&claim, None, None, 3).unwrap();
    let b64_payload = header_of(&v3)["content"].as_str().unwrap().to_string();
    let forged = v3.replace(&b64_payload, &hex_payload);

    let err = git_tree::from_record("t", &forged)
        .expect_err("a hex payload in a v3 record must not decode");
    let msg = err.to_string();
    assert!(
        msg.contains("base64") || msg.contains("altered") || msg.contains("malformed"),
        "the error should name the decoding problem. got: {msg}"
    );
}

#[test]
fn base64_is_shorter_than_hex_for_the_same_claim() {
    // kan#195's measurable half: hex doubles the payload for nothing.
    let identity = Identity::generate();
    let claim = signed(&identity, "a finding of ordinary length");
    let v2 = header_of(&git_tree::to_record_at_version(&claim, None, None, 2).unwrap());
    let v3 = header_of(&git_tree::to_record_at_version(&claim, None, None, 3).unwrap());
    let hex = v2["content"].as_str().unwrap().len();
    let b64 = v3["content"].as_str().unwrap().len();
    assert!(
        b64 < hex && b64 as f64 <= hex as f64 * 0.7,
        "base64 ({b64}) should be well under hex ({hex})"
    );
}

#[test]
fn tampering_with_a_v3_subject_or_kind_is_still_caught() {
    // `.design/git-tree-transport.md` REQ-9's forgery defence must survive the
    // move to structural comparison. The whole reason the format exists is
    // human review in a PR, so the fields a human reads are exactly the ones
    // that must not be able to lie.
    let identity = Identity::generate();
    let claim = signed(&identity, "a finding");
    let record = git_tree::to_record_at_version(&claim, None, None, 3).unwrap();

    let lied = record.replace(r#""local": "bug-42""#, r#""local": "bug-43""#);
    assert_ne!(lied, record, "the test must actually change the subject");
    let err = git_tree::from_record("t", &lied).expect_err("a forged v3 subject must be caught");
    assert!(
        err.to_string().contains("subject"),
        "the error should name the field. got: {err}"
    );

    let lied = record.replace(r#""kind": "observation""#, r#""kind": "decision""#);
    assert_ne!(lied, record, "the test must actually change the kind");
    let err = git_tree::from_record("t", &lied).expect_err("a forged v3 kind must be caught");
    assert!(
        err.to_string().contains("kind"),
        "the error should name the field. got: {err}"
    );
}

#[test]
fn a_v3_subject_of_the_wrong_shape_is_a_readable_error() {
    let identity = Identity::generate();
    let claim = signed(&identity, "a finding");
    let record = git_tree::to_record_at_version(&claim, None, None, 3).unwrap();
    let broken = record.replace(r#""subject": {"#, r#""subject2": {"#);
    let err = git_tree::from_record("t", &broken).expect_err("a v3 header needs a wire subject");
    assert!(
        !err.to_string().is_empty(),
        "the reader must say something actionable"
    );
}

#[test]
fn a_version_beyond_the_reader_is_reported_by_number() {
    let identity = Identity::generate();
    let claim = signed(&identity, "a finding");
    let record = git_tree::to_record_at_version(&claim, None, None, 3).unwrap();
    let future = record.replace(r#""v": 3"#, r#""v": 4"#);
    assert_ne!(future, record, "the test must actually change the version");

    let err = git_tree::from_record("t", &future).expect_err("v4 is beyond this build");
    let msg = err.to_string();
    assert!(
        msg.contains('4') && msg.contains("not damaged"),
        "a future version must be named as a version, not as corruption. got: {msg}"
    );
}

#[test]
fn the_v3_separator_contains_no_fence_run() {
    // The v1/v2 separator contains `---`, so a scan for the frontmatter fence
    // re-enters on it and tries to parse `8<` as a header (kan#195).
    let identity = Identity::generate();
    let a = signed(&identity, "first");
    let b = signed(&identity, "second");
    let joined = format!(
        "{}***8<***\n{}",
        git_tree::to_record_at_version(&a, None, Some((0, 2)), 3).unwrap(),
        git_tree::to_record_at_version(&b, None, Some((1, 2)), 3).unwrap()
    );

    let records = git_tree::split_records(&joined);
    assert_eq!(records.len(), 2, "both v3 records must be found");
    for record in &records {
        git_tree::from_record("t", record).expect("each split record verifies");
    }
}

#[test]
fn a_body_containing_either_separator_survives_v3_framing() {
    // `text_len` framing means record content never decides where a record
    // ends — the defect that turned one claim into three phantoms.
    let identity = Identity::generate();
    for text in [
        "before\n---8<---\nafter",
        "before\n***8<***\nafter",
        "---\nlooks like frontmatter",
        "***8<***",
    ] {
        let a = signed(&identity, text);
        let b = signed(&identity, "second");
        let joined = format!(
            "{}***8<***\n{}",
            git_tree::to_record_at_version(&a, None, Some((0, 2)), 3).unwrap(),
            git_tree::to_record_at_version(&b, None, Some((1, 2)), 3).unwrap()
        );
        let records = git_tree::split_records(&joined);
        assert_eq!(records.len(), 2, "body {text:?} tore the file into records");
        let (_, read) = git_tree::from_record("t", records[0]).unwrap();
        assert_eq!(
            read.content.body.text(),
            Some(text),
            "body {text:?} did not survive"
        );
    }
}

#[test]
fn a_mixed_file_splits_both_ways() {
    // Not a shape the writer produces, but the split runs before any header is
    // parsed, so it cannot ask what version it is reading. Being explicit that
    // both separators are understood beats discovering it from a torn file.
    let identity = Identity::generate();
    let a = signed(&identity, "first");
    let b = signed(&identity, "second");
    let joined = format!(
        "{}---8<---\n{}",
        git_tree::to_record_at_version(&a, None, Some((0, 2)), 2).unwrap(),
        git_tree::to_record_at_version(&b, None, Some((1, 2)), 3).unwrap()
    );
    let records = git_tree::split_records(&joined);
    assert_eq!(records.len(), 2);
    for record in &records {
        git_tree::from_record("t", record).expect("each record verifies under its own version");
    }
}

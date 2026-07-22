//! `.design/v0.7-milestone.md` REQ-7/REQ-8/REQ-14 — the published record's
//! framing.
//!
//! Version 1 wrote narrative text verbatim and read it back with `.trim()`,
//! so the writer's own output failed its own reader on 8 of 22 tested inputs.
//! Each produced "the record has been altered since it was signed" against an
//! honest claim — unrecoverably, because the CID is frozen in the
//! append-only log, and silently, because `publish` exits 0. A trailing
//! newline is the common case for any multi-line text arriving over MCP.
//!
//! It also split the file on a separator string that narrative prose could
//! contain, turning one claim into three phantom records.

use kan::{
    claim::{Anchor, AuthorId, ClaimBody, ClaimContent, Rkey, SubjectRef},
    sign::Identity,
    transport::git_tree,
};

fn signed(identity: &Identity, text: &str) -> kan::claim::Claim {
    let content = ClaimContent {
        author: AuthorId {
            did: identity.did(),
            agent: None,
        },
        workspace: Anchor::Workspace("genesis".to_string()),
        subject: SubjectRef::Local(Rkey::from("bug-42")),
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

/// Every case in track 3's matrix, including all 8 that were broken.
fn hostile_texts() -> Vec<(&'static str, String)> {
    vec![
        ("plain", "a simple observation".to_string()),
        ("trailing newline", "line1\n\nline2\n\n".to_string()),
        ("leading space", " leading".to_string()),
        ("trailing space", "trailing ".to_string()),
        ("tab indented", "\tindented".to_string()),
        ("whitespace only", "   \n  ".to_string()),
        ("CRLF", "one\r\ntwo\r\n".to_string()),
        ("NBSP at end", "text\u{00A0}".to_string()),
        ("many blank lines", "a\n\n\nb\n\n".to_string()),
        (
            "record separator in prose",
            "before\n---8<---\nafter".to_string(),
        ),
        ("separator alone", "---8<---".to_string()),
        ("--- on own line", "before\n---\nafter".to_string()),
        ("starts with ---", "---\nlooks like frontmatter".to_string()),
        (
            "looks like a header",
            "---\n{\"cid\": \"x\"}\n---\n".to_string(),
        ),
        ("emoji + combining", "🌍é\u{0301}".to_string()),
        ("zero width space", "a\u{200B}b".to_string()),
        ("BOM", "\u{FEFF}text".to_string()),
        ("lone CR", "a\rb".to_string()),
        ("long", "x".repeat(100_000)),
        (
            "yaml metacharacters",
            "key: value\n- item\n#c\n@a\n*b\n&c\n!d\n%e\n|f\n>g".to_string(),
        ),
    ]
}

/// AC-8 and AC-9: every one of these must publish and parse back to a
/// matching CID, as exactly one record.
#[test]
fn every_hostile_text_round_trips_byte_exactly() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::load_or_create(&dir.path().join("identity")).unwrap();

    let mut broken = Vec::new();
    for (label, text) in hostile_texts() {
        let claim = signed(&identity, &text);
        let expected = kan::cid::content_cid(&claim.content).unwrap();
        let record = git_tree::to_record(&claim).unwrap();

        let records = git_tree::split_records(&record);
        if records.len() != 1 {
            broken.push(format!("{label}: split into {} records", records.len()));
            continue;
        }
        match git_tree::from_record("f.md", records[0]) {
            Ok((cid, parsed)) => {
                if cid != expected {
                    broken.push(format!("{label}: CID mismatch"));
                } else if parsed.content.body.text() != Some(text.as_str()) {
                    broken.push(format!(
                        "{label}: text not byte-exact ({:?} != {:?})",
                        parsed.content.body.text(),
                        text
                    ));
                }
            }
            Err(e) => broken.push(format!("{label}: {e}")),
        }
    }
    assert!(
        broken.is_empty(),
        "{} of {} inputs failed their own writer's output:\n  {}",
        broken.len(),
        hostile_texts().len(),
        broken.join("\n  ")
    );
}

/// AC-9 specifically: the separator in prose must not tear one claim apart,
/// even with several records in one file.
#[test]
fn a_separator_in_prose_does_not_tear_a_multi_record_file() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::load_or_create(&dir.path().join("identity")).unwrap();

    let claims: Vec<_> = [
        "ordinary first claim",
        "second claim\n---8<---\nstill the second claim",
        "third claim, trailing newline\n",
    ]
    .iter()
    .map(|t| (signed(&identity, t), None))
    .collect();

    let path = git_tree::write_subject(
        dir.path(),
        &SubjectRef::Local(Rkey::from("bug-42")),
        &claims,
    )
    .unwrap();
    let text = std::fs::read_to_string(&path).unwrap();

    let records = git_tree::split_records(&text);
    assert_eq!(records.len(), 3, "one record per claim, no phantoms");
    for (i, record) in records.iter().enumerate() {
        let (cid, parsed) = git_tree::from_record("bug-42.md", record)
            .unwrap_or_else(|e| panic!("record {i} failed: {e}"));
        assert_eq!(cid, kan::cid::content_cid(&claims[i].0.content).unwrap());
        assert_eq!(
            parsed.content.body.text(),
            claims[i].0.content.body.text(),
            "record {i} text must be byte-exact"
        );
    }
}

/// AC-15: a record from a declared-future version says so by version number,
/// rather than failing deeper with a message about hex or CIDs.
#[test]
fn a_future_format_version_is_named_rather_than_misreported() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::load_or_create(&dir.path().join("identity")).unwrap();
    let record = git_tree::to_record(&signed(&identity, "hello")).unwrap();

    let bumped = record.replacen("\"v\": 2", "\"v\": 99", 1);
    assert_ne!(bumped, record, "the version field must be present to bump");

    let err = git_tree::from_record("f.md", &bumped)
        .expect_err("a future version must not be accepted silently");
    let msg = err.to_string();
    assert!(
        msg.contains("99"),
        "the error must name the version it met: {msg}"
    );
    assert!(
        !msg.contains("does not match its own content"),
        "a newer format must not be reported as tampering: {msg}"
    );
}

/// Coexistence: records written by v0.6.0-beta.1 carry no version and no
/// declared length, and must still read.
#[test]
fn a_version_one_record_without_a_declared_length_still_reads() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::load_or_create(&dir.path().join("identity")).unwrap();
    let claim = signed(&identity, "written by an older kan");
    let expected = kan::cid::content_cid(&claim.content).unwrap();

    // Strip exactly what v1 didn't have.
    let record = git_tree::to_record(&claim).unwrap();
    let legacy: String = record
        .lines()
        .filter(|l| {
            !l.trim_start().starts_with("\"v\":") && !l.trim_start().starts_with("\"text_len\":")
        })
        .collect::<Vec<_>>()
        .join("\n");

    let (cid, parsed) = git_tree::from_record("f.md", &legacy)
        .expect("a v1 record must still parse -- SPEC 7.1 coexistence");
    assert_eq!(cid, expected);
    assert_eq!(parsed.content.body.text(), Some("written by an older kan"));
}

/// AC-14. `telos/x` and `telos_x` collapsed to one file, and publishing the
/// second silently destroyed the first's record. `telos/<slug>` is `day`'s
/// naming convention (ADR-42), so this was live, not hypothetical.
#[test]
fn subjects_that_differ_only_in_punctuation_get_different_files() {
    let colliding = [
        ("telos/legible-process", "telos_legible-process"),
        ("bug 42", "bug-42"),
        ("a/b", "a:b"),
    ];
    for (left, right) in colliding {
        let l = git_tree::file_name(&SubjectRef::Local(Rkey::from(left)));
        let r = git_tree::file_name(&SubjectRef::Local(Rkey::from(right)));
        assert_ne!(l, r, "{left:?} and {right:?} must not share a file");
    }
}

/// The same, for case — APFS is case-insensitive by default, so two names
/// differing only in case are one file no matter what kan maps them to.
/// The disambiguating suffix is lowercase hex precisely so it survives case
/// folding.
#[test]
fn subjects_differing_only_in_case_get_different_files() {
    let upper = git_tree::file_name(&SubjectRef::Local(Rkey::from("Bug42")));
    let lower = git_tree::file_name(&SubjectRef::Local(Rkey::from("bug42")));
    assert_ne!(upper, lower);
    assert_ne!(
        upper.to_lowercase(),
        lower.to_lowercase(),
        "they must still differ after case folding, or a case-insensitive \
         filesystem collapses them regardless of what kan intended"
    );
}

/// Publishing two colliding subjects must leave both records readable —
/// the end-to-end version of the two tests above.
#[test]
fn publishing_two_colliding_subjects_keeps_both() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::load_or_create(&dir.path().join("identity")).unwrap();

    for name in ["telos/legible-process", "telos_legible-process"] {
        let mut claim = signed(&identity, &format!("claim about {name}"));
        claim.content.subject = SubjectRef::Local(Rkey::from(name));
        let cid = kan::cid::content_cid(&claim.content).unwrap();
        claim.sig = identity.sign(&cid.to_bytes()).unwrap();
        git_tree::write_subject(
            dir.path(),
            &SubjectRef::Local(Rkey::from(name)),
            &[(claim, None)],
        )
        .unwrap();
    }

    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir.path().join(".claims")).unwrap() {
        let text = std::fs::read_to_string(entry.unwrap().path()).unwrap();
        for record in git_tree::split_records(&text) {
            let (_, claim) = git_tree::from_record("x.md", record).unwrap();
            found.push(claim.content.body.text().unwrap().to_string());
        }
    }
    found.sort();
    assert_eq!(
        found,
        vec![
            "claim about telos/legible-process".to_string(),
            "claim about telos_legible-process".to_string(),
        ],
        "publishing the second subject must not destroy the first's record"
    );
}

//! `.design/git-tree-transport.md` — the git tree as a sharing layer.
//!
//! The claims under test are the ones that make the format safe: a record
//! round-trips to a byte-identical CID, a tampered record is detected rather
//! than trusted, and claims read back out of the tree fold exactly as claims
//! read out of a log.

use kan::{
    cid::content_cid,
    claim::v1::{Anchor, AuthorId, Claim, ClaimBody, ClaimContent, Layer, Rkey, SubjectRef},
    sign::Identity,
    store::log::Log,
    transport::{git_tree, Transport},
};

fn identity() -> Identity {
    Identity::generate()
}

fn content(subject: &str, body: ClaimBody, identity: &Identity) -> ClaimContent {
    ClaimContent {
        author: AuthorId {
            did: identity.did(),
            agent: None,
        },
        workspace: Anchor::Workspace("genesis".to_string()),
        subject: SubjectRef::Local(subject.to_string()),
        body,
        cites: vec![],
        artifacts: vec![],
        recorded_at: None,
    }
}

fn signed(content: ClaimContent, identity: &Identity) -> Claim {
    let cid = content_cid(&content).unwrap();
    let sig = identity.sign(&cid.to_bytes()).unwrap();
    Claim { content, sig }
}

fn observation(subject: &str, text: &str, id: &Identity) -> Claim {
    signed(
        content(
            subject,
            ClaimBody::Observation {
                text: text.to_string(),
            },
            id,
        ),
        id,
    )
}

/// AC-3: a claim's identity survives the round trip. This is the property
/// everything else rests on — if serializing changed the CID, the tree would
/// hold different claims than the log, not the same ones elsewhere.
#[test]
fn a_record_round_trips_to_the_same_cid() {
    let id = identity();
    let claim = observation("bug-42", "the parser drops trailing commas", &id);
    let expected = content_cid(&claim.content).unwrap();

    let record = git_tree::to_record(&claim).unwrap();
    let (cid, parsed) = git_tree::from_record("test.md", &record).unwrap();

    assert_eq!(cid, expected);
    assert_eq!(parsed, claim);
}

/// The narrative text lives in the Markdown body, so a reader sees the same
/// prose the signature covers.
#[test]
fn narrative_text_is_in_the_body_not_the_frontmatter() {
    let id = identity();
    let claim = observation("bug-42", "a distinctive sentence", &id);
    let record = git_tree::to_record(&claim).unwrap();

    let (frontmatter, body) = record
        .trim_start_matches("---")
        .split_once("\n---")
        .expect("a record has a closed frontmatter fence");
    assert!(
        !frontmatter.contains("a distinctive sentence"),
        "text should not be duplicated into the frontmatter:\n{frontmatter}"
    );
    assert!(body.contains("a distinctive sentence"), "{body}");
}

/// AC-5: editing the visible prose changes the CID and is caught. Without
/// this the file would be an unsigned artifact that merely looked
/// authoritative.
#[test]
fn a_hand_edited_body_is_detected_as_a_cid_mismatch() {
    let id = identity();
    let claim = observation("bug-42", "the original wording", &id);
    let record = git_tree::to_record(&claim).unwrap();
    let tampered = record.replace("the original wording", "something else entirely");

    let err =
        git_tree::from_record("test.md", &tampered).expect_err("a tampered body must not verify");
    assert!(
        matches!(err, git_tree::Error::CidMismatch { .. }),
        "expected a CID mismatch, got: {err}"
    );
}

/// AC-5: a record whose signature was produced by a different key does not
/// verify, even though its content hashes correctly.
#[test]
fn a_signature_from_another_key_is_rejected() {
    let author = identity();
    let impostor = identity();

    let content = content(
        "bug-42",
        ClaimBody::Observation {
            text: "claims to be from the author".to_string(),
        },
        &author,
    );
    let cid = content_cid(&content).unwrap();
    // Correct content, correct CID, wrong signer.
    let claim = Claim {
        content,
        sig: impostor.sign(&cid.to_bytes()).unwrap(),
    };

    let record = git_tree::to_record(&claim).unwrap();
    let err = git_tree::from_record("test.md", &record)
        .expect_err("a signature from another key must not verify");
    assert!(
        matches!(err, git_tree::Error::BadSignature { .. }),
        "expected a signature failure, got: {err}"
    );
}

/// Bodies without narrative text (status, relations, publication) survive
/// the round trip too — the text-in-body rule must not corrupt them.
#[test]
fn textless_bodies_round_trip() {
    let id = identity();
    for body in [
        ClaimBody::Status {
            value: kan::claim::v1::StatusValue::Resolved,
        },
        ClaimBody::Publication {
            layer: Layer::GitTree,
        },
        ClaimBody::Subject {
            title: "a title".to_string(),
            subject_kind: kan::claim::v1::SubjectKind::Issue,
        },
    ] {
        let claim = signed(content("bug-42", body.clone(), &id), &id);
        let record = git_tree::to_record(&claim).unwrap();
        let (_, parsed) = git_tree::from_record("test.md", &record)
            .unwrap_or_else(|e| panic!("{body:?} should round trip: {e}"));
        assert_eq!(parsed, claim, "{body:?}");
    }
}

/// Found by publishing a real subject: 9 of 12 records failed to parse.
/// `Cid` serializes for DAG-CBOR, so through `serde_json` it became
/// `{"": [0, 1, 113, ...]}` — which does not deserialize back. Every claim
/// with a `cites` edge was unreadable; only the three without one worked.
/// The unit tests missed it entirely because their fixtures had no citations.
#[test]
fn a_claim_with_citations_round_trips() {
    let id = identity();
    let first = observation("bug-42", "the first finding", &id);
    let first_cid = content_cid(&first.content).unwrap();

    let mut content = content(
        "bug-42",
        ClaimBody::Observation {
            text: "a finding that builds on the first".to_string(),
        },
        &id,
    );
    content.cites = vec![first_cid.clone()];
    let claim = signed(content, &id);

    let record = git_tree::to_record(&claim).unwrap();
    let (_, parsed) =
        git_tree::from_record("test.md", &record).expect("a claim with citations must round trip");
    assert_eq!(parsed, claim);
    assert_eq!(parsed.content.cites, vec![first_cid]);
}

/// A retraction carries a `Cid` in its body rather than in `cites` — the
/// same hazard in a different position.
#[test]
fn a_retraction_round_trips() {
    let id = identity();
    let target = observation("bug-42", "to be retracted", &id);
    let supersedes = content_cid(&target.content).unwrap();

    let claim = signed(
        content("bug-42", ClaimBody::Retraction { supersedes }, &id),
        &id,
    );
    let record = git_tree::to_record(&claim).unwrap();
    let (_, parsed) = git_tree::from_record("test.md", &record).unwrap();
    assert_eq!(parsed, claim);
}

#[test]
fn several_records_share_one_subject_file() {
    let id = identity();
    let a = observation("bug-42", "first", &id);
    let b = observation("bug-42", "second", &id);

    let file = format!(
        "{}---8<---\n{}",
        git_tree::to_record(&a).unwrap(),
        git_tree::to_record(&b).unwrap()
    );
    let records = git_tree::split_records(&file);
    assert_eq!(records.len(), 2);
    let parsed: Vec<Claim> = records
        .iter()
        .map(|r| git_tree::from_record("f.md", r).unwrap().1)
        .collect();
    assert_eq!(parsed, vec![a, b]);
}

/// AC-8: ordering carries no meaning. Two clones whose merges interleaved
/// records differently must read the same claim set.
#[test]
fn record_order_does_not_change_the_claims_read() {
    let id = identity();
    let a = observation("bug-42", "first", &id);
    let b = observation("bug-42", "second", &id);
    let (ra, rb) = (
        git_tree::to_record(&a).unwrap(),
        git_tree::to_record(&b).unwrap(),
    );

    let forward = format!("{ra}---8<---\n{rb}");
    let reverse = format!("{rb}---8<---\n{ra}");

    let read = |text: &str| {
        let mut cids: Vec<String> = git_tree::split_records(text)
            .iter()
            .map(|r| git_tree::from_record("f.md", r).unwrap().0.to_string())
            .collect();
        cids.sort();
        cids
    };
    assert_eq!(read(&forward), read(&reverse));
}

/// A subject rkey containing `/` must not create directories.
#[test]
fn a_slashed_subject_becomes_one_flat_file() {
    let name = git_tree::file_name(&SubjectRef::Local("telos/legible-process".to_string()));
    assert!(!name.contains('/'), "{name}");
    assert!(name.ends_with(".md"), "{name}");
}

/// AC-2/AC-4: publishing writes the subject's claims into the tree, and
/// reading them back yields the same claims — the transport round trip, not
/// just the format's.
#[tokio::test]
async fn publishing_writes_the_tree_and_subscribing_reads_it_back() {
    let dir = tempfile::tempdir().unwrap();
    let id = identity();
    let log = Log::open_or_create(dir.path(), &id).await.unwrap();
    let mut tree = git_tree::GitTree::new(log, dir.path());

    let cid = tree
        .publish(
            content(
                "bug-42",
                ClaimBody::Observation {
                    text: "published into the tree".to_string(),
                },
                &id,
            ),
            &id,
        )
        .await
        .unwrap();

    // Filenames carry a digest of the exact subject bytes so the mapping is
    // injective (REQ-13) -- ask for the name rather than hardcoding it.
    // The subject's own name as a directory, one file per publishing author.
    let subject_dir = dir
        .path()
        .join(".claims")
        .join(git_tree::subject_path(&SubjectRef::Local(Rkey::from("bug-42"))).unwrap());
    let file = std::fs::read_dir(&subject_dir)
        .unwrap_or_else(|e| panic!("publishing should create {}: {e}", subject_dir.display()))
        .flatten()
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|x| x == "md"))
        .expect("publishing should write this author's file");
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(text.contains("published into the tree"));

    let read = tree.read_all();
    assert_eq!(read.len(), 1);
    let (read_cid, claim) = read.into_iter().next().unwrap().unwrap();
    assert_eq!(read_cid, cid, "the tree holds the same claim, not a copy");
    assert_eq!(claim.content.body.text(), Some("published into the tree"));
}

/// `.design/schema-evolution.md` AC-11. A CID is a content hash and carries
/// no time; a TID does. kan generates one per append but keeps it on
/// `StoredClaim`, so publishing used to drop it — leaving a clone able to
/// verify every claim and unable to order any two by time.
#[test]
fn a_published_record_carries_its_tid_and_stays_verifiable() {
    let id = identity();
    let claim = observation("bug-42", "recorded at some point", &id);
    let expected = content_cid(&claim.content).unwrap();

    let record = git_tree::to_record_with_rev(&claim, Some("3lqqx7abc2k22")).unwrap();
    let (cid, parsed, rev) = git_tree::from_record_with_rev("t.md", &record).unwrap();

    assert_eq!(rev.as_deref(), Some("3lqqx7abc2k22"));
    assert_eq!(parsed, claim);
    assert_eq!(
        cid, expected,
        "rev is envelope metadata and must not disturb the CID"
    );

    // A record written without one still reads: older records have no rev,
    // which is a gap rather than a failure.
    let bare = git_tree::to_record(&claim).unwrap();
    let (_, _, none) = git_tree::from_record_with_rev("t.md", &bare).unwrap();
    assert_eq!(none, None);
}

/// TIDs are lexicographically sortable, which is the whole reason to carry
/// one: two claims read out of a tree can be ordered without a clock.
#[test]
fn published_claims_can_be_ordered_by_tid() {
    let id = identity();
    let a = observation("bug-42", "first", &id);
    let b = observation("bug-42", "second", &id);
    let file = format!(
        "{}---8<---\n{}",
        git_tree::to_record_with_rev(&a, Some("3lqqx7aaaaa22")).unwrap(),
        git_tree::to_record_with_rev(&b, Some("3lqqx7bbbbb22")).unwrap()
    );

    let mut revs: Vec<String> = git_tree::split_records(&file)
        .iter()
        .filter_map(|r| git_tree::from_record_with_rev("f.md", r).unwrap().2)
        .collect();
    let original = revs.clone();
    revs.sort();
    assert_eq!(
        revs, original,
        "TIDs sort lexicographically into time order"
    );
}

/// AC-12: `.kan/` stays private, `.claims/` is the shared layer. They are
/// separate directories precisely so ADR-3's rule is extended rather than
/// contradicted.
#[test]
fn the_shared_layer_is_outside_the_private_store() {
    assert_ne!(git_tree::CLAIMS_DIR, ".kan");
    assert!(!git_tree::CLAIMS_DIR.starts_with(".kan"));
    assert!(!git_tree::GITATTRIBUTES_LINE.contains("merge=union"));
}

/// kan ships no merge-driver guidance for `.claims/`, and specifically not
/// `merge=union` — it is line-based, every record starts with the same
/// boilerplate lines, so git unions *inside* a record and welds two claims
/// into one malformed record with duplicate `cid`/`sig` keys. Both
/// concurrent claims are lost, at exit 0. A plain conflict is strictly
/// better: visible, and recoverable.
#[test]
fn no_merge_driver_is_recommended_for_the_shared_layer() {
    assert!(git_tree::GITATTRIBUTES_LINE.is_empty());
    // The guidance names `merge=union` in order to warn against it, so the
    // check is that it is not *recommended* — the word alone proves nothing.
    let guidance = git_tree::gitignore_guidance();
    assert!(guidance.contains("Do not set a merge driver"));
    assert!(guidance.contains("silently destroys"));
    assert!(!guidance.contains("Add to .gitattributes"));
}

/// #111: `write_subject`'s primary write must refuse to overwrite a file that
/// holds *another* subject's claims, rather than trusting the (lossy, 32-bit
/// digest) filename as a unique key — the last instance of ADR-52's class on a
/// write path. Simulated by placing subject B's real records at subject A's
/// path (the collision the digest could produce) and confirming a publish of A
/// is refused with the file left byte-for-byte intact.
///
/// Negative control: reverting the guard (removing the `retirable` check
/// before the write) makes A's publish overwrite B's file and this test fails
/// on the `FilenameCollision` match and the untouched-bytes assertion.
#[test]
fn publish_refuses_to_overwrite_another_subjects_file() {
    let id = identity();
    let root = tempfile::tempdir().unwrap();

    // B's genuine published file.
    let b = observation("subject-b", "b's only claim", &id);
    git_tree::write_subject(root.path(), &b.content.subject, &[(b.clone(), None)]).unwrap();

    // Force B's records to sit at A's path.
    //
    // The simulated collision CHANGED with the layout and the test says so
    // rather than being quietly deleted. It used to stand in for two subjects
    // colliding in the 4-byte filename digest; preserving `/` as a directory
    // separator removed that digest and that collision. What survives is
    // case folding — `Bug42` and `bug42` are one directory on APFS, below kan
    // entirely — so the guard still has a case to refuse, and this is it.
    let a_subject = SubjectRef::Local(Rkey::from("subject-a"));
    let claims_dir = root.path().join(git_tree::CLAIMS_DIR);
    let a_dir = claims_dir.join(git_tree::subject_path(&a_subject).unwrap());
    let b_dir = claims_dir.join(git_tree::subject_path(&b.content.subject).unwrap());
    assert_ne!(a_dir, b_dir);
    std::fs::create_dir_all(&a_dir).unwrap();
    let b_file = std::fs::read_dir(&b_dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|x| x == "md"))
        .expect("B has a published file");
    let a_path = a_dir.join(b_file.file_name().unwrap());
    std::fs::copy(&b_file, &a_path).unwrap();
    let before = std::fs::read(&a_path).unwrap();

    // Publishing A must refuse rather than clobber B's claims.
    let a = observation("subject-a", "a's claim", &id);
    let err = git_tree::write_subject(root.path(), &a_subject, &[(a, None)]).unwrap_err();
    assert!(
        matches!(err, git_tree::Error::FilenameCollision { .. }),
        "expected FilenameCollision, got {err:?}"
    );
    assert_eq!(
        std::fs::read(&a_path).unwrap(),
        before,
        "the colliding file must be left byte-for-byte intact"
    );
}

/// A normal re-publish of a subject's *own* file is not a collision and must
/// still succeed — the guard keys on the file's contents (all this subject's),
/// so this is the discriminating other half of the test above.
#[test]
fn republishing_a_subjects_own_file_succeeds() {
    let id = identity();
    let root = tempfile::tempdir().unwrap();
    let c1 = observation("subj", "first", &id);
    let subj = c1.content.subject.clone();
    git_tree::write_subject(root.path(), &subj, &[(c1.clone(), None)]).unwrap();
    // Re-publish the same subject with an extra claim — the file already
    // exists and is entirely this subject's, so the overwrite is allowed.
    let c2 = observation("subj", "second", &id);
    git_tree::write_subject(root.path(), &subj, &[(c1, None), (c2, None)])
        .expect("own-file re-publish must succeed");
}

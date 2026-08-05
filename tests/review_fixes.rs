//! Regression tests for the defects a pre-release adversarial review found in
//! v0.7 (ADR-49). Each reproduces the reviewer's own case.

use kan::{
    claim::{Anchor, AuthorId, ClaimBody, ClaimContent, Rkey, SubjectRef},
    sign::Identity,
    transport::git_tree,
};

fn signed(identity: &Identity, subject: &str, text: &str) -> kan::claim::Claim {
    let content = ClaimContent {
        author: AuthorId {
            did: identity.did(),
            agent: None,
        },
        workspace: Anchor::Workspace("g".to_string()),
        subject: SubjectRef::Local(Rkey::from(subject)),
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

/// D6 / REQ-13 second half / AC-14: a file whose name disagrees with the
/// records inside is reported.
///
/// The name was decorative — `read_all` never compared it to anything, so a
/// `.claims/x.md` full of subject-`y` claims folded as `y` in silence. With
/// the header fields also unverified before REQ-9, *nothing* about a file's
/// apparent subject was checkable; only the hex content was.
#[test]
fn a_file_named_for_the_wrong_subject_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::load_or_create(&dir.path().join("identity")).unwrap();
    let subject = SubjectRef::Local(Rkey::from("real-subject"));

    let path = git_tree::write_subject(
        dir.path(),
        &subject,
        &[(signed(&identity, "real-subject", "a claim"), None)],
    )
    .unwrap();

    // Rename it to another subject's filename, leaving records untouched.
    let impostor = dir
        .path()
        .join(".claims")
        .join(git_tree::file_name(&SubjectRef::Local(Rkey::from(
            "totally-different",
        ))));
    std::fs::rename(&path.path, &impostor).unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let results = rt.block_on(async {
        let id = Identity::load_or_create(&dir.path().join("reader-id")).unwrap();
        let log = kan::store::log::Log::open_or_create(&dir.path().join("reader-log"), &id)
            .await
            .unwrap();
        git_tree::GitTree::new(log, dir.path().to_path_buf()).read_all()
    });

    let reported = results.iter().any(|r| {
        r.as_ref()
            .err()
            .is_some_and(|e| e.to_string().contains("filename does not describe"))
    });
    assert!(
        reported,
        "a file whose name disagrees with its records must be reported; got {:?}",
        results
            .iter()
            .map(|r| r.as_ref().map(|_| "ok").map_err(|e| e.to_string()))
            .collect::<Vec<_>>()
    );
}

/// D4: a `SameAs` merge must not put one subject's claims into another
/// subject's file.
///
/// Folding before publishing is right — it filters retracted and untrusted
/// claims (REQ-12) — but the fold's unit is the merge *class*, so taking its
/// output wholesale duplicated every claim into every merged subject's file
/// and made publishing one rewrite the others.
#[test]
fn publishing_a_merged_subject_writes_only_that_subjects_claims() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::load_or_create(&dir.path().join("identity")).unwrap();

    for (subject, text) in [("alpha", "about alpha"), ("beta", "about beta")] {
        git_tree::write_subject(
            dir.path(),
            &SubjectRef::Local(Rkey::from(subject)),
            &[(signed(&identity, subject, text), None)],
        )
        .unwrap();
    }

    for (subject, foreign) in [("alpha", "about beta"), ("beta", "about alpha")] {
        let path = dir
            .path()
            .join(".claims")
            .join(git_tree::file_name(&SubjectRef::Local(Rkey::from(subject))));
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            !text.contains(foreign),
            "{subject}'s file must not contain another subject's claim"
        );
    }
}

/// #107: a `.claims/` file written by v0.6 must keep verifying, and
/// republishing must retire it rather than leaving a diverging duplicate.
///
/// v0.7 renamed files to make the mapping injective (REQ-13) and then added
/// filename authentication (D6). Each was right alone; together they orphaned
/// every existing published file and then reported every record in it as
/// mismatched — a wall of errors about files kan wrote itself. Neither change
/// was checked against what already existed.
#[test]
fn a_v0_6_published_file_still_verifies_and_is_retired_on_republish() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::load_or_create(&dir.path().join("identity")).unwrap();
    let subject = SubjectRef::Local(Rkey::from("bug-42"));
    let claim = signed(&identity, "bug-42", "written before the rename");

    // Publish, then move the file to the name v0.6 would have used.
    let written = git_tree::write_subject(dir.path(), &subject, &[(claim.clone(), None)]).unwrap();
    let legacy = dir
        .path()
        .join(".claims")
        .join(git_tree::legacy_file_name(&subject));
    assert_ne!(
        written.path, legacy,
        "the current name must differ from v0.6's, or this test proves nothing"
    );
    std::fs::rename(&written.path, &legacy).unwrap();

    // It must read clean under the old name: kan wrote it, it is signed, and
    // only the naming convention changed.
    let rt = tokio::runtime::Runtime::new().unwrap();
    let results = rt.block_on(async {
        let id = Identity::load_or_create(&dir.path().join("reader-id")).unwrap();
        let log = kan::store::log::Log::open_or_create(&dir.path().join("reader-log"), &id)
            .await
            .unwrap();
        git_tree::GitTree::new(log, dir.path().to_path_buf()).read_all()
    });
    let errors: Vec<String> = results
        .iter()
        .filter_map(|r| r.as_ref().err().map(|e| e.to_string()))
        .collect();
    assert!(
        errors.is_empty(),
        "a v0.6-named file must verify clean: {errors:?}"
    );

    // Republishing retires it rather than leaving two diverging files.
    let again = git_tree::write_subject(dir.path(), &subject, &[(claim, None)]).unwrap();
    assert_eq!(
        again.retired.as_deref(),
        Some(legacy.as_path()),
        "republishing must report retiring the old file, not do it silently"
    );
    assert!(!legacy.exists(), "the orphan must be gone");
    assert!(again.path.exists());

    let remaining: Vec<_> = std::fs::read_dir(dir.path().join(".claims"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name())
        .collect();
    assert_eq!(
        remaining.len(),
        1,
        "exactly one file per subject: {remaining:?}"
    );
}

/// Review D-A: publishing a subject must never retire a *different* subject's
/// file, even when both map to the same lossy v0.6 legacy name.
///
/// The first #107 fix keyed the deletion on `legacy_file_name` alone — the
/// very mapping whose lossiness caused #107 in the first place — so
/// publishing `telos/x` deleted `telos_x`'s file and told the user it had
/// rewritten it. A write path destroying another subject's data.
#[test]
fn publishing_does_not_retire_a_colliding_subjects_file() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::load_or_create(&dir.path().join("identity")).unwrap();

    // `telos_x` has a genuine v0.6 file of its own.
    let neighbour = SubjectRef::Local(Rkey::from("telos_x"));
    let w = git_tree::write_subject(
        dir.path(),
        &neighbour,
        &[(signed(&identity, "telos_x", "the neighbour's claim"), None)],
    )
    .unwrap();
    let legacy = dir
        .path()
        .join(".claims")
        .join(git_tree::legacy_file_name(&neighbour));
    std::fs::rename(&w.path, &legacy).unwrap();

    // Publish `telos/x` — a different subject that maps to the SAME legacy name.
    let colliding = SubjectRef::Local(Rkey::from("telos/x"));
    assert_eq!(
        git_tree::legacy_file_name(&colliding),
        git_tree::legacy_file_name(&neighbour),
        "the two subjects must share a legacy name, or this proves nothing"
    );
    let written = git_tree::write_subject(
        dir.path(),
        &colliding,
        &[(signed(&identity, "telos/x", "the colliding claim"), None)],
    )
    .unwrap();

    assert!(
        written.retired.is_none(),
        "publishing telos/x must not retire telos_x's file"
    );
    assert!(legacy.exists(), "the neighbour's file must survive");
    let text = std::fs::read_to_string(&legacy).unwrap();
    assert!(
        text.contains("the neighbour's claim"),
        "the neighbour's claim must be intact"
    );
}

/// Review D-C: a legacy-named file holding a *mix* of subjects (each mapping
/// to that legacy name) must not authenticate — only a uniform, single-subject
/// file gets the legacy allowance.
#[test]
fn a_mixed_subject_legacy_file_is_not_authenticated() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::load_or_create(&dir.path().join("identity")).unwrap();

    // Two subjects that both map to `telos_x.md` under the v0.6 scheme.
    let a = signed(&identity, "telos/x", "record about telos/x");
    let b = signed(&identity, "telos_x", "record about telos_x");
    let claims_dir = dir.path().join(".claims");
    std::fs::create_dir_all(&claims_dir).unwrap();
    let mixed = format!(
        "{}\n---8<---\n{}",
        git_tree::to_record(&a).unwrap(),
        git_tree::to_record(&b).unwrap()
    );
    let legacy_name = git_tree::legacy_file_name(&SubjectRef::Local(Rkey::from("telos_x")));
    std::fs::write(claims_dir.join(&legacy_name), mixed).unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let results = rt.block_on(async {
        let id = Identity::load_or_create(&dir.path().join("reader-id")).unwrap();
        let log = kan::store::log::Log::open_or_create(&dir.path().join("reader-log"), &id)
            .await
            .unwrap();
        git_tree::GitTree::new(log, dir.path().to_path_buf()).read_all()
    });
    let mismatch = results.iter().any(|r| {
        r.as_ref()
            .err()
            .is_some_and(|e| e.to_string().contains("does not describe"))
    });
    assert!(
        mismatch,
        "a mixed-subject legacy file must be reported, not waved through: {:?}",
        results
            .iter()
            .map(|r| r.as_ref().map(|_| "ok").map_err(|e| e.to_string()))
            .collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// v0.11's pre-release adversarial review, round two.
//
// The first round found six defects; they were fixed and the fixes shipped
// with NO tests at all. The re-review proved it the only way that counts --
// it reverted the entire source diff of the fix commits and the suite still
// passed 287/0. Nothing in the repo would have noticed the fixes vanishing.
//
// That is this project's own recurring failure in its purest form. The
// milestone those fixes belong to was *about* claims nothing checks, and
// rewrote nine tests that could not fail. Then its fix round wrote none.
//
// These run the real binary, because every one of these defects is about what
// the binary does across separate invocations -- an index left behind by one
// process and read by the next, a refusal that must leave the filesystem
// untouched. A library-level test cannot see any of it.
// ---------------------------------------------------------------------------

use std::process::Command;

struct Run {
    stdout: String,
    stderr: String,
    ok: bool,
}

fn kan(dir: &std::path::Path, key: Option<&std::path::Path>, args: &[&str]) -> Run {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kan"));
    cmd.args(args).current_dir(dir).env("KAN_NO_KEYCHAIN", "1");
    match key {
        Some(k) => {
            cmd.env("KAN_IDENTITY_FILE", k);
        }
        None => {
            cmd.env_remove("KAN_IDENTITY_FILE");
        }
    }
    let out = cmd.output().expect("failed to run kan binary");
    Run {
        stdout: String::from_utf8_lossy(&out.stdout).trim().to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ok: out.status.success(),
    }
}

fn git(dir: &std::path::Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(dir)
        .status()
        .expect("failed to run git");
    assert!(status.success(), "git {args:?} failed");
}

fn repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-q"]);
    git(
        dir.path(),
        &[
            "-c",
            "user.email=kan-test@example.com",
            "-c",
            "user.name=kan-test",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "init",
        ],
    );
    dir
}

/// A workspace whose `.claims/` holds an **own-authored** record that its log
/// does not have — a restored clone, or a workspace whose log was rebuilt.
///
/// Built by publishing, committing, then deleting `.kan/` while keeping the
/// key, which is the state a `kan restore` exists to resolve.
fn own_claims_not_in_log() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = repo();
    let key = dir.path().join("key");
    let run = kan(
        dir.path(),
        Some(&key),
        &["observe", "a claim of mine", "--subject", "bug-1"],
    );
    assert!(run.ok, "setup write failed: {}", run.stderr);
    let run = kan(dir.path(), Some(&key), &["publish", "bug-1"]);
    assert!(run.ok, "setup publish failed: {}", run.stderr);
    git(dir.path(), &["add", "-A"]);
    git(
        dir.path(),
        &[
            "-c",
            "user.email=kan-test@example.com",
            "-c",
            "user.name=kan-test",
            "commit",
            "-qm",
            "publish",
        ],
    );
    std::fs::remove_dir_all(dir.path().join(".kan")).unwrap();
    (dir, key)
}

/// B2: one command must not return two different answers over identical
/// bytes, depending on which code path last touched a *disposable cache*.
///
/// The read path decided own-vs-foreign by log membership and the write path
/// by `author.did == mine`, so they projected different row sets — and both
/// recorded the same index fingerprint, so neither could invalidate the
/// other's work. `kan show` returned 1 live claim or 0 depending on whether a
/// read or a write had last rebuilt the index, and deleting
/// `.kan/index.sqlite` — a file the code calls disposable derived data —
/// changed the answer.
#[test]
fn a_read_and_a_write_project_the_same_claims() {
    let (dir, key) = own_claims_not_in_log();
    let count = |label: &str| -> usize {
        let run = kan(dir.path(), Some(&key), &["show", "bug-1", "--json"]);
        assert!(run.ok, "{label}: show failed: {}", run.stderr);
        let v: serde_json::Value = serde_json::from_str(&run.stdout).unwrap();
        v["claims"].as_array().unwrap().len()
    };

    // One write first, so the log has an author and `Local` is non-empty
    // throughout. Without it the first read legitimately returns 0 -- an
    // empty log trusts nobody -- and the comparison would be measuring the
    // trust base changing rather than the two paths disagreeing.
    let run = kan(dir.path(), Some(&key), &["mark", "seed", "open"]);
    assert!(run.ok, "seed write failed: {}", run.stderr);

    // A read rebuilds the projection first.
    std::fs::remove_file(dir.path().join(".kan/index.sqlite")).unwrap();
    let after_read = count("after a read-open");

    // Then a write rebuilds it by the other path.
    let run = kan(dir.path(), Some(&key), &["mark", "unrelated", "open"]);
    assert!(run.ok, "write failed: {}", run.stderr);
    let after_write = count("after a write-open");

    // Then the projection is discarded entirely and rebuilt from scratch.
    std::fs::remove_file(dir.path().join(".kan/index.sqlite")).unwrap();
    let after_discard = count("after discarding the index");

    assert_eq!(
        (after_read, after_write),
        (after_write, after_discard),
        "`kan show bug-1` returned {after_read}, then {after_write}, then \
         {after_discard} live claims over identical on-disk bytes -- the read and write \
         paths project different row sets while recording the same freshness key, so \
         neither can invalidate the other"
    );
}

/// B3: `restore` must refuse before bringing a workspace into existence.
///
/// It resolved (and so minted and persisted) an identity, then reported that
/// nothing in the tree was signed by "this repo's identity" — about an
/// identity it had invented one line earlier and left on disk. That is the
/// exact failure `restore`'s own doc describes, reached by the code meant to
/// avoid it, and it broke REQ-3/AC-9 on the path where a wrongly-persisted
/// identity is most expensive.
#[test]
fn a_refused_restore_brings_no_workspace_into_existence() {
    let dir = repo();
    // A published tree signed by somebody else entirely.
    let stranger = repo();
    let stranger_key = stranger.path().join("key");
    assert!(
        kan(
            stranger.path(),
            Some(&stranger_key),
            &["observe", "not yours", "--subject", "theirs"]
        )
        .ok
    );
    assert!(kan(stranger.path(), Some(&stranger_key), &["publish", "theirs"]).ok);
    let claims = dir.path().join(".claims");
    std::fs::create_dir_all(&claims).unwrap();
    for entry in std::fs::read_dir(stranger.path().join(".claims")).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), claims.join(entry.file_name())).unwrap();
    }

    let key = dir.path().join("key-that-does-not-exist");
    let run = kan(dir.path(), Some(&key), &["restore"]);

    assert!(!run.ok, "restore should have refused: {}", run.stdout);
    assert!(
        !key.exists(),
        "a refused restore minted a signing key -- and then judged the tree against it"
    );
    // Holds in THIS configuration -- the env key is absent, so nothing gets
    // as far as opening a store. With `KAN_IDENTITY_FILE` naming a key that
    // exists, a refused restore still creates an empty `.kan/`; that is
    // pre-existing and about store creation rather than identity
    // persistence, which is what REQ-3/AC-9 is about. Scoped here rather
    // than asserted as a general property it does not have.
    assert!(
        !dir.path().join(".kan").exists(),
        "a refused restore created a workspace, with no key file in play"
    );
}

/// B3, second half: the refusal must name the authors actually in the tree,
/// and must not advertise a remedy that cannot work.
///
/// The generic no-identity message is written for `--trust me` — it talks
/// about naming an author with `--trust`, about what `me` means, and about
/// reading never creating an identity, none of which apply to a write verb
/// with no `--trust` flag. And `kan identity adopt`, the remedy it named, was
/// a **no-op** here: `existing_identity` checked `KAN_IDENTITY_FILE` first and
/// exclusively, so it never looked at the `.kan/identity` adopt had just
/// written, and `restore` refused identically forever.
#[test]
fn a_lost_key_restore_names_the_tree_and_its_remedy_works() {
    let dir = repo();
    let key = dir.path().join("key");
    assert!(
        kan(
            dir.path(),
            Some(&key),
            &["observe", "mine to restore", "--subject", "bug-1"]
        )
        .ok
    );
    assert!(kan(dir.path(), Some(&key), &["publish", "bug-1"]).ok);
    let did = kan(dir.path(), Some(&key), &["identity", "did"]).stdout;
    // The key becomes unreachable: `.kan/` gone, and the env var points at a
    // path that no longer exists.
    std::fs::remove_dir_all(dir.path().join(".kan")).unwrap();
    let missing = dir.path().join("gone");

    let refused = kan(dir.path(), Some(&missing), &["restore"]);
    assert!(!refused.ok, "expected a refusal: {}", refused.stdout);
    assert!(
        refused.stderr.contains(&did),
        "the refusal must name the authors whose claims are sitting in the tree -- it is \
         the one fact a lost-key operator needs: {}",
        refused.stderr
    );
    // Restore's own refusal, not the one written for `--trust me`. Checked
    // by a phrase only restore's says, rather than by the ABSENCE of
    // `--trust`: absence is satisfied by any number of wrong messages, and
    // it is the presence of restore's own wording that is the property.
    assert!(
        refused
            .stderr
            .contains("cannot tell which of these claims are yours"),
        "expected `restore`'s own refusal, which names the tree it read: {}",
        refused.stderr
    );

    // The remedy it advertises has to actually work.
    let adopted = kan(
        dir.path(),
        Some(&missing),
        &["identity", "adopt", "--key", key.to_str().unwrap()],
    );
    assert!(adopted.ok, "adopt failed: {}", adopted.stderr);
    let after = kan(dir.path(), Some(&missing), &["restore"]);
    assert!(
        after.ok,
        "`restore` gave the same refusal after the adopt it told the operator to run -- \
         the advertised remedy is a no-op: {}",
        after.stderr
    );

    // ...and it must have restored as the identity it named, not merely
    // exited 0.
    //
    // Asserting `after.ok` alone is what let the second version of this
    // defect through: the read side learned to see `.kan/identity` while the
    // sign side went on minting at the absent KAN_IDENTITY_FILE path, so
    // `restore` succeeded under a brand-new DID, left a private key at the
    // path the operator had lost, and split the log across two authors. Exit
    // 0 was true and meaningless.
    assert_eq!(
        kan(dir.path(), Some(&missing), &["identity", "did"]).stdout,
        did,
        "restore succeeded under a different identity than the one it adopted"
    );
    assert!(
        !missing.exists(),
        "a second signing key was minted at the KAN_IDENTITY_FILE path"
    );
    let shown = kan(
        dir.path(),
        Some(&missing),
        &["show", "bug-1", "--trust", "me"],
    );
    assert!(
        shown.stdout.contains("mine to restore"),
        "the restored claims are not visible as this workspace's own: {}",
        shown.stdout
    );
}

/// N2: #144's subject name must be refused on **both** of the two subjects
/// that `same` and `relate` name.
///
/// `append` validates only the subject the claim is about, so the second went
/// unchecked on the CLI — and the merge class then *displays* under the bad
/// name, so the good subject disappears from `status` entirely. MCP had
/// validated both all along, making it a property of one surface out of two.
#[test]
fn both_subjects_of_a_two_subject_verb_are_validated() {
    for verb in [
        vec!["same", "good", "bad\nname"],
        vec!["relate", "good", "blocks", "bad\nname"],
    ] {
        let dir = repo();
        let key = dir.path().join("key");
        assert!(
            kan(
                dir.path(),
                Some(&key),
                &["observe", "seed", "--subject", "good"]
            )
            .ok
        );

        let run = kan(dir.path(), Some(&key), &verb);
        assert!(
            !run.ok,
            "`kan {}` accepted a control character in its second subject",
            verb.join(" ")
        );

        let status = kan(dir.path(), Some(&key), &["status", "--json"]);
        assert!(status.ok);
        assert!(
            !status.stdout.contains("bad\\nname"),
            "the bad name reached the log via `{}` -- and a merge class displays under it, \
             so `good` vanishes from status: {}",
            verb.join(" "),
            status.stdout
        );
    }
}

/// N5: an error must not assert the log is empty when it is not.
///
/// `--trust me` with no reachable key said "nothing has been written here" in
/// a workspace whose log is full. It fires when no KEY is reachable, which is
/// a different fact. Saying "there is nothing here" when there is plenty is
/// the complete-looking wrong answer this project keeps meeting — shipped in
/// a message written during the milestone about ending it.
#[test]
fn a_missing_key_does_not_claim_the_log_is_empty() {
    let dir = repo();
    let key = dir.path().join("key");
    assert!(
        kan(
            dir.path(),
            Some(&key),
            &["observe", "plenty has been written here", "--subject", "s"]
        )
        .ok
    );
    let missing = dir.path().join("not-a-key");

    // The claim is plainly readable without any identity...
    let readable = kan(dir.path(), Some(&missing), &["show", "s"]);
    assert!(readable.ok, "the default read should not need a key");
    assert!(
        readable.stdout.contains("plenty has been written here"),
        "precondition: the log is readable and non-empty: {}",
        readable.stdout
    );

    // ...so an error about the missing key must not deny it.
    let refused = kan(dir.path(), Some(&missing), &["show", "s", "--trust", "me"]);
    assert!(!refused.ok, "expected `--trust me` to fail with no key");
    assert!(
        !refused.stderr.contains("nothing has been written here"),
        "the error contradicts the workspace it is describing: {}",
        refused.stderr
    );
}

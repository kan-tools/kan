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
    {
        std::fs::create_dir_all(key.parent().unwrap()).unwrap();
        kan::sign::Identity::generate().save(&key).unwrap();
    }
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
    {
        std::fs::create_dir_all(stranger_key.parent().unwrap()).unwrap();
        kan::sign::Identity::generate().save(&stranger_key).unwrap();
    }
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
    {
        std::fs::create_dir_all(key.parent().unwrap()).unwrap();
        kan::sign::Identity::generate().save(&key).unwrap();
    }
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

    // No selection at all: the operator has LOST the key, which is the state
    // `restore` exists for. Pointing KAN_IDENTITY_FILE at a stale path models
    // a different failure since REQ-2 -- the selection is refused before
    // restore can enumerate the tree, which is correct but is not this test's
    // subject.
    let refused = kan(dir.path(), None, &["restore"]);
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

    // The remedy it advertises has to actually work -- and a stale
    // KAN_IDENTITY_FILE must be reported rather than worked around.
    let adopted = kan(
        dir.path(),
        Some(&missing),
        &["identity", "adopt", "--key", key.to_str().unwrap()],
    );
    assert!(adopted.ok, "adopt failed: {}", adopted.stderr);

    // Still pointing at a path that does not exist: REFUSED, naming the
    // guard's evidence. Substituting `.kan/identity` here instead would sign
    // as whatever the workspace happens to hold, which fabricates authorship
    // when the missing path is a declared role's key.
    let still_stale = kan(dir.path(), Some(&missing), &["restore"]);
    assert!(
        !still_stale.ok,
        "a stale KAN_IDENTITY_FILE was silently substituted rather than reported: {}",
        still_stale.stdout
    );
    // REQ-2 changed WHICH refusal this is, deliberately, and the new one is
    // a better answer to the question the operator actually asked. Before, a
    // stale selection fell through to restore's lost-key refusal, which
    // listed the tree's authors -- useful, but it answered "who wrote this?"
    // when the operator's problem was "the key you named is not there".
    // Now the selection is reported as what it is. The property the test
    // defends is unchanged: a stale KAN_IDENTITY_FILE is REPORTED, never
    // silently substituted with whatever the workspace happens to hold.
    assert!(
        still_stale.stderr.contains("does not exist"),
        "expected the stale selection to be named: {}",
        still_stale.stderr
    );
    assert!(
        !still_stale.stderr.contains(&did),
        "a stale selection should be reported on its own terms, not answered with the \
         workspace's identity: {}",
        still_stale.stderr
    );

    // With the variable out of the way, the adopted key is this workspace's
    // and the restore lands under it.
    let after = kan(dir.path(), None, &["restore"]);
    assert!(
        after.ok,
        "`restore` still refused after the adopt it told the operator to run -- the \
         advertised remedy is a no-op: {}",
        after.stderr
    );
    assert_eq!(
        kan(dir.path(), None, &["identity", "did"]).stdout,
        did,
        "restore succeeded under a different identity than the one it adopted"
    );
    assert!(
        !missing.exists(),
        "a second signing key was minted at the KAN_IDENTITY_FILE path"
    );
    let shown = kan(dir.path(), None, &["show", "bug-1", "--trust", "me"]);
    assert!(
        shown.stdout.contains("mine to restore"),
        "the restored claims are not visible as this workspace's own: {}",
        shown.stdout
    );
}

/// B1 from the fourth review: a claim must never be signed by an identity the
/// caller did not ask for.
///
/// A previous round made an absent `KAN_IDENTITY_FILE` fall back to
/// `.kan/identity`, calling it symmetry with the read side. It fabricated
/// authorship — writing as a declared role whose key file had gone missing
/// silently signed as the *human*, at exit 0, with only an stderr line that
/// `day` and MCP callers never surface. `.kan/roles` records that path as the
/// role's key; the resolver never reads it.
///
/// A loud refusal is the only safe answer: the caller named a key, and that
/// key is not there.
#[test]
fn a_missing_role_key_never_signs_as_somebody_else() {
    let dir = repo();
    // The human's key must live at `.kan/identity`, because that is the file
    // the substitution reached for. Putting it anywhere else makes the
    // substitution's precondition false, so the write gets refused by an
    // unrelated arm of the guard and the test passes without exercising the
    // defect at all -- which is what the first version of this test did.
    let human = dir.path().join(".kan/identity");
    std::fs::create_dir_all(dir.path().join(".kan")).unwrap();
    {
        std::fs::create_dir_all(human.parent().unwrap()).unwrap();
        kan::sign::Identity::generate().save(&human).unwrap();
    }
    assert!(
        kan(
            dir.path(),
            Some(&human),
            &["observe", "the human's note", "--subject", "bug-7"]
        )
        .ok
    );
    assert!(
        human.exists(),
        "precondition: the human's key must be at .kan/identity, where the substitution \
         looked"
    );
    let human_did = kan(dir.path(), Some(&human), &["identity", "did"]).stdout;

    let role_key = dir.path().join("roles.d-prover");
    {
        std::fs::create_dir_all(role_key.parent().unwrap()).unwrap();
        kan::sign::Identity::generate().save(&role_key).unwrap();
    }
    let added = kan(
        dir.path(),
        Some(&human),
        &[
            "identity",
            "role",
            "add",
            "prover",
            "--key",
            role_key.to_str().unwrap(),
        ],
    );
    assert!(added.ok, "role add failed: {}", added.stderr);
    let role_did = kan(dir.path(), Some(&role_key), &["identity", "did"]).stdout;
    assert_ne!(human_did, role_did, "precondition: two distinct identities");

    // The role's key goes missing — lost, cleaned up, not yet provisioned.
    std::fs::remove_file(&role_key).unwrap();

    let run = kan(
        dir.path(),
        Some(&role_key),
        &["observe", "written as the role", "--subject", "bug-8"],
    );
    assert!(
        !run.ok,
        "writing with a missing key file succeeded -- and therefore signed as somebody \
         else: {}",
        run.stdout
    );

    // Nothing was written at all, so nothing can carry the wrong author.
    let shown = kan(dir.path(), Some(&human), &["show", "bug-8"]);
    assert!(
        !shown.stdout.contains("written as the role"),
        "the claim was recorded despite the refusal, under {human_did}: {}",
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
        {
            std::fs::create_dir_all(key.parent().unwrap()).unwrap();
            kan::sign::Identity::generate().save(&key).unwrap();
        }
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
    {
        std::fs::create_dir_all(key.parent().unwrap()).unwrap();
        kan::sign::Identity::generate().save(&key).unwrap();
    }
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

/// B3 from the fourth review: the second-identity guard must count a root
/// **seed** as an identity, in the layout a real first run actually leaves.
///
/// The guard weighed only `log/repo.car`, then only `seed`. A seed-rooted
/// workspace on macOS has `seed-id` and no `seed` — the default first-run
/// shape — and `Seed::load` returns `None` under `KAN_NO_KEYCHAIN`, so
/// `seed-id` is the *only* on-disk trace that the workspace is seed-rooted at
/// all. That left the guard blind in precisely the empty-log case it had just
/// been widened for: with the log cleared and the claims in `.claims/`,
/// minting sailed straight past it and shadowed the original identity
/// permanently.
#[test]
fn a_seed_rooted_workspace_is_not_re_minted_when_its_log_is_cleared() {
    let dir = repo();
    let kan_dir = dir.path().join(".kan");

    // A seed-rooted workspace: no key file, a seed recorded, claims written.
    assert!(
        kan(
            dir.path(),
            None,
            &["observe", "seeded work", "--subject", "bug-1"]
        )
        .ok
    );
    assert!(
        kan_dir.join("seed").exists() || kan_dir.join("seed-id").exists(),
        "precondition: the workspace should be seed-rooted"
    );
    assert!(
        !kan_dir.join("identity").exists(),
        "precondition: seed-rooted workspaces hold no plaintext key file"
    );
    let original = kan(dir.path(), None, &["identity", "did"]).stdout;

    // `seed-id` only — the shape a keychain-backed first run leaves, and the
    // one the guard could not see.
    let _ = std::fs::remove_file(kan_dir.join("seed"));
    std::fs::write(kan_dir.join("seed-id"), "some-account-id").unwrap();

    // The restore precondition: the log is gone, the claims are elsewhere.
    for dead in ["log", "overlay", "index.sqlite"] {
        let p = kan_dir.join(dead);
        let _ = std::fs::remove_dir_all(&p);
        let _ = std::fs::remove_file(&p);
    }

    let run = kan(
        dir.path(),
        None,
        &["observe", "after the log went", "--subject", "bug-2"],
    );
    assert!(
        !run.ok,
        "a seed-rooted workspace with an empty log was re-minted: {}\n{}",
        run.stdout, run.stderr
    );
    assert!(
        !kan_dir.join("seed").exists(),
        "minting wrote a second root seed beside the recorded one -- the original \
         identity is now permanently shadowed, since Seed::load prefers the file"
    );
    // Deliberately NOT `assert!(!after.ok || after.stdout == original)` --
    // the assertion above already establishes the guard fires, so that
    // disjunction is satisfied by the failure and can never fail. It is the
    // weaker relative of the `assert!(x || true)` clippy caught in this file.
    //
    // The positive form: the seed is still the only one, so nothing has been
    // shadowed. `Seed::load` prefers the file, so a second seed beside the
    // recorded one is what would make the original unrecoverable.
    assert!(
        !kan_dir.join("seed").exists(),
        "minting wrote a second root seed beside the recorded one"
    );
    let _ = original;
}

/// B4 from the fourth review: reads and writes must resolve the **same**
/// identity in a workspace holding both a seed and a key file.
///
/// `sign::existing_identity` (reads: `--trust me`, `--trust roles`, `restore`)
/// checked the key file first; `load_or_create_for_workspace` (writes) checks
/// the seed first. Wherever both existed the two disagreed, and the symptom
/// was the one this milestone exists to end: `kan identity did` naming one
/// identity while `--trust me` folded under another and reported "no claims"
/// against a full log.
///
/// Two resolvers with inverted precedence was the structural cause of every
/// identity defect the v0.11 review rounds found. This pins that they agree.
#[test]
fn reads_and_writes_resolve_the_same_identity() {
    let dir = repo();
    let kan_dir = dir.path().join(".kan");

    assert!(
        kan(
            dir.path(),
            None,
            &["observe", "seed rooted note", "--subject", "bug-1"]
        )
        .ok
    );
    let writing = kan(dir.path(), None, &["identity", "did"]).stdout;
    assert!(
        !writing.is_empty(),
        "precondition: the workspace has an identity"
    );

    // Give the workspace a key file as well as its seed -- the state where
    // the two resolvers diverged. The key is minted in a SEPARATE repo so
    // this one's guard is not involved, then dropped in beside the seed.
    let elsewhere = repo();
    let spare = elsewhere.path().join("spare-key");
    {
        std::fs::create_dir_all(spare.parent().unwrap()).unwrap();
        kan::sign::Identity::generate().save(&spare).unwrap();
    }
    assert!(
        kan(elsewhere.path(), Some(&spare), &["identity", "did"]).ok,
        "could not mint a spare key"
    );
    std::fs::copy(&spare, kan_dir.join("identity")).unwrap();
    assert!(
        kan_dir.join("identity").exists()
            && (kan_dir.join("seed").exists() || kan_dir.join("seed-id").exists()),
        "precondition: the workspace must hold BOTH a key file and a seed"
    );

    // The read side must fold under the same identity the write side signs
    // with, or it reports somebody else's log as empty.
    let shown = kan(dir.path(), None, &["show", "bug-1", "--trust", "me"]);
    assert!(shown.ok, "`--trust me` failed: {}", shown.stderr);
    assert!(
        shown.stdout.contains("seed rooted note"),
        "the read side resolved a different identity than the write side: `kan identity \
         did` says {writing}, and `--trust me` cannot see that identity's own claim.\n{}",
        shown.stdout
    );
}

/// B2 from the fifth review: refusing a missing role key must not depend on
/// the guard happening to find other evidence.
///
/// The previous round said "the caller named a key and that key is not there;
/// refusing is the only safe answer" — but refusal ran through
/// `refuse_second_identity`, which needs evidence. In the documented CI /
/// agent / `day` configuration (ADR-42) the primary identity lives *outside*
/// `.kan/`, so with an empty log there is no evidence at all: kan minted a
/// fresh key at the missing role's path and signed with it.
///
/// The resulting claim carries a DID that appears in no `.kan/roles` line, so
/// `--trust roles` — "everything this workspace wrote" — reports nothing on
/// the subject just written. Same class as the substitution it replaced,
/// reached by minting instead.
#[test]
fn a_missing_role_key_is_refused_even_with_no_other_evidence() {
    let dir = repo();
    // The primary lives outside `.kan/`, which is what leaves no evidence.
    let primary = dir.path().join("primary-key");
    {
        std::fs::create_dir_all(primary.parent().unwrap()).unwrap();
        kan::sign::Identity::generate().save(&primary).unwrap();
    }
    assert!(kan(dir.path(), Some(&primary), &["identity", "did"]).ok);

    let role_key = dir.path().join("prover-key");
    {
        std::fs::create_dir_all(role_key.parent().unwrap()).unwrap();
        kan::sign::Identity::generate().save(&role_key).unwrap();
    }
    let added = kan(
        dir.path(),
        Some(&primary),
        &[
            "identity",
            "role",
            "add",
            "prover",
            "--key",
            role_key.to_str().unwrap(),
        ],
    );
    assert!(added.ok, "role add failed: {}", added.stderr);
    let role_did = kan(dir.path(), Some(&role_key), &["identity", "did"]).stdout;

    // The role's key goes missing, and the log is empty -- no claims, so the
    // guard has nothing to weigh.
    std::fs::remove_file(&role_key).unwrap();
    assert!(
        !dir.path().join(".kan/log/repo.car").exists()
            || std::fs::metadata(dir.path().join(".kan/log/repo.car"))
                .map(|m| m.len() == 0)
                .unwrap_or(true),
        "precondition: the log must be empty, so the guard has no evidence"
    );

    let run = kan(
        dir.path(),
        Some(&role_key),
        &["observe", "as the role", "--subject", "bug-2"],
    );
    assert!(
        !run.ok,
        "a missing declared-role key was minted rather than refused: {}",
        run.stdout
    );
    assert!(
        !role_key.exists(),
        "a fresh key was minted at the declared role's path -- claims signed with it \
         appear under no `.kan/roles` line, so `--trust roles` reports them as nothing"
    );
    assert!(
        run.stderr.contains("prover"),
        "the refusal should name the role whose key is missing: {}",
        run.stderr
    );
    let _ = role_did;
}

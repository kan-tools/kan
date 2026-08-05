//! #144 and #141 — two ways kan accepted something it should have refused,
//! both reported from real use rather than found by a test.
//!
//! They share a shape worth naming: kan did the work first and discovered the
//! problem afterwards, so the failure arrived after side effects that implied
//! success. #144 recorded a claim under a subject name that could not have
//! been meant; #141 minted an identity and created `.kan/` before failing on
//! a git precondition it could have checked first.

use std::process::Command;

fn kan(dir: &std::path::Path, key: &std::path::Path, args: &[&str]) -> (String, String, bool) {
    let out = Command::new(env!("CARGO_BIN_EXE_kan"))
        .args(args)
        .current_dir(dir)
        .env("KAN_IDENTITY_FILE", key)
        .env("KAN_NO_KEYCHAIN", "1")
        .output()
        .expect("failed to run kan binary");
    (
        String::from_utf8_lossy(&out.stdout).trim().to_string(),
        String::from_utf8_lossy(&out.stderr).trim().to_string(),
        out.status.success(),
    )
}

fn git_repo(with_commit: bool) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        Command::new("git")
            .args(args)
            .current_dir(dir.path())
            .status()
            .expect("failed to run git");
    };
    run(&["init", "-q"]);
    if with_commit {
        run(&[
            "-c",
            "user.email=kan-test@example.com",
            "-c",
            "user.name=kan-test",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "init",
        ]);
    }
    dir
}

/// #144's actual cause. The report was "`status --json` emits a phantom
/// subject whose name is every other subject name newline-joined" — there is
/// no phantom and no JSON bug. It is a real claim, written by a shell
/// expansion that produced a whole listing where a name was wanted, which kan
/// accepted verbatim.
#[test]
fn a_subject_name_with_a_newline_is_refused() {
    let dir = git_repo(true);
    let key = dir.path().join("key");

    let (_, err, ok) = kan(
        dir.path(),
        &key,
        &["observe", "oops", "--subject", "alpha\nbeta"],
    );

    assert!(!ok, "kan accepted a multi-line subject name");
    assert!(
        err.contains("control character") && err.contains("newline"),
        "the refusal should name what was wrong: {err}"
    );
    // It should also name the cause, because the operator did not type this.
    assert!(
        err.contains("shell expansion"),
        "the refusal should name the likely cause: {err}"
    );
}

/// The guard has to be narrow or it breaks this repo's own subjects. Slashes,
/// spaces and unicode are all in active use (`telos/raw-data-and-projections`,
/// `schema/design-doc`).
#[test]
fn ordinary_subject_names_are_untouched() {
    let dir = git_repo(true);
    let key = dir.path().join("key");

    for name in [
        "telos/raw-data-and-projections",
        "schema/design-doc",
        "a name with spaces",
        "unicode-é-ok",
        "v0.9.2-beta.1",
    ] {
        let (_, err, ok) = kan(dir.path(), &key, &["observe", "fine", "--subject", name]);
        assert!(ok, "rejected a legitimate subject name {name:?}: {err}");
    }
}

// Non-destruction outranks this guard: a log that already contains such a
// subject — and at least one real one does — must still read. That is not
// tested here, deliberately. The only honest way to build the state is a kan
// that predates the guard, and a test that writes a *legitimate* subject and
// then reads it back would assert nothing about the case it claims to cover.
// The property is instead structural and checkable by inspection:
// `validate_subject_name` is called from `append` alone, so no read path can
// reach it.

/// #141: a repo with no commits reported git's own `ambiguous argument
/// 'HEAD'` prose, which names neither kan's requirement nor the fix.
///
/// **Probed with a write since v0.11.** The requirement is a *write-time*
/// one — kan anchors every claim to the repo's root commit — and the anchor
/// is no longer resolved on reads, which is where 28.2ms of a ~42ms
/// invocation went (`.design/identity-surface.md` RQ-5). A read of a
/// commitless repo now succeeds and reports nothing, which is the honest
/// answer: there are no claims, and nothing about reading needs a root
/// commit. #141's error is unchanged where it applies.
#[test]
fn a_repo_with_no_commits_says_what_it_needs() {
    let dir = git_repo(false);
    let key = dir.path().join("key");

    let (_, err, ok) = kan(dir.path(), &key, &["observe", "x", "--subject", "s"]);

    assert!(!ok, "a write succeeded in a repo with no commits");
    assert!(
        !err.contains("rev-list") && !err.contains("ambiguous argument"),
        "git's raw error is still leaking: {err}"
    );
    assert!(
        err.contains("no commits") && err.contains("git commit"),
        "the error should name the requirement and the fix: {err}"
    );
}

/// The other half of #141, and the part that made the error misleading: the
/// keychain notice printed *first*, so an identity was minted and `.kan/`
/// created before the failure. "Nothing was written" has to be true.
#[test]
fn a_failed_open_in_a_commitless_repo_writes_nothing() {
    let dir = git_repo(false);
    let key = dir.path().join("key");

    let (_, _, ok) = kan(dir.path(), &key, &["observe", "x", "--subject", "s"]);
    assert!(!ok);

    assert!(
        !dir.path().join(".kan").exists(),
        ".kan/ was created despite the command failing"
    );
    assert!(
        !key.exists(),
        "a signing key was minted despite the command failing"
    );
}

/// AC-3, and the general form of what #141 fixed in one case: a **read**
/// creates nothing at all.
///
/// #141 stopped one failing path from leaving a workspace behind. v0.11
/// stops every read from vivifying one (#149), which is why this asserts the
/// whole `.kan/` directory is absent rather than just the key: no directory,
/// no key, no `seed-id`, no index file. A repo you have only ever *read* is
/// indistinguishable afterwards from one kan has never seen.
#[test]
fn a_read_creates_no_workspace() {
    for has_commits in [true, false] {
        let dir = git_repo(has_commits);
        let key = dir.path().join("key");

        let (out, err, ok) = kan(dir.path(), &key, &["status"]);

        assert!(ok, "a read failed (commits: {has_commits}): {err}");
        assert!(
            out.contains("no subjects"),
            "expected an empty-workspace report (commits: {has_commits}): {out}"
        );
        assert!(
            !dir.path().join(".kan").exists(),
            "a read created .kan/ (commits: {has_commits})"
        );
        assert!(
            !key.exists(),
            "a read minted a signing key (commits: {has_commits})"
        );
    }
}

/// v0.11 REQ-3 / AC-9: a write refused for a bad subject name leaves no
/// newly-persisted key, no `seed-id`, no `identity-id` — and no `.kan/`.
///
/// #144's check lived inside `append`, which runs *after* `Workspace::open`.
/// So `kan observe x --subject $'bad\nname'` in a fresh repo minted a signing
/// key and created a workspace on its way to refusing, for a command that
/// wrote nothing. Same ordering defect ADR-82 names — validate before acting
/// — reached by a third route after #141 and #146.
#[test]
fn a_write_refused_for_its_subject_name_mints_nothing() {
    let dir = git_repo(true);
    let key = dir.path().join("key");

    let (_, err, ok) = kan(
        dir.path(),
        &key,
        &["observe", "x", "--subject", "bad\nname"],
    );

    assert!(!ok, "an invalid subject name was accepted");
    assert!(
        err.contains("control character"),
        "the refusal should say what was wrong: {err}"
    );
    assert!(
        !key.exists(),
        "a refused write minted a signing key -- REQ-3: a minted identity is persisted \
         only after the write it was minted for has succeeded"
    );
    assert!(
        !dir.path().join(".kan").exists(),
        "a refused write created a workspace: {:?}",
        std::fs::read_dir(dir.path().join(".kan"))
            .map(|d| d.flatten().map(|e| e.file_name()).collect::<Vec<_>>())
            .unwrap_or_default()
    );

    // The check has to stay in `append` as well, since that is the single
    // choke point every write verb reaches -- this is an earlier refusal,
    // never the only one. A legitimate write still works afterwards.
    let (_, err, ok) = kan(dir.path(), &key, &["observe", "real", "--subject", "fine"]);
    assert!(
        ok,
        "a legitimate write was broken by the early check: {err}"
    );
}

/// REQ-3 / AC-9 in full: **no** refused write leaves an identity behind,
/// whatever refused it.
///
/// The earlier version of this pinned one cause (a bad subject name) by
/// hoisting one check. That is a check-shaped fix to a state-shaped problem:
/// every *other* way a write can fail after `Workspace::open` still minted,
/// and the list of those is not one anybody should have to keep complete.
///
/// v0.11 moves the state change instead. `Workspace::open` resolves no
/// identity; `commit_identity` runs immediately before the append, once every
/// precondition has passed. So the property holds for causes nobody
/// enumerated, which is the only version of it worth having.
///
/// **Persist before the append, not after**, deliberately departing from
/// REQ-3's wording ("only after the write ... has succeeded"). Failing
/// between persist and append leaves an identity with an empty log — exactly
/// what `kan identity did` produces. Failing the other way round leaves a
/// claim signed by a key nothing on disk holds, which the ADR-77 guard then
/// refuses to open: log unreadable, key unrecoverable.
#[test]
fn no_refused_write_leaves_an_identity_behind() {
    // (label, repo has commits, args)
    let cases: &[(&str, bool, &[&str])] = &[
        (
            "a control character in the subject",
            true,
            &["observe", "x", "--subject", "bad\nname"],
        ),
        (
            "a repo with no commits",
            false,
            &["observe", "x", "--subject", "s"],
        ),
        (
            "an unparseable --cites CID",
            true,
            &["observe", "x", "--subject", "s", "--cites", "not-a-cid"],
        ),
    ];

    for (label, has_commits, args) in cases {
        let dir = git_repo(*has_commits);
        let key = dir.path().join("key");

        let (_, err, ok) = kan(dir.path(), &key, args);

        assert!(!ok, "{label}: the write was expected to be refused");
        assert!(
            !key.exists(),
            "{label}: a refused write minted a signing key ({err})"
        );
        assert!(
            !dir.path().join(".kan").exists(),
            "{label}: a refused write created a workspace ({err})"
        );
    }

    // The negative control, and the one that makes the rest mean something:
    // a write that is NOT refused still brings the workspace into existence.
    let dir = git_repo(true);
    let key = dir.path().join("key");
    let (_, err, ok) = kan(dir.path(), &key, &["observe", "real", "--subject", "s"]);
    assert!(ok, "a legitimate write failed: {err}");
    assert!(
        key.exists(),
        "a successful write did not persist an identity"
    );
    assert!(
        dir.path().join(".kan/log").exists(),
        "a successful write did not create the log"
    );
}

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

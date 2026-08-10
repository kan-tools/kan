//! `.design/role-declarations.md` — role declarations as claims, on the
//! surfaces the change-ledger golden structurally cannot reach.
//!
//! **Why these are not in `tests/golden_trust_and_identity.rs`.** AC-11 named
//! that fixture as the witness for `kan identity role list`'s output changing
//! shape. It cannot be: its workspace is driven entirely by
//! `KAN_IDENTITY_FILE` and has no identity of its own, so under REQ-7 it can
//! never hold a declared role, and the golden can only ever freeze the *empty*
//! listing. The golden still earns its place — it froze REQ-7's refusal, and
//! it is what found the hole in that guard — but the populated listing needs a
//! workspace the fixture is not.

use std::collections::BTreeSet;
use std::process::Command;

struct Run {
    stdout: String,
    stderr: String,
    ok: bool,
}

fn kan_as(dir: &std::path::Path, key: Option<&std::path::Path>, args: &[&str]) -> Run {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kan"));
    cmd.args(args).current_dir(dir);
    match key {
        Some(k) => {
            cmd.env("KAN_IDENTITY_FILE", k);
        }
        None => {
            cmd.env_remove("KAN_IDENTITY_FILE");
        }
    }
    let output = cmd.output().expect("failed to run kan binary");
    Run {
        stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ok: output.status.success(),
    }
}

fn git_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let status = Command::new("git")
            .args(args)
            .current_dir(dir.path())
            .status()
            .expect("failed to run git");
        assert!(status.success(), "git {args:?} failed");
    };
    run(&["init", "-q"]);
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
    dir
}

/// A workspace with its own identity and one claim — the state in which a role
/// can legitimately be declared.
fn workspace_with_own_identity() -> tempfile::TempDir {
    let dir = git_repo();
    let run = kan_as(
        dir.path(),
        None,
        &["observe", "shared", "the primary's claim"],
    );
    assert!(run.ok, "primary write failed: {}", run.stderr);
    dir
}

/// How many claims the log holds — the negative controls below assert this is
/// *unchanged* by a refusal, which is what distinguishes "refused" from
/// "wrote something and then complained".
fn claim_count(dir: &std::path::Path) -> usize {
    let run = kan_as(dir, None, &["show", "--all", "--json"]);
    assert!(run.ok, "show --all failed: {}", run.stderr);
    let view: serde_json::Value = serde_json::from_str(&run.stdout).unwrap();
    view["claims"].as_array().map(|c| c.len()).unwrap_or(0)
}

/// REQ-8 + AC-10: the three empty `--trust roles` frames read **differently**,
/// none of them errors, and the alias still composes.
///
/// Asserted pairwise-distinct rather than each being non-empty: an assertion
/// that every state says *something* is one a single hardcoded string would
/// pass, which is the shape of test this project keeps finding.
#[test]
fn three_empty_roles_frames_read_differently() {
    let reason_for = |dir: &std::path::Path, key: Option<&std::path::Path>| -> String {
        let run = kan_as(dir, key, &["show", "shared", "--trust", "roles", "--json"]);
        assert!(
            run.ok,
            "`--trust roles` errored instead of returning an empty frame: {}",
            run.stderr
        );
        let view: serde_json::Value = serde_json::from_str(&run.stdout).unwrap();
        assert!(
            view["trust"]["authors"].as_array().unwrap().is_empty(),
            "this case was supposed to produce an EMPTY frame: {view}"
        );
        view["trust"]["empty_reason"]
            .as_str()
            .unwrap_or_else(|| panic!("an empty frame must say which empty it is: {view}"))
            .to_string()
    };

    // (a) nothing declared.
    let nothing = workspace_with_own_identity();
    let a = reason_for(nothing.path(), None);

    // (b) declarations exist but this workspace's own identity is gone, so
    // none can be honoured. This is the LOST-KEY case, not a contrived one:
    // declare a role, then lose the secret the workspace roots in.
    //
    // "No declarations AND no identity" is deliberately NOT this state --
    // `roles::declared` answers `Nothing` there, because with nothing declared
    // that is the true and more useful answer regardless of who is asking.
    let no_identity = workspace_with_own_identity();
    let add = kan_as(
        no_identity.path(),
        None,
        &["identity", "role", "add", "reviewer"],
    );
    assert!(add.ok, "role add failed: {}", add.stderr);
    for artifact in ["seed", "identity", "seed-id", "identity-id"] {
        let p = no_identity.path().join(".kan").join(artifact);
        if p.exists() {
            std::fs::remove_file(&p).unwrap();
        }
    }
    let b = reason_for(no_identity.path(), None);

    // (c) declarations exist, but none were authored by this workspace.
    //
    // Built by REPLACING the workspace's rooting artifact by hand -- delete
    // the seed, drop a different key at `.kan/identity` -- because that is how
    // this state actually arises: someone restores the wrong key file. It is
    // deliberately NOT built with `kan identity adopt`, which since REQ-9
    // REPAIRS this state by carrying the registry across, so an adopt-built
    // (c) would silently become case (a) and this test would assert nothing.
    let foreign = workspace_with_own_identity();
    let add = kan_as(
        foreign.path(),
        None,
        &["identity", "role", "add", "reviewer"],
    );
    assert!(add.ok, "role add failed: {}", add.stderr);
    for artifact in ["seed", "seed-id", "identity-id"] {
        let p = foreign.path().join(".kan").join(artifact);
        if p.exists() {
            std::fs::remove_file(&p).unwrap();
        }
    }
    kan::sign::Identity::generate()
        .save(&foreign.path().join(".kan/identity"))
        .unwrap();
    let c = reason_for(foreign.path(), None);

    assert_ne!(
        a, b,
        "(a) nothing declared and (b) no workspace identity read identically"
    );
    assert_ne!(
        a, c,
        "(a) nothing declared and (c) only-foreign read identically"
    );
    assert_ne!(
        b, c,
        "(b) no workspace identity and (c) only-foreign read identically"
    );
}

fn did_of(dir: &std::path::Path, key: Option<&std::path::Path>) -> String {
    let run = kan_as(dir, key, &["identity", "did"]);
    assert!(run.ok, "identity did failed: {}", run.stderr);
    run.stdout
}

/// The declared role DIDs, as a set — membership, never a count.
fn declared_dids(dir: &std::path::Path) -> BTreeSet<String> {
    let run = kan_as(dir, None, &["identity", "role", "list", "--json"]);
    assert!(run.ok, "role list failed: {}", run.stderr);
    let view: serde_json::Value = serde_json::from_str(&run.stdout).unwrap();
    view["roles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["did"].as_str().unwrap().to_string())
        .collect()
}

/// REQ-9 + AC-10c: `kan identity adopt` leaves `--trust roles` naming the
/// **same author set** it named before.
#[test]
fn adopt_carries_the_role_registry_across() {
    let dir = workspace_with_own_identity();
    let add = kan_as(dir.path(), None, &["identity", "role", "add", "reviewer"]);
    assert!(add.ok, "role add failed: {}", add.stderr);
    let before = declared_dids(dir.path());
    assert_eq!(before.len(), 2, "primary + reviewer should be declared");

    // A second identity that has also written here -- adopt refuses a key that
    // authored nothing, so this is the only shape adopt accepts.
    let successor = dir.path().join("successor-key");
    kan::sign::Identity::generate().save(&successor).unwrap();
    let wrote = kan_as(
        dir.path(),
        Some(&successor),
        &["observe", "shared", "the successor's claim"],
    );
    assert!(wrote.ok, "{}", wrote.stderr);

    let adopt = kan_as(
        dir.path(),
        Some(&successor),
        &["identity", "adopt", "--key", successor.to_str().unwrap()],
    );
    assert!(adopt.ok, "adopt failed: {}", adopt.stderr);
    assert!(
        adopt.stdout.contains("carried 2 role declaration"),
        "adopt should name what it carried across: {}",
        adopt.stdout
    );

    // A SUPERSET, not equality, and the extra member is the correction.
    //
    // "The set is unchanged" was the wrong property: it is satisfied by adopt
    // carrying the old registry and never declaring the identity it just
    // adopted, which is exactly the defect a fourth review round found. The
    // criterion passed BECAUSE of the bug. What must hold is that nothing
    // carried is lost AND the adopted identity is declared.
    let after = declared_dids(dir.path());
    assert!(
        before.is_subset(&after),
        "adopt dropped an identity that was declared before it: {after:?}"
    );
    assert!(
        after.contains(&did_of(dir.path(), None)),
        "adopt left the identity it adopted undeclared: {after:?}"
    );
}

/// REQ-9's actual point, and the reason it resolves from declaration authors:
/// the registry survives adopting **after the workspace identity is gone**.
///
/// This is the lost-key case. Had adopt asked `declared_roles()` for the set,
/// resolution would have returned `NoWorkspaceIdentity` — the identity is
/// precisely what is missing — the set would have been empty, and adopt would
/// have carried nothing while reporting success.
#[test]
fn adopt_carries_roles_even_when_the_workspace_identity_is_lost() {
    let dir = workspace_with_own_identity();
    let add = kan_as(dir.path(), None, &["identity", "role", "add", "reviewer"]);
    assert!(add.ok, "role add failed: {}", add.stderr);
    let before = declared_dids(dir.path());
    assert_eq!(before.len(), 2);

    let successor = dir.path().join("successor-key");
    kan::sign::Identity::generate().save(&successor).unwrap();
    let wrote = kan_as(
        dir.path(),
        Some(&successor),
        &["observe", "shared", "the successor's claim"],
    );
    assert!(wrote.ok, "{}", wrote.stderr);

    // Lose the secret the workspace roots in.
    for artifact in ["seed", "identity", "seed-id", "identity-id"] {
        let p = dir.path().join(".kan").join(artifact);
        if p.exists() {
            std::fs::remove_file(&p).unwrap();
        }
    }
    assert!(
        declared_dids(dir.path()).is_empty(),
        "precondition: with the identity gone, no declaration can be honoured"
    );

    let adopt = kan_as(
        dir.path(),
        Some(&successor),
        &["identity", "adopt", "--key", successor.to_str().unwrap()],
    );
    assert!(adopt.ok, "adopt failed: {}", adopt.stderr);

    let after = declared_dids(dir.path());
    assert!(
        before.is_subset(&after),
        "the registry did not survive a recovery adopt -- which is the one case REQ-9 \
         exists for: {after:?}\n{}",
        adopt.stdout
    );
    assert!(
        after.contains(&did_of(dir.path(), None)),
        "the recovered workspace's own identity is undeclared: {after:?}"
    );
}

/// Two declaring authors means adopt **carries nothing and says so**, rather
/// than guessing which registry belonged to the workspace.
#[test]
fn adopt_refuses_to_guess_between_two_registries() {
    let dir = workspace_with_own_identity();
    let add = kan_as(dir.path(), None, &["identity", "role", "add", "reviewer"]);
    assert!(add.ok, "{}", add.stderr);

    // A second identity that writes, adopts (becoming the workspace), and
    // declares its own role -- so the log now holds two declaring authors.
    let second = dir.path().join("second-key");
    kan::sign::Identity::generate().save(&second).unwrap();
    let wrote = kan_as(dir.path(), Some(&second), &["observe", "shared", "second"]);
    assert!(wrote.ok, "{}", wrote.stderr);
    let adopt = kan_as(
        dir.path(),
        Some(&second),
        &["identity", "adopt", "--key", second.to_str().unwrap()],
    );
    assert!(adopt.ok, "{}", adopt.stderr);
    let add2 = kan_as(dir.path(), None, &["identity", "role", "add", "auditor"]);
    assert!(add2.ok, "{}", add2.stderr);

    // A third identity adopts. Two authors have declared, so there is no
    // single registry to carry.
    let third = dir.path().join("third-key");
    kan::sign::Identity::generate().save(&third).unwrap();
    let wrote = kan_as(dir.path(), Some(&third), &["observe", "shared", "third"]);
    assert!(wrote.ok, "{}", wrote.stderr);
    let adopt3 = kan_as(
        dir.path(),
        Some(&third),
        &["identity", "adopt", "--key", third.to_str().unwrap()],
    );
    assert!(adopt3.ok, "{}", adopt3.stderr);
    assert!(
        adopt3.stdout.contains("will not guess"),
        "adopt should refuse to pick between two registries and say so: {}",
        adopt3.stdout
    );
    assert!(
        declared_dids(dir.path()).is_empty(),
        "adopt installed a registry it had no basis to choose: {}",
        adopt3.stdout
    );
}

/// The four rows of the only real `.kan/roles` in existence
/// (`maxinelevesque/sheaf-games`), copied verbatim in shape.
///
/// **A fixture, never the live workspace.** A test that read that repo would
/// pass or fail on whether someone had touched it, and could damage it. What
/// matters is reproduced here: four rows, tab-separated, absolute paths, and a
/// `primary` row whose key path points at a `.kan/identity` that does not
/// exist — that workspace is keychain-rooted, and `register_active` wrote the
/// path unconditionally.
const SHEAF_GAMES_ROLES: &str = "\
did:key:zDnaenWDM6qp5Ra829d9wPUzBKBA3V6fm2cg4KVP3WFKqsYTv\tprimary\t/w/.kan/identity
did:key:zDnaeZQRXpcTkQojRMTux2jYL8UDJvJAtLdyP7V3i36KcjjZF\tprover\t/w/.kan/roles.d/prover
did:key:zDnaeY4cHjp9KP1aLoegE5rMHix5qmcRTpK7BiRyszjyfJJjN\tdirector\t/w/.kan/roles.d/director
did:key:zDnaecF176LvsiLUhri2yC3zXgi4KxRo3MA89LKM4EyjBbWCe\treferee\t/w/.kan/roles.d/referee
";

/// AC-6 + AC-7: importing the real four-row file declares all four, is
/// idempotent, and leaves `.kan/roles` **byte-identical**.
#[test]
fn import_is_idempotent_and_preserves_the_set() {
    let dir = workspace_with_own_identity();
    let roles_file = dir.path().join(".kan/roles");
    std::fs::write(&roles_file, SHEAF_GAMES_ROLES).unwrap();
    let before = std::fs::read(&roles_file).unwrap();

    let expected: BTreeSet<String> = SHEAF_GAMES_ROLES
        .lines()
        .map(|l| l.split('\t').next().unwrap().to_string())
        .collect();
    assert_eq!(
        expected.len(),
        4,
        "the fixture should carry four distinct DIDs"
    );

    let first = kan_as(dir.path(), None, &["identity", "role", "import"]);
    assert!(first.ok, "import failed: {}", first.stderr);
    assert!(
        first.stdout.contains("safe to remove") && first.stdout.contains("older than v0.12"),
        "import must say the file is unread and name the one reason to keep it: {}",
        first.stdout
    );

    // AC-6: `--trust roles` names exactly the file's four DIDs.
    let listed = kan_as(dir.path(), None, &["identity", "role", "list", "--json"]);
    assert!(listed.ok, "{}", listed.stderr);
    let view: serde_json::Value = serde_json::from_str(&listed.stdout).unwrap();
    let got: BTreeSet<String> = view["roles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["did"].as_str().unwrap().to_string())
        .collect();
    assert!(
        expected.is_subset(&got),
        "import lost rows the file declared: {view}"
    );

    // A SUPERSET, not equality, and the extra member is the point.
    //
    // Import also ensures this workspace's OWN identity is declared, because a
    // registry that does not name it drops every claim it ever wrote out of
    // `--trust roles` -- the defect a third cold review graded blocking. The
    // fixture's four rows are fabricated DIDs, so none of them is this test
    // workspace's identity and the auto-declaration is visible here.
    //
    // On the real file it is a NO-OP: `sheaf-games`'s `primary` row names its
    // own workspace DID, so importing it declares that identity via the row.
    // The fixture is the harsher case, which is the right one to pin.
    let workspace_did = did_of(dir.path(), None);
    assert!(
        got.contains(&workspace_did),
        "import left this workspace's own identity undeclared: {view}"
    );
    assert_eq!(
        got.len(),
        expected.len() + 1,
        "import declared something beyond the file's rows and this workspace: {view}"
    );

    // AC-6, second half: running it twice adds nothing.
    let second = kan_as(dir.path(), None, &["identity", "role", "import"]);
    assert!(second.ok, "second import failed: {}", second.stderr);
    assert!(
        second.stdout.contains("nothing new to import"),
        "a second import should be a no-op: {}",
        second.stdout
    );
    let after_twice = kan_as(dir.path(), None, &["identity", "role", "list", "--json"]);
    let view2: serde_json::Value = serde_json::from_str(&after_twice.stdout).unwrap();
    assert_eq!(
        view2["roles"].as_array().unwrap().len(),
        5,
        "the second import duplicated declarations: {view2}"
    );

    // AC-7: the file is untouched, byte for byte.
    assert_eq!(
        std::fs::read(&roles_file).unwrap(),
        before,
        "import modified `.kan/roles`, which it must never do"
    );
}

/// Import **reports** a row whose name is already declared for a different
/// DID, and does not rebind it.
///
/// Latest-wins is the fold's rule for duplicates (REQ-6), and applying it
/// during a migration would silently repoint a live role at whatever an old
/// file happened to say — the one moment a quiet change is least welcome.
#[test]
fn import_refuses_to_rebind_a_live_name() {
    let dir = workspace_with_own_identity();
    let add = kan_as(dir.path(), None, &["identity", "role", "add", "prover"]);
    assert!(add.ok, "role add failed: {}", add.stderr);

    let live = kan_as(dir.path(), None, &["identity", "role", "list", "--json"]);
    let view: serde_json::Value = serde_json::from_str(&live.stdout).unwrap();
    let live_did = view["roles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "prover")
        .unwrap()["did"]
        .as_str()
        .unwrap()
        .to_string();

    std::fs::write(
        dir.path().join(".kan/roles"),
        "did:key:zDnaeSezF2t8gTQrOFpVmvSMPFsxqRDzZL6JGjTxjJ2TvNqYe\tprover\t/gone\n",
    )
    .unwrap();

    let import = kan_as(dir.path(), None, &["identity", "role", "import"]);
    assert!(
        import.ok,
        "import should not fail on a conflict: {}",
        import.stderr
    );
    assert!(
        import.stderr.contains("NOT imported"),
        "the conflict must be reported: {}",
        import.stderr
    );

    let after = kan_as(dir.path(), None, &["identity", "role", "list", "--json"]);
    let view: serde_json::Value = serde_json::from_str(&after.stdout).unwrap();
    let still = view["roles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "prover")
        .unwrap()["did"]
        .as_str()
        .unwrap();
    assert_eq!(
        still, live_did,
        "import rebound a live role name to the file's DID: {view}"
    );
}

/// The migration's discoverability half: a workspace holding a legacy
/// `.kan/roles` that has not been imported is **told so**, on both surfaces an
/// operator would ask on.
///
/// Without it, upgrading `sheaf-games` -- the one real workspace with this
/// file -- makes `--trust roles` go empty and `kan identity authors` report
/// four UNDECLARED authors, with nothing anywhere pointing at the file sitting
/// in `.kan/`. Decided with Maxine when the one-shot import was chosen; the
/// cost of every non-automatic option was exactly this, and this closes it
/// without kan reading the file for resolution.
#[test]
fn a_legacy_roles_file_is_noticed_and_named() {
    let dir = workspace_with_own_identity();
    std::fs::write(
        dir.path().join(".kan/roles"),
        "did:key:zDnaeSezF2t8gTQrOFpVmvSMPFsxqRDzZL6JGjTxjJ2TvNqYe\tprover\t/gone\n",
    )
    .unwrap();

    for args in [
        &["identity", "role", "list"][..],
        &["identity", "authors"][..],
    ] {
        let run = kan_as(dir.path(), None, args);
        assert!(run.ok, "{args:?} failed: {}", run.stderr);
        assert!(
            run.stdout.contains("kan identity role import"),
            "{args:?} did not name the command that brings the file across: {}",
            run.stdout
        );
    }

    // And it must go away on its own once something IS declared, rather than
    // needing kan to remember that the migration happened.
    let add = kan_as(dir.path(), None, &["identity", "role", "add", "reviewer"]);
    assert!(add.ok, "role add failed: {}", add.stderr);
    let listed = kan_as(dir.path(), None, &["identity", "role", "list"]);
    assert!(
        !listed.stdout.contains("kan identity role import"),
        "the notice outlived the state it describes: {}",
        listed.stdout
    );
}

/// REQ-8: `roles` expanding to nothing must not take the rest of the frame
/// with it. This is the argument that reversed the spec from erroring to an
/// empty frame -- an erroring alias makes one member of a set kill the whole
/// read.
#[test]
fn an_empty_roles_alias_still_composes() {
    let dir = workspace_with_own_identity();
    let did = kan_as(dir.path(), None, &["identity", "did"]);
    assert!(did.ok, "{}", did.stderr);

    let run = kan_as(
        dir.path(),
        None,
        &[
            "show",
            "shared",
            "--trust",
            "roles",
            "--trust",
            &did.stdout,
            "--json",
        ],
    );
    assert!(
        run.ok,
        "`--trust roles --trust <did>` failed because `roles` expanded to nothing: {}",
        run.stderr
    );
    let view: serde_json::Value = serde_json::from_str(&run.stdout).unwrap();
    assert_eq!(
        view["claims"].as_array().unwrap().len(),
        1,
        "the named author's claim should still be returned: {view}"
    );
    assert!(
        view["trust"]["empty_reason"].is_null(),
        "a frame that named an author is not empty and must carry no empty_reason: {view}"
    );
}

/// REQ-4 + AC-11: `kan identity role list` reports **name and DID, and no key
/// path**, in both renderings.
#[test]
fn role_list_reports_two_columns_and_no_key_path() {
    let dir = workspace_with_own_identity();
    let add = kan_as(dir.path(), None, &["identity", "role", "add", "reviewer"]);
    assert!(add.ok, "role add failed: {}", add.stderr);

    let listed = kan_as(dir.path(), None, &["identity", "role", "list"]);
    assert!(listed.ok, "role list failed: {}", listed.stderr);
    let row = listed
        .stdout
        .lines()
        .find(|line| line.starts_with("reviewer\t"))
        .unwrap_or_else(|| panic!("no row for the declared role: {}", listed.stdout));
    assert_eq!(
        row.split('\t').count(),
        2,
        "a role row is `name<TAB>did` since REQ-4 dropped the key path: {row:?}"
    );
    assert!(
        !listed.stdout.contains("roles.d"),
        "the key path is back in the listing: {}",
        listed.stdout
    );

    let json = kan_as(dir.path(), None, &["identity", "role", "list", "--json"]);
    assert!(json.ok, "role list --json failed: {}", json.stderr);
    let view: serde_json::Value = serde_json::from_str(&json.stdout).unwrap();
    let roles = view["roles"].as_array().expect("roles array");
    let reviewer = roles
        .iter()
        .find(|r| r["name"] == "reviewer")
        .unwrap_or_else(|| panic!("reviewer missing from {view}"));
    assert!(
        reviewer.get("key_path").is_none(),
        "RoleJson still carries key_path: {reviewer}"
    );
    assert!(
        reviewer["did"]
            .as_str()
            .is_some_and(|d| d.starts_with("did:")),
        "a declared role must report its DID: {reviewer}"
    );
}

/// REQ-7 + AC-9, first half — depth 0's negative control. A role cannot
/// declare a role, and the refusal appends **nothing**.
#[test]
fn a_role_cannot_declare_a_role() {
    let dir = workspace_with_own_identity();
    let add = kan_as(dir.path(), None, &["identity", "role", "add", "reviewer"]);
    assert!(add.ok, "role add failed: {}", add.stderr);

    let role_key = dir.path().join(".kan/roles.d/reviewer");
    assert!(role_key.exists(), "the role key should have been minted");

    let before = claim_count(dir.path());
    let nested = kan_as(
        dir.path(),
        Some(&role_key),
        &["identity", "role", "add", "deputy"],
    );

    assert!(
        !nested.ok,
        "a declared role was allowed to declare another role: {}",
        nested.stdout
    );
    assert!(
        nested.stderr.contains("only this workspace's own identity"),
        "the refusal should name the rule it enforces: {}",
        nested.stderr
    );
    assert_eq!(
        claim_count(dir.path()),
        before,
        "a refused declaration still appended a claim"
    );
}

/// REQ-7 + AC-9, second half — the hole the change-ledger golden found.
///
/// A workspace driven entirely by `KAN_IDENTITY_FILE` has no identity of its
/// own, so *nothing* could ever honour a declaration written there. The first
/// version of the guard compared the signer against the workspace identity
/// only when one existed, so this case skipped the check: `role add` reported
/// success and `--trust roles` could never see the result. A
/// complete-looking write with no effect is the defect class this milestone
/// exists to close, so it must refuse and append nothing.
#[test]
fn a_workspace_with_no_identity_of_its_own_cannot_declare() {
    let dir = git_repo();
    let key = dir.path().join("outside-key");
    kan::sign::Identity::generate().save(&key).unwrap();

    let wrote = kan_as(dir.path(), Some(&key), &["observe", "shared", "a claim"]);
    assert!(wrote.ok, "seeding write failed: {}", wrote.stderr);
    assert!(
        !dir.path().join(".kan/seed").exists() && !dir.path().join(".kan/identity").exists(),
        "this test needs a workspace with NO identity of its own, or it proves nothing"
    );

    let before = claim_count(dir.path());
    let add = kan_as(
        dir.path(),
        Some(&key),
        &["identity", "role", "add", "reviewer"],
    );

    assert!(
        !add.ok,
        "a workspace with no identity of its own declared a role that nothing can honour: {}",
        add.stdout
    );
    assert!(
        add.stderr.contains("no identity of its own"),
        "the refusal should say why the declaration could never be honoured: {}",
        add.stderr
    );
    assert_eq!(
        claim_count(dir.path()),
        before,
        "a refused declaration still appended a claim"
    );
}

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

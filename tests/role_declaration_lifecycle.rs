//! `.design/role-declarations.md` AC-3, AC-4, AC-5 and AC-8 — what happens to
//! a role declaration over its life: retracted, foreign, or re-declared.
//!
//! Separate from `tests/role_declarations.rs`, which pins the *surfaces*
//! (listing, refusals, the three empty frames). These pin the *rules the fold
//! applies*, which is where a silent change would be hardest to notice.

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

/// The CID of the claim declaring `name`, read off that role's own subject —
/// which is exactly what REQ-2's `role/<name>` subject choice buys. Under a
/// single shared registry subject this would mean filtering a growing list.
fn declaration_cid(dir: &std::path::Path, name: &str) -> String {
    let run = kan_as(dir, None, &["show", &format!("role/{name}"), "--json"]);
    assert!(run.ok, "show role/{name} failed: {}", run.stderr);
    let view: serde_json::Value = serde_json::from_str(&run.stdout).unwrap();
    view["claims"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["kind"] == "RoleDeclaration")
        .unwrap_or_else(|| panic!("no declaration on role/{name}: {view}"))["cid"]
        .as_str()
        .unwrap()
        .to_string()
}

/// Every file under `.kan/`, recursively and sorted, so "no file edited" is a
/// comparison rather than an assertion.
fn kan_dir_listing(dir: &std::path::Path) -> Vec<String> {
    fn walk(root: &std::path::Path, prefix: &str, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(root) else {
            return;
        };
        for entry in entries.flatten() {
            let name = format!("{prefix}{}", entry.file_name().to_string_lossy());
            if entry.path().is_dir() {
                walk(&entry.path(), &format!("{name}/"), out);
            } else {
                out.push(name);
            }
        }
    }
    let mut out = Vec::new();
    walk(&dir.join(".kan"), "", &mut out);
    out.sort();
    out
}

/// **AC-3 — the milestone's AC-10.** A role declaration carries an author, and
/// retracting it removes the role from `--trust roles` **with no file edited**.
///
/// The `.kan/` listing is compared before and after, so "no file edited" is
/// measured. Under `.kan/roles` this same operation was a line deletion; that
/// it is now purely a claim operation is the requirement.
#[test]
fn retracting_a_declaration_removes_the_role() {
    let dir = workspace_with_own_identity();
    let add = kan_as(dir.path(), None, &["identity", "role", "add", "reviewer"]);
    assert!(add.ok, "role add failed: {}", add.stderr);
    assert_eq!(
        declared_dids(dir.path()).len(),
        2,
        "primary + reviewer should be declared"
    );

    let shown = kan_as(dir.path(), None, &["show", "role/reviewer", "--json"]);
    assert!(shown.ok, "{}", shown.stderr);
    let view: serde_json::Value = serde_json::from_str(&shown.stdout).unwrap();
    let declaration = view["claims"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["kind"] == "RoleDeclaration")
        .unwrap();
    assert!(
        declaration["author"]
            .as_str()
            .is_some_and(|a| a.starts_with("did:")),
        "a declaration must carry its author: {view}"
    );

    let before_files = kan_dir_listing(dir.path());
    let cid = declaration_cid(dir.path(), "reviewer");
    let retract = kan_as(dir.path(), None, &["retract", &cid]);
    assert!(retract.ok, "retract failed: {}", retract.stderr);

    let after = declared_dids(dir.path());
    assert_eq!(
        after.len(),
        1,
        "retracting the declaration did not remove the role: {after:?}"
    );
    assert_eq!(
        kan_dir_listing(dir.path()),
        before_files,
        "retracting a role added or removed a file in `.kan/`; it must be a claim \
         operation only"
    );
}

/// AC-4: a role whose declaring claim is retracted **cannot be named**.
#[test]
fn a_retracted_role_is_undeclared() {
    let dir = workspace_with_own_identity();
    let add = kan_as(dir.path(), None, &["identity", "role", "add", "reviewer"]);
    assert!(add.ok, "{}", add.stderr);
    let role_key = dir.path().join(".kan/roles.d/reviewer");
    let wrote = kan_as(
        dir.path(),
        Some(&role_key),
        &["observe", "shared", "the reviewer's claim"],
    );
    assert!(wrote.ok, "{}", wrote.stderr);

    let named = kan_as(
        dir.path(),
        None,
        &["show", "shared", "--trust", "role:reviewer", "--json"],
    );
    assert!(
        named.ok,
        "role:reviewer should resolve while declared: {}",
        named.stderr
    );

    let cid = declaration_cid(dir.path(), "reviewer");
    assert!(kan_as(dir.path(), None, &["retract", &cid]).ok);

    let after = kan_as(
        dir.path(),
        None,
        &["show", "shared", "--trust", "role:reviewer", "--json"],
    );
    assert!(
        !after.ok,
        "`role:reviewer` still resolved after its declaration was retracted: {}",
        after.stdout
    );
    assert!(
        after.stderr.contains("names no role"),
        "the refusal should say the name is not declared: {}",
        after.stderr
    );

    // The same fact stated positively, which is what `identity authors` is for.
    let authors = kan_as(dir.path(), None, &["identity", "authors"]);
    assert!(authors.ok, "{}", authors.stderr);
    assert!(
        authors.stdout.contains("UNDECLARED"),
        "the retracted role's author should read as undeclared: {}",
        authors.stdout
    );
}

/// AC-5: a declaration authored by **anyone other than** the workspace
/// identity grants nothing — and nothing is hidden either.
///
/// This is REQ-8's pre-condition and the reason the rule had to be fixed
/// before the sharing channel opens: once `.claims/`-borne records count as
/// authors, a foreign file could otherwise declare a role for itself.
#[test]
fn a_foreign_declaration_grants_nothing() {
    let dir = workspace_with_own_identity();

    let stranger = dir.path().join("stranger-key");
    kan::sign::Identity::generate().save(&stranger).unwrap();
    let wrote = kan_as(
        dir.path(),
        Some(&stranger),
        &["observe", "shared", "the stranger's claim"],
    );
    assert!(wrote.ok, "{}", wrote.stderr);
    let stranger_did = kan_as(dir.path(), Some(&stranger), &["identity", "did"]).stdout;

    // kan refuses to write one at all (REQ-7) -- the first half of the rule.
    let refused = kan_as(
        dir.path(),
        Some(&stranger),
        &["identity", "role", "add", "smuggled"],
    );
    assert!(
        !refused.ok,
        "a non-workspace identity was allowed to declare: {}",
        refused.stdout
    );

    let declared = declared_dids(dir.path());
    assert!(
        !declared.contains(&stranger_did),
        "the stranger must not be declared: {declared:?}"
    );

    // ...and the second half: the stranger's claims stay fully visible. A rule
    // that granted nothing by HIDING things would be the wrong fix.
    let shown = kan_as(dir.path(), None, &["show", "shared", "--json"]);
    assert!(shown.ok, "{}", shown.stderr);
    let view: serde_json::Value = serde_json::from_str(&shown.stdout).unwrap();
    let authors: BTreeSet<String> = view["claims"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["author"].as_str().unwrap().to_string())
        .collect();
    assert!(
        authors.contains(&stranger_did),
        "the stranger's claims must remain visible -- nothing is hidden: {view}"
    );
}

/// AC-8: the registry survives an **index rebuild**, and a re-declaration of a
/// taken name is refused as affordance (REQ-6) without changing the set.
///
/// The rebuild half matters because the index is disposable: a projection that
/// only holds while it is warm is not a projection.
#[test]
fn the_declared_set_survives_an_index_rebuild() {
    let dir = workspace_with_own_identity();
    let first = kan_as(dir.path(), None, &["identity", "role", "add", "reviewer"]);
    assert!(first.ok, "{}", first.stderr);
    let expected = declared_dids(dir.path());
    assert_eq!(expected.len(), 2);

    let second_key = dir.path().join("second-reviewer");
    kan::sign::Identity::generate().save(&second_key).unwrap();
    let refused = kan_as(
        dir.path(),
        None,
        &[
            "identity",
            "role",
            "add",
            "reviewer",
            "--key",
            second_key.to_str().unwrap(),
        ],
    );
    assert!(
        !refused.ok,
        "declaring a taken name should be refused as affordance: {}",
        refused.stdout
    );
    assert!(
        refused.stderr.contains("already declared"),
        "the refusal should name the clash: {}",
        refused.stderr
    );
    assert_eq!(
        declared_dids(dir.path()),
        expected,
        "a refused re-declaration changed the registry"
    );

    std::fs::remove_file(dir.path().join(".kan/index.sqlite")).unwrap();
    assert_eq!(
        declared_dids(dir.path()),
        expected,
        "the declared set changed when the index was rebuilt from the log"
    );
}

//! The properties of the role registry that must hold **identically** before
//! and after REQ-5 moves it from `.kan/roles` to `RoleDeclaration` claims
//! (`.design/role-declarations.md`).
//!
//! **Landed before the move, deliberately, and this is the whole point of the
//! file.** REQ-5's acceptance criteria say `--trust roles` returns "the same
//! author set the file produced". An expectation written *after* the resolver
//! changes is one derived from the new code, and can only agree with itself.
//! These tests pass against the file-backed resolver as it stands today; they
//! are not edited when the resolver moves, and their going green afterwards is
//! the evidence. `atom/generative-build`: instrument the measurement before the
//! change it measures.
//!
//! Both tests assert **membership**, never a count. The suite's existing role
//! coverage (`tests/multi_role.rs`) asserts claim counts, which a migration
//! that swapped one author for another at the same cardinality would pass.

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

/// The DIDs `--trust <spec>` expanded to — the *mechanism* that moves from a
/// file read to a fold, read straight off the view's own trust report.
fn expanded_authors(view: &serde_json::Value) -> BTreeSet<String> {
    view["trust"]["authors"]
        .as_array()
        .expect("a view must report the authors its trust base expanded to")
        .iter()
        .map(|a| a["did"].as_str().expect("author did").to_string())
        .collect()
}

/// The authors of the claims the view actually returned — the *consequence*.
/// Pinned alongside the expansion because they can disagree: v0.11 found two
/// projection bugs that hid each other, where fixing one alone would have
/// turned a cost into a wrong answer.
fn visible_authors(view: &serde_json::Value) -> BTreeSet<String> {
    view["claims"]
        .as_array()
        .expect("claims")
        .iter()
        .map(|c| c["author"].as_str().expect("claim author").to_string())
        .collect()
}

fn show_roles(dir: &std::path::Path) -> serde_json::Value {
    let run = kan_as(dir, None, &["show", "shared", "--trust", "roles", "--json"]);
    assert!(run.ok, "`--trust roles` failed: {}", run.stderr);
    serde_json::from_str(&run.stdout).expect("valid json from --json")
}

fn did_of(dir: &std::path::Path, key: Option<&std::path::Path>) -> String {
    let run = kan_as(dir, key, &["identity", "did"]);
    assert!(run.ok, "identity did failed: {}", run.stderr);
    run.stdout
}

/// Declare two roles beside the primary, have all three write, and return
/// `(workspace, primary_did, prover_did, director_did, director_key)`.
fn workspace_with_two_roles() -> (
    tempfile::TempDir,
    String,
    String,
    String,
    std::path::PathBuf,
) {
    let dir = git_repo();
    let kan_dir = dir.path().join(".kan");
    std::fs::create_dir_all(&kan_dir).unwrap();
    kan::sign::Identity::generate()
        .save(&kan_dir.join("identity"))
        .unwrap();
    let first = kan_as(
        dir.path(),
        None,
        &["observe", "shared", "the primary's claim"],
    );
    assert!(first.ok, "primary write failed: {}", first.stderr);
    let primary = did_of(dir.path(), None);

    let mut dids = Vec::new();
    let mut keys = Vec::new();
    for name in ["prover", "director"] {
        let key = dir.path().join("keys").join(name);
        std::fs::create_dir_all(key.parent().unwrap()).unwrap();
        kan::sign::Identity::generate().save(&key).unwrap();

        let add = kan_as(
            dir.path(),
            None,
            &[
                "identity",
                "role",
                "add",
                name,
                "--key",
                key.to_str().unwrap(),
            ],
        );
        assert!(add.ok, "role add {name} failed: {}", add.stderr);

        let wrote = kan_as(
            dir.path(),
            Some(&key),
            &["observe", "shared", &format!("the {name}'s claim")],
        );
        assert!(wrote.ok, "{name} write failed: {}", wrote.stderr);

        dids.push(did_of(dir.path(), Some(&key)));
        keys.push(key);
    }

    (
        dir,
        primary,
        dids[0].clone(),
        dids[1].clone(),
        keys[1].clone(),
    )
}

/// `--trust roles` expands to **exactly** the declared set — the primary that
/// `role add` auto-registers, plus both declared roles, and nothing else.
///
/// This is REQ-5's AC-6 stated as a property rather than as a number, and it
/// is the assertion the migration has to satisfy: the same three DIDs, whether
/// they come from three tab-separated lines or from three claims.
#[test]
fn trust_roles_expands_to_the_exact_declared_set() {
    let (dir, primary, prover, director, _) = workspace_with_two_roles();
    let expected: BTreeSet<String> = [primary, prover, director].into_iter().collect();

    let view = show_roles(dir.path());

    assert_eq!(
        expanded_authors(&view),
        expected,
        "`--trust roles` expanded to a different author set than the registry declares: {view}"
    );
    assert_eq!(
        visible_authors(&view),
        expected,
        "the claims returned were authored by a different set than the trust base named: {view}"
    );
}

/// A declared role's claims stay visible under `--trust roles` **after its key
/// file is deleted**.
///
/// This is the shape of the one real `.kan/roles` file in existence, and it is
/// not a contrived case: `maxinelevesque/sheaf-games` is keychain-rooted, so
/// `register_active` recorded its primary at `.kan/identity` — a path that has
/// never existed there — while that identity holds 807 claims. A registry row
/// whose third column points at nothing is the normal state, not the damaged
/// one.
///
/// It is pinned here because REQ-4 deletes that column, and a migration that
/// quietly dropped rows it could not resolve to a live key would take a role's
/// entire history out of `--trust roles` while every count still looked
/// plausible. Under REQ-5 the property holds for a stronger reason than it
/// does today: the declaration is a claim, and the key path is not in it at
/// all.
#[test]
fn a_declared_role_outlives_its_key_file() {
    let (dir, primary, prover, director, director_key) = workspace_with_two_roles();

    std::fs::remove_file(&director_key).expect("removing the director's key");
    assert!(
        !director_key.exists(),
        "the key file is still present, so this test would pass without proving anything"
    );

    let expected: BTreeSet<String> = [primary, prover, director].into_iter().collect();
    let view = show_roles(dir.path());

    assert_eq!(
        expanded_authors(&view),
        expected,
        "deleting a role's key file removed it from `--trust roles`: {view}"
    );
    assert_eq!(
        visible_authors(&view),
        expected,
        "deleting a role's key file hid the claims it had already written: {view}"
    );
}

/// The registry's default-key route persists the key it declares under the
/// cataloged `.kan/roles.d/<name>` artifact, and the declaration's DID is the
/// DID that key actually controls. Membership-only assertions cannot prove
/// this at-rest binding.
#[test]
fn a_default_role_persists_the_key_that_its_declaration_names() {
    let dir = git_repo();
    let add = kan_as(dir.path(), None, &["identity", "role", "add", "auditor"]);
    assert!(add.ok, "role add failed: {}", add.stderr);

    let key = dir.path().join(".kan/roles.d/auditor");
    assert!(
        key.is_file(),
        "default role key was not persisted at {key:?}"
    );
    let key_did = did_of(dir.path(), Some(&key));

    let listed = kan_as(dir.path(), None, &["identity", "role", "list", "--json"]);
    assert!(listed.ok, "role list failed: {}", listed.stderr);
    let view: serde_json::Value = serde_json::from_str(&listed.stdout).expect("role list JSON");
    let roles = view["roles"].as_array().expect("roles array");
    let auditor = roles
        .iter()
        .find(|role| role["name"] == "auditor")
        .unwrap_or_else(|| panic!("auditor missing from {}", listed.stdout));
    assert_eq!(auditor["did"], key_did);
}

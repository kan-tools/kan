//! Regression tests for the two BLOCKING defects a cold adversarial review
//! found in `v0.12-role-declarations` (`.design/role-declarations.md`).
//!
//! Both reproduce the reviewer's own case, per CLAUDE.md's rule that a fix
//! answering a review finding ships with a test that fails without it. Both
//! were confirmed by hand against the built binary before being written here,
//! and both were verified by reverting the fix hunk and watching *these*
//! tests — not merely some test — go red.
//!
//! The common shape is worth naming: each defect is a **complete-looking write
//! that grants nothing**, produced by the very requirements written to
//! eliminate that class. Knowing a failure class is not protection against it.

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

fn did_of(dir: &std::path::Path, key: Option<&std::path::Path>) -> String {
    let run = kan_as(dir, key, &["identity", "did"]);
    assert!(run.ok, "identity did failed: {}", run.stderr);
    run.stdout
}

/// **Round 2, BLOCKING-1.** `kan identity role add` after `kan identity role
/// import` must still declare the workspace's own identity.
///
/// The defect: the auto-declaration was gated on the registry being **empty**,
/// where `main`'s `register_active` checked whether the workspace's **DID** was
/// already recorded. `import` fills the registry from a legacy file that need
/// not contain a `primary` row — the file this milestone exists to migrate —
/// so the next `role add` saw a non-empty set, skipped the auto-declaration,
/// and left the workspace's own identity undeclared. `role list` then printed
/// `active: <W>` directly above a list not containing `W`, and `W`'s own claims
/// were excluded from `--trust roles`.
///
/// The same loss `primary_role_name`'s docstring says the auto-declaration
/// exists to prevent — reached by it *not firing* rather than by firing twice.
#[test]
fn role_add_after_import_still_declares_the_workspace_identity() {
    let dir = workspace_with_own_identity();
    let workspace_did = did_of(dir.path(), None);

    // A legacy registry with no `primary` row — exactly what a pre-v0.12
    // workspace that never ran `role add` looks like.
    std::fs::write(
        dir.path().join(".kan/roles"),
        "did:key:zDnaeSezF2t8gTQrOFpVmvSMPFsxqRDzZL6JGjTxjJ2TvNqYe\treviewer\t/gone\n",
    )
    .unwrap();
    let import = kan_as(dir.path(), None, &["identity", "role", "import"]);
    assert!(import.ok, "import failed: {}", import.stderr);
    assert!(
        !declared_dids(dir.path()).contains(&workspace_did),
        "precondition: import alone should not declare the workspace identity, or this \
         test proves nothing"
    );

    let add = kan_as(dir.path(), None, &["identity", "role", "add", "auditor"]);
    assert!(add.ok, "role add failed: {}", add.stderr);

    let declared = declared_dids(dir.path());
    assert!(
        declared.contains(&workspace_did),
        "after import, `role add` left the workspace's own identity undeclared: {declared:?}"
    );

    // The property that matters: its claims are visible under `--trust roles`.
    // Asserted on the AUTHORS of returned claims rather than by grepping the
    // listing -- `role list` prints `active: <did>` as its first line, so a
    // naive substring search for the DID matches that line and reports success
    // while the registry is wrong. (That false positive is how this defect
    // nearly escaped a second time.)
    let view = kan_as(
        dir.path(),
        None,
        &["show", "shared", "--trust", "roles", "--json"],
    );
    assert!(view.ok, "{}", view.stderr);
    let view: serde_json::Value = serde_json::from_str(&view.stdout).unwrap();
    let authors: BTreeSet<String> = view["claims"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["author"].as_str().unwrap().to_string())
        .collect();
    assert!(
        authors.contains(&workspace_did),
        "`--trust roles` lost the workspace identity's own claims after import: {view}"
    );
}

/// **BLOCKING-2.** `kan identity role add primary` must not shadow the
/// workspace's own identity out of `--trust roles`.
///
/// The defect: `declare_role` auto-declares the workspace identity as
/// `primary`, then declares the requested role — and when the requested name
/// *is* `primary`, latest-wins rebound it to the new role key and dropped the
/// workspace's own identity, and every claim it had written, out of the view.
/// The clash check could not catch it, because it runs against the declared
/// set, which is empty by the condition that triggers the auto-declaration.
///
/// `primary_role_name` already existed to pick `primary-<suffix>` on a
/// collision, and was being called with a hardcoded empty "taken" list, so its
/// collision branch was dead code.
#[test]
fn declaring_a_role_named_primary_does_not_shadow_the_workspace_identity() {
    let dir = workspace_with_own_identity();
    let workspace_did = did_of(dir.path(), None);

    let add = kan_as(dir.path(), None, &["identity", "role", "add", "primary"]);
    assert!(add.ok, "role add primary failed: {}", add.stderr);

    let declared = declared_dids(dir.path());
    assert!(
        declared.contains(&workspace_did),
        "the workspace's own identity was shadowed out of the declared set by a role \
         named `primary`: {declared:?}"
    );
    assert_eq!(
        declared.len(),
        2,
        "both the workspace identity and the new role should be declared: {declared:?}"
    );

    // The property that actually matters: the workspace's own claim is still
    // visible under `--trust roles`. The set assertion above would pass on a
    // registry that was right while the view was wrong.
    let view = kan_as(
        dir.path(),
        None,
        &["show", "shared", "--trust", "roles", "--json"],
    );
    assert!(view.ok, "{}", view.stderr);
    let view: serde_json::Value = serde_json::from_str(&view.stdout).unwrap();
    let authors: BTreeSet<String> = view["claims"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["author"].as_str().unwrap().to_string())
        .collect();
    assert!(
        authors.contains(&workspace_did),
        "`--trust roles` lost the workspace identity's own claims: {view}"
    );
}

/// **BLOCKING-1.** `kan identity adopt` must not report carrying a role
/// registry it authored under the wrong identity.
///
/// The defect: the carry opened a writable workspace, which resolves a
/// *selection* from `KAN_IDENTITY_FILE` rather than the key just adopted. With
/// the variable pointing anywhere else, all the declarations were authored by
/// that identity — valid, signed, and inert — `--trust roles` went from three
/// authors to zero, and adopt printed "carried 3 role declaration(s) across to
/// <adopted>", naming an identity that authored none of them.
///
/// This is the documented CI/`day`/agent configuration, where
/// `KAN_IDENTITY_FILE` is always set.
#[test]
fn adopt_does_not_carry_roles_under_a_stray_selection() {
    let dir = workspace_with_own_identity();
    let add = kan_as(dir.path(), None, &["identity", "role", "add", "reviewer"]);
    assert!(add.ok, "{}", add.stderr);
    let reviewer_key = dir.path().join(".kan/roles.d/reviewer");
    assert!(
        kan_as(
            dir.path(),
            Some(&reviewer_key),
            &["observe", "shared", "the reviewer's claim"]
        )
        .ok
    );

    // A third identity, which is what `KAN_IDENTITY_FILE` will point at.
    let stray = dir.path().join("stray-key");
    kan::sign::Identity::generate().save(&stray).unwrap();
    assert!(kan_as(dir.path(), Some(&stray), &["observe", "shared", "stray"]).ok);
    let stray_did = did_of(dir.path(), Some(&stray));

    let adopted_did = did_of(dir.path(), Some(&reviewer_key));
    let adopt = kan_as(
        dir.path(),
        Some(&stray),
        &["identity", "adopt", "--key", reviewer_key.to_str().unwrap()],
    );
    assert!(adopt.ok, "adopt failed: {}", adopt.stderr);

    // Either it carried them correctly, or it refused and said so. What it
    // must NEVER do is report success while authoring them as someone else.
    let declarations = kan_as(dir.path(), None, &["show", "role/reviewer", "--json"]);
    assert!(declarations.ok, "{}", declarations.stderr);
    let view: serde_json::Value = serde_json::from_str(&declarations.stdout).unwrap();
    let authored_by_stray = view["claims"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["kind"] == "RoleDeclaration")
        .any(|c| c["author"] == stray_did);
    assert!(
        !authored_by_stray,
        "adopt authored a role declaration as the KAN_IDENTITY_FILE selection ({stray_did}) \
         rather than the adopted identity ({adopted_did}); such a declaration grants \
         nothing: {view}"
    );

    // And the report must not claim a carry that did not happen.
    //
    // The refusal text also contains the word "carried" ("was NOT carried
    // across"), so a bare `contains("carried")` matches both branches and
    // sends this into the wrong one -- which is exactly the incidental-
    // substring trap this file exists to guard against, met while writing the
    // guard. The refusal is therefore checked FIRST and by its own phrase.
    let refused = adopt.stdout.contains("NOT carried across");
    let claimed_carry = adopt.stdout.contains("role declaration(s) across to");
    assert!(
        refused ^ claimed_carry,
        "adopt must either carry the registry or say plainly that it did not, never both \
         or neither: {}",
        adopt.stdout
    );
    if claimed_carry {
        assert!(
            declared_dids(dir.path()).contains(&adopted_did),
            "adopt reported carrying the registry, but the adopted identity declares \
             nothing: {}",
            adopt.stdout
        );
    }
}

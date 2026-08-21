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
    let kan_dir = dir.path().join(".kan");
    std::fs::create_dir_all(&kan_dir).unwrap();
    kan::sign::Identity::generate()
        .save(&kan_dir.join("identity"))
        .unwrap();
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

/// **Round 2 BLOCKING-1 and round 3 BLOCKING-2.** Both `kan identity role
/// import` and a subsequent `kan identity role add` must leave the workspace's
/// own identity declared.
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

    // Round 3, BLOCKING-2: import ALONE must declare it too. Round 2's version
    // of this test asserted the opposite as a "precondition" -- enshrining the
    // defect as expected behaviour, which is how a regression test can make a
    // gap permanent instead of catching it.
    assert!(
        declared_dids(dir.path()).contains(&workspace_did),
        "`role import` left the workspace's own identity undeclared, so `--trust roles` \
         drops every claim it ever wrote"
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

/// **Round 3, BLOCKING-1.** The auto-declared primary name must be one that is
/// actually free.
///
/// `primary_role_name` asked only whether the literal `"primary"` was taken and,
/// if so, returned `primary-<suffix>` **without checking that too**. With both
/// already declared it handed back a colliding name, REQ-6's latest-wins
/// rebound it, and the previous holder's claims silently left `--trust roles`.
///
/// Round 2's fix -- extending the caller's `taken` list -- bought nothing
/// against this, because the branch it selects never consulted the list. That
/// hunk was also untested: reverting it left all 385 tests green.
#[test]
fn the_auto_declared_primary_never_takes_a_live_name() {
    let dir = workspace_with_own_identity();
    let workspace_did = did_of(dir.path(), None);
    let suffix = &workspace_did[workspace_did.len() - 8..];

    // A legacy registry that already holds BOTH candidate names, for other
    // identities. Reachable by hand-editing, and by any workspace that has
    // been through more than one identity.
    let other_a = kan::sign::Identity::generate().did();
    let other_b = kan::sign::Identity::generate().did();
    std::fs::write(
        dir.path().join(".kan/roles"),
        format!("{other_a}\tprimary\t/gone\n{other_b}\tprimary-{suffix}\t/gone\n"),
    )
    .unwrap();

    let import = kan_as(dir.path(), None, &["identity", "role", "import"]);
    assert!(import.ok, "import failed: {}", import.stderr);

    let declared = declared_dids(dir.path());
    for (label, did) in [("primary", &other_a), ("primary-<suffix>", &other_b)] {
        assert!(
            declared.contains(did),
            "the auto-declared primary took `{label}`, which another identity already \
             held, and latest-wins dropped it: {declared:?}"
        );
    }
    assert!(
        declared.contains(&workspace_did),
        "the workspace identity was not declared at all: {declared:?}"
    );
    assert_eq!(
        declared.len(),
        3,
        "all three identities should be declared, under three distinct names: {declared:?}"
    );
}

/// **Round 3, N8.** The auto-declaration must be **said out loud**, on both
/// paths that perform it.
///
/// `kan identity role add auditor` appends a `RoleDeclaration` for the
/// workspace's own identity that the operator never asked for, and printed
/// only `auditor`. REQ-9 earns its own write side effect by being "visible,
/// deliberate, reversible" — this one was two of the three.
///
/// It is not a cosmetic gap. **Both of this feature's deliverable defects were
/// silent because of it**: one had the auto-declaration write a colliding name
/// and drop a live role, the other had it never fire, and in both cases
/// nothing on screen would have shown either. A write the operator cannot see
/// is a write nobody reviews.
#[test]
fn the_auto_declaration_is_reported_on_both_paths() {
    // Path 1: `role add` on a workspace with nothing declared.
    let dir = workspace_with_own_identity();
    let workspace_did = did_of(dir.path(), None);
    let add = kan_as(dir.path(), None, &["identity", "role", "add", "auditor"]);
    assert!(add.ok, "role add failed: {}", add.stderr);
    assert!(
        add.stdout
            .contains("also declared this workspace's own identity"),
        "`role add` appended a declaration the operator did not ask for and did not \
         mention it: {}",
        add.stdout
    );
    assert!(
        add.stdout.contains(&workspace_did),
        "the report must name the identity it declared, not merely that it did: {}",
        add.stdout
    );

    // Path 2: `import` from a legacy file that does not name this workspace.
    let dir2 = workspace_with_own_identity();
    let workspace_did2 = did_of(dir2.path(), None);
    std::fs::write(
        dir2.path().join(".kan/roles"),
        "did:key:zDnaeSezF2t8gTQrOFpVmvSMPFsxqRDzZL6JGjTxjJ2TvNqYe\treviewer\t/gone\n",
    )
    .unwrap();
    let import = kan_as(dir2.path(), None, &["identity", "role", "import"]);
    assert!(import.ok, "import failed: {}", import.stderr);
    assert!(
        import
            .stdout
            .contains("also declared this workspace's own identity"),
        "`import` declared this workspace and did not say so: {}",
        import.stdout
    );
    assert!(
        import.stdout.contains(&workspace_did2),
        "the report must name the identity it declared: {}",
        import.stdout
    );

    // And it must NOT claim an auto-declaration that did not happen: a second
    // `role add`, with the workspace already declared, appends nothing extra.
    let again = kan_as(dir.path(), None, &["identity", "role", "add", "reviewer"]);
    assert!(again.ok, "{}", again.stderr);
    assert!(
        !again
            .stdout
            .contains("also declared this workspace's own identity"),
        "reported an auto-declaration on a workspace that was already declared: {}",
        again.stdout
    );
}

/// **Round 4, BLOCKING-1.** `kan identity adopt` must leave the **adopted**
/// identity declared, not only the registry it carried across.
///
/// Adopt is the third writer of role declarations, and the one caller that
/// never asked the shared rule. Carrying the previous identity's registry
/// leaves the workspace declaring roles while its own new identity is
/// undeclared — unless the adopted key happens to be one of the carried roles.
/// Then `role list` prints `active: <A>` above a list without `A`, and
/// `--trust roles` drops every claim `A` ever wrote and every one it writes
/// from then on, while adopt reports success.
///
/// Reachable with no hand-editing: an agent key writes here via
/// `KAN_IDENTITY_FILE`, the workspace key later becomes unreachable, and the
/// operator adopts the agent key — which is #90's flow, the one adopt exists
/// for.
///
/// The lesson above the defect: extracting a shared rule for two callers does
/// not find the third. Three rounds fixed one caller each; a fourth, scoped at
/// the rule rather than at a diff, found the caller nobody had looked at.
#[test]
fn adopt_leaves_the_adopted_identity_declared() {
    let dir = workspace_with_own_identity();
    let add = kan_as(dir.path(), None, &["identity", "role", "add", "reviewer"]);
    assert!(add.ok, "{}", add.stderr);

    // An agent key that writes here and is then NOT among the declared roles.
    let agent = dir.path().join("agent-key");
    let declared_agent = kan_as(
        dir.path(),
        None,
        &[
            "identity",
            "role",
            "add",
            "agent",
            "--key",
            agent.to_str().unwrap(),
        ],
    );
    assert!(declared_agent.ok, "{}", declared_agent.stderr);
    assert!(
        kan_as(
            dir.path(),
            Some(&agent),
            &["observe", "shared", "the agent's claim"]
        )
        .ok
    );
    let adopted_did = did_of(dir.path(), Some(&agent));

    // Retract the agent's own declaration, so the key being adopted is not in
    // the set that gets carried.
    let shown = kan_as(dir.path(), None, &["show", "role/agent", "--json"]);
    assert!(shown.ok, "{}", shown.stderr);
    let view: serde_json::Value = serde_json::from_str(&shown.stdout).unwrap();
    let cid = view["claims"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["kind"] == "RoleDeclaration")
        .expect("the agent role should have a declaration")["cid"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(kan_as(dir.path(), None, &["retract", &cid]).ok);
    assert!(
        !declared_dids(dir.path()).contains(&adopted_did),
        "precondition: the key about to be adopted must be undeclared, or this test \
         proves nothing"
    );

    let adopt = kan_as(
        dir.path(),
        None,
        &["identity", "adopt", "--key", agent.to_str().unwrap()],
    );
    assert!(adopt.ok, "adopt failed: {}", adopt.stderr);

    let declared = declared_dids(dir.path());
    assert!(
        declared.contains(&adopted_did),
        "adopt left the identity it adopted undeclared: {declared:?}\n{}",
        adopt.stdout
    );

    // And the claims it had already written are visible under `--trust roles`.
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
        authors.contains(&adopted_did),
        "`--trust roles` lost the adopted identity's own claims: {view}"
    );

    // Said out loud, like the other two paths.
    assert!(
        adopt.stdout.contains("also declared the adopted identity"),
        "adopt declared the adopted identity without saying so: {}",
        adopt.stdout
    );
}

//! `.design/identity-surface.md` REQ-5 and REQ-9 — the four things `--trust`
//! now distinguishes, and the difference between two of them.
//!
//! `local` (the default: every author in the log), `me` (the active identity
//! alone), `roles` (only what was declared), and `role:<name>` (one declared
//! role, named rather than spelled as a 56-character DID). A bare
//! `did:key:...` is unchanged.
//!
//! **`roles` narrowed, and that is the point.** ADR-61 widened it to include
//! the active identity because omitting it gave the wrong answer to the
//! obvious question — "show me everything this workspace's own identities
//! wrote" would quietly drop the caller's own claims. Under `Local` the
//! *default* answers that question, so `roles` is free to mean exactly what
//! its name says. That is what makes `local` minus `roles` computable, which
//! is REQ-9: the authors present in this log but never declared.

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

/// A workspace with a primary identity and one declared role, both having
/// written to the same subject.
///
/// Note that `kan identity role add` registers the **primary too**, under the
/// name `primary` — so in this workspace `roles` and `local` coincide. That
/// is correct and worth knowing: the narrowing REQ-5 describes is only
/// observable where an author wrote *without* being declared, which is what
/// [`undeclared_workspace`] builds.
struct Workspace {
    dir: tempfile::TempDir,
    primary: std::path::PathBuf,
    role: std::path::PathBuf,
}

impl Workspace {
    fn new() -> Self {
        let dir = git_repo();
        let primary = dir.path().join("primary-key");
        { std::fs::create_dir_all(primary.parent().unwrap()).unwrap(); kan::sign::Identity::generate().save(&primary).unwrap(); }
        let role = dir.path().join("keys/prover");
        { std::fs::create_dir_all(role.parent().unwrap()).unwrap(); kan::sign::Identity::generate().save(&role).unwrap(); }

        let wrote = kan(
            dir.path(),
            Some(&primary),
            &["observe", "the primary's claim", "--subject", "finding"],
        );
        assert!(wrote.ok, "primary write failed: {}", wrote.stderr);

        let added = kan(
            dir.path(),
            Some(&primary),
            &[
                "identity",
                "role",
                "add",
                "prover",
                "--key",
                role.to_str().unwrap(),
            ],
        );
        assert!(added.ok, "role add failed: {}", added.stderr);

        let wrote = kan(
            dir.path(),
            Some(&role),
            &["observe", "the prover's claim", "--subject", "finding"],
        );
        assert!(wrote.ok, "role write failed: {}", wrote.stderr);

        Self { dir, primary, role }
    }

    fn path(&self) -> &std::path::Path {
        self.dir.path()
    }

    fn show(&self, key: &std::path::Path, args: &[&str]) -> serde_json::Value {
        let mut full = vec!["show", "finding", "--json"];
        full.extend_from_slice(args);
        let run = kan(self.path(), Some(key), &full);
        assert!(run.ok, "kan {full:?} failed: {}", run.stderr);
        serde_json::from_str(&run.stdout).expect("--json did not emit valid JSON")
    }

    fn texts(&self, key: &std::path::Path, args: &[&str]) -> Vec<String> {
        let mut out: Vec<String> = self.show(key, args)["claims"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c["text"].as_str().map(str::to_string))
            .collect();
        out.sort();
        out
    }

    fn did(&self, key: &std::path::Path) -> String {
        kan(self.path(), Some(key), &["identity", "did"]).stdout
    }
}

/// AC-7, first half: each selector returns exactly the set its name claims.
#[test]
fn each_selector_returns_the_set_its_name_claims() {
    let ws = Workspace::new();
    let both = vec![
        "the primary's claim".to_string(),
        "the prover's claim".to_string(),
    ];

    // `local` is the default, and naming it explicitly means the same thing.
    assert_eq!(
        ws.texts(&ws.primary, &[]),
        both,
        "the default is not `local`"
    );
    assert_eq!(ws.texts(&ws.primary, &["--trust", "local"]), both);
    assert_eq!(
        ws.show(&ws.primary, &["--trust", "local"])["trust"]["base"],
        "Local"
    );

    // `me` is the active identity alone -- and it depends on who is running,
    // which is exactly what distinguishes it from every other selector here.
    assert_eq!(
        ws.texts(&ws.primary, &["--trust", "me"]),
        vec!["the primary's claim".to_string()]
    );
    assert_eq!(
        ws.texts(&ws.role, &["--trust", "me"]),
        vec!["the prover's claim".to_string()]
    );
    assert_eq!(
        ws.show(&ws.primary, &["--trust", "me"])["trust"]["base"],
        "Solo",
        "a lone `me` is the narrow single-author frame, and should say so"
    );

    // `roles` is exactly what `.kan/roles` declares -- which here is both,
    // because `role add` registers the primary alongside the new role. The
    // v0.11 change is that it is now ONLY that, with no active identity
    // injected on top; `undeclared_reader_is_not_silently_included` is where
    // that becomes visible.
    assert_eq!(
        ws.texts(&ws.primary, &["--trust", "roles"]),
        both,
        "`roles` should be exactly the declared set, which includes the auto-declared primary"
    );

    // `role:<name>` names one of them, without pasting a DID.
    assert_eq!(
        ws.texts(&ws.primary, &["--trust", "role:prover"]),
        vec!["the prover's claim".to_string()]
    );

    // And a bare DID still works, unchanged.
    let prover_did = ws.did(&ws.role);
    assert_eq!(
        ws.texts(&ws.primary, &["--trust", &prover_did]),
        vec!["the prover's claim".to_string()]
    );
}

/// A workspace with two authors and **no roles declared at all** — the
/// #90/#136 shape.
///
/// Both keys are minted while the log is empty, which is the one way a second
/// identity gets in without being declared (the `WouldMintSecondIdentity`
/// guard refuses it afterwards). That is exactly how the reported cases
/// arose: an upgrade or a moved checkout re-minted before anything had been
/// written under the new key.
fn undeclared_workspace() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = git_repo();
    let a = dir.path().join("key-a");
    { std::fs::create_dir_all(a.parent().unwrap()).unwrap(); kan::sign::Identity::generate().save(&a).unwrap(); }
    let b = dir.path().join("key-b");
    { std::fs::create_dir_all(b.parent().unwrap()).unwrap(); kan::sign::Identity::generate().save(&b).unwrap(); }
    for key in [&a, &b] {
        assert!(kan(dir.path(), Some(key), &["identity", "did"]).ok);
    }
    for (key, text) in [(&a, "written by a"), (&b, "written by b")] {
        let run = kan(
            dir.path(),
            Some(key),
            &["observe", text, "--subject", "finding"],
        );
        assert!(run.ok, "setup write failed: {}", run.stderr);
    }
    (dir, a, b)
}

/// AC-7, second half / REQ-9: `local` minus `roles` is exactly the undeclared
/// authors, and that difference is reachable from the CLI.
#[test]
fn local_minus_roles_is_the_undeclared_authors_and_the_cli_says_so() {
    let (dir, a, b) = undeclared_workspace();

    let show = |args: &[&str]| -> serde_json::Value {
        let mut full = vec!["show", "finding", "--json"];
        full.extend_from_slice(args);
        let run = kan(dir.path(), Some(&a), &full);
        assert!(run.ok, "kan {full:?} failed: {}", run.stderr);
        serde_json::from_str(&run.stdout).unwrap()
    };

    let local = show(&["--trust", "local"]);
    assert_eq!(
        local["claims"].as_array().unwrap().len(),
        2,
        "both authors wrote to this log: {local}"
    );

    // Nothing was ever declared, so `roles` is empty -- and an empty frame
    // shows nothing rather than quietly falling back to something wider.
    let roles = show(&["--trust", "roles"]);
    assert_eq!(
        roles["claims"].as_array().unwrap().len(),
        0,
        "`roles` returned claims in a workspace with no declared roles: {roles}"
    );
    assert_eq!(
        roles["excluded_by_trust"], 2,
        "an empty frame must still disclose what it excluded: {roles}"
    );

    // REQ-9: the same fact, stated positively, from the CLI.
    let did_of = |key: &std::path::Path| kan(dir.path(), Some(key), &["identity", "did"]).stdout;
    let (did_a, did_b) = (did_of(&a), did_of(&b));

    let listed = kan(dir.path(), Some(&a), &["identity", "authors"]);
    assert!(listed.ok, "kan identity authors failed: {}", listed.stderr);
    assert!(
        listed.stdout.contains(&did_a) && listed.stdout.contains(&did_b),
        "not every log author was listed: {}",
        listed.stdout
    );
    assert!(
        listed.stdout.contains("UNDECLARED"),
        "the undeclared authors were not flagged: {}",
        listed.stdout
    );

    let json = kan(dir.path(), Some(&a), &["identity", "authors", "--json"]);
    assert!(json.ok, "{}", json.stderr);
    let v: serde_json::Value = serde_json::from_str(&json.stdout).unwrap();
    let authors = v["authors"].as_array().unwrap();
    assert_eq!(authors.len(), 2, "expected both log authors: {v}");
    assert!(
        authors.iter().all(|a| a["declared"] == false),
        "no role was ever declared here, so every author must report undeclared -- \
         reporting otherwise would hide exactly the #90/#136 anomaly this exists for: {v}"
    );
}

/// The v0.11 narrowing, stated where it is observable: `--trust roles` read
/// by an **undeclared** identity does not silently include that identity.
///
/// Until v0.11 `roles` expanded to the declared set *plus the active one*, so
/// a read by an identity nobody had declared quietly counted itself as a
/// role. Under `Local` the default already answers "everything this workspace
/// wrote", so `roles` no longer has to over-report to be useful -- and an
/// undeclared identity reading `roles` now gets an answer about declarations
/// rather than an answer about itself.
#[test]
fn an_undeclared_reader_is_not_silently_included_in_roles() {
    let dir = git_repo();
    let primary = dir.path().join("primary-key");
    { std::fs::create_dir_all(primary.parent().unwrap()).unwrap(); kan::sign::Identity::generate().save(&primary).unwrap(); }
    let stranger = dir.path().join("stranger-key");
    // Both minted while the log is empty, so neither trips the guard.
    for key in [&primary, &stranger] {
        assert!(kan(dir.path(), Some(key), &["identity", "did"]).ok);
    }
    for (key, text) in [
        (&primary, "the primary's claim"),
        (&stranger, "the stranger's claim"),
    ] {
        let run = kan(
            dir.path(),
            Some(key),
            &["observe", text, "--subject", "finding"],
        );
        assert!(run.ok, "setup write failed: {}", run.stderr);
    }
    // Declaring any role registers the primary too, but never the stranger.
    let role_key = dir.path().join("keys/prover");
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

    // Read as the stranger, asking for the declared roles.
    let run = kan(
        dir.path(),
        Some(&stranger),
        &["show", "finding", "--json", "--trust", "roles"],
    );
    assert!(run.ok, "{}", run.stderr);
    let v: serde_json::Value = serde_json::from_str(&run.stdout).unwrap();
    let texts: Vec<&str> = v["claims"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["text"].as_str())
        .collect();
    assert!(
        !texts.contains(&"the stranger's claim"),
        "`roles` included the reading identity, which nobody declared: {v}"
    );
    assert!(
        texts.contains(&"the primary's claim"),
        "`roles` dropped an identity that WAS declared: {v}"
    );
}

/// A selector that names nothing is an error, never a silently narrower view.
///
/// Silently dropping one `--trust` argument hands back a view narrower than
/// the one asked for, with an exit code saying it succeeded -- the failure
/// this whole surface exists to end.
#[test]
fn an_unresolvable_selector_fails_rather_than_narrowing() {
    let ws = Workspace::new();

    let run = kan(
        ws.path(),
        Some(&ws.primary),
        &["show", "finding", "--trust", "role:nobody"],
    );
    assert!(
        !run.ok,
        "an undeclared role name was accepted: {}",
        run.stdout
    );
    assert!(
        run.stderr.contains("prover"),
        "the error should name the roles that do exist: {}",
        run.stderr
    );

    // A weight on a set-valued alias has no meaning and is refused rather
    // than quietly ignored.
    for spec in ["roles=0.5", "local=0.5"] {
        let run = kan(
            ws.path(),
            Some(&ws.primary),
            &["show", "finding", "--trust", spec],
        );
        assert!(!run.ok, "`{spec}` was accepted: {}", run.stdout);
        assert!(
            run.stderr.contains("takes no weight"),
            "`{spec}` should explain itself: {}",
            run.stderr
        );
    }
}

/// `role:<name>` takes a weight, because unlike `roles` and `local` it names
/// exactly one author -- so it composes with the weighted surface rather
/// than being a special case bolted beside it.
#[test]
fn a_named_role_composes_with_weights() {
    let ws = Workspace::new();
    let view = ws.show(
        &ws.primary,
        &["--trust", "role:prover=0.25", "--trust", "me"],
    );
    assert_eq!(view["trust"]["base"], "PeerContested");
    let authors = view["trust"]["authors"].as_array().unwrap();
    assert_eq!(
        authors.len(),
        2,
        "expected both authors in the frame: {view}"
    );
    let weight_of = |did: &str| -> f64 {
        authors
            .iter()
            .find(|a| a["did"] == did)
            .unwrap_or_else(|| panic!("{did} missing"))["weight"]
            .as_f64()
            .unwrap()
    };
    assert_eq!(weight_of(&ws.did(&ws.role)), 0.25);
    assert_eq!(weight_of(&ws.did(&ws.primary)), 1.0);
}

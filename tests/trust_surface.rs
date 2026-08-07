//! `.design/v0.8-milestone.md` REQ-3/AC-3 — the `PeerContested` trust base,
//! reachable from a read surface rather than only constructible in the
//! library, and the disclosure that comes with it.
//!
//! These run the real binary as a subprocess, because that is the only way
//! the properties `day` needs are actually checked: day executes `kan` and
//! parses `--json` (ADR-42), so a library-level test would validate kan
//! against kan's own idea of its CLI. The ACs mirrored here are
//! `.design/kan-read-contract.md`'s, stated by the consumer while the shape
//! was still open.

use std::process::Command;

/// Two identities in one workspace, both key files created **while the log
/// is empty**. That ordering is load-bearing: the `WouldMintSecondIdentity`
/// guard fires on a second identity's first reference to a *non-empty* log,
/// so a role created later is refused. Lifting that restriction is REQ-4's
/// job (`tests/multi_role.rs`); this file takes the narrow path that already
/// works so the trust surface can be tested independently of it.
struct Roles {
    dir: tempfile::TempDir,
    prover: std::path::PathBuf,
    director: std::path::PathBuf,
}

fn kan_as(dir: &std::path::Path, key: Option<&std::path::Path>, args: &[&str]) -> (String, bool) {
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
    (
        String::from_utf8_lossy(&output.stdout).trim().to_string(),
        output.status.success(),
    )
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

impl Roles {
    fn new() -> Self {
        let dir = git_repo();
        let prover = dir.path().join("keys/prover");
        {
            std::fs::create_dir_all(prover.parent().unwrap()).unwrap();
            kan::sign::Identity::generate().save(&prover).unwrap();
        }
        let director = dir.path().join("keys/director");
        {
            std::fs::create_dir_all(director.parent().unwrap()).unwrap();
            kan::sign::Identity::generate().save(&director).unwrap();
        }
        // Mint both before either writes, per the struct doc.
        for key in [&prover, &director] {
            let (_, ok) = kan_as(dir.path(), Some(key), &["identity", "did"]);
            assert!(ok, "minting {} failed", key.display());
        }
        Self {
            dir,
            prover,
            director,
        }
    }

    fn path(&self) -> &std::path::Path {
        self.dir.path()
    }

    fn did(&self, key: &std::path::Path) -> String {
        let (did, ok) = kan_as(self.path(), Some(key), &["identity", "did"]);
        assert!(ok);
        did
    }

    fn show_json(&self, key: &std::path::Path, args: &[&str]) -> serde_json::Value {
        let mut full = vec!["show"];
        full.extend_from_slice(args);
        full.push("--json");
        let (out, ok) = kan_as(self.path(), Some(key), &full);
        assert!(ok, "kan {full:?} failed: {out}");
        serde_json::from_str(&out).expect("show --json did not emit valid JSON")
    }
}

/// AC-3, and `.design/kan-read-contract.md` AC-1: a read naming two authors
/// returns both their claims — and since v0.11, so does the read with no
/// selector at all.
///
/// The unselected half used to be `Solo`, where each role saw
/// `1 live claim(s)` and nothing said the other's existed. v0.8 made that
/// visible by disclosing the exclusion; v0.11 removes it by making the
/// default `Local`. `--trust me` is what still shows one.
#[test]
fn an_explicit_pair_and_the_default_both_show_both_roles() {
    let roles = Roles::new();
    let prover_did = roles.did(&roles.prover);
    let director_did = roles.did(&roles.director);
    assert_ne!(
        prover_did, director_did,
        "roles must be distinct identities"
    );

    let (_, ok) = kan_as(
        roles.path(),
        Some(&roles.prover),
        &["observe", "claim-1", "the prover's finding"],
    );
    assert!(ok);
    let (_, ok) = kan_as(
        roles.path(),
        Some(&roles.director),
        &["observe", "claim-1", "the director's verdict"],
    );
    assert!(ok);

    // No selector (`Local`): both claims, because both authors wrote here.
    let default = roles.show_json(&roles.prover, &["claim-1"]);
    let default_authors: Vec<&str> = default["claims"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["author"].as_str().unwrap())
        .collect();
    assert_eq!(
        default_authors.len(),
        2,
        "the default read dropped a log author's claim: {default}"
    );
    assert!(default_authors.contains(&prover_did.as_str()));
    assert!(default_authors.contains(&director_did.as_str()));

    // `--trust me`: one claim, the active identity's own -- the old default.
    let mine = roles.show_json(&roles.prover, &["claim-1", "--trust", "me"]);
    assert_eq!(mine["claims"].as_array().unwrap().len(), 1);
    assert_eq!(mine["claims"][0]["author"], prover_did);

    // PeerContested over both: both claims, attributed.
    let both = roles.show_json(
        &roles.prover,
        &["claim-1", "--trust", &prover_did, "--trust", &director_did],
    );
    let authors: Vec<&str> = both["claims"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["author"].as_str().unwrap())
        .collect();
    assert_eq!(authors.len(), 2, "expected both roles' claims: {both}");
    assert!(authors.contains(&prover_did.as_str()));
    assert!(authors.contains(&director_did.as_str()));
}

/// `.design/kan-read-contract.md` AC-3 / REQ-3: the response says which trust
/// base produced it, so a consumer *reads* that kan honoured the frame rather
/// than assuming it. A view that cannot be labelled is one day cannot
/// honestly report on.
#[test]
fn the_view_names_the_trust_base_that_produced_it() {
    let roles = Roles::new();
    let prover_did = roles.did(&roles.prover);
    let director_did = roles.did(&roles.director);
    let (_, ok) = kan_as(
        roles.path(),
        Some(&roles.prover),
        &["observe", "s", "a finding"],
    );
    assert!(ok);

    // v0.11 AC-8: the default names `Local`, and every author it lists is one
    // with a claim in the log. Only the prover has written here, so `Local`
    // and the old `Solo` default report the same single author at the same
    // weight -- the envelope *shape* is unchanged, which is RQ-4's whole
    // point: a new value, not a new field.
    let default = roles.show_json(&roles.prover, &["s"]);
    assert_eq!(default["trust"]["base"], "Local");
    assert_eq!(default["trust"]["authors"].as_array().unwrap().len(), 1);
    assert_eq!(default["trust"]["authors"][0]["did"], prover_did);
    assert_eq!(default["trust"]["authors"][0]["weight"], 1.0);
    assert_ne!(
        default["trust"]["authors"][0]["did"], director_did,
        "the director has written nothing here and must not be in Local"
    );

    // `--trust me` still resolves to the active identity alone, so the narrow
    // frame remains reachable and its author set is still exact. Which
    // *variant name* that frame reports is REQ-5's question, not this one's.
    let mine = roles.show_json(&roles.prover, &["s", "--trust", "me"]);
    assert_eq!(mine["trust"]["authors"].as_array().unwrap().len(), 1);
    assert_eq!(mine["trust"]["authors"][0]["did"], prover_did);

    // Weights, not a membership set: a role hierarchy is a weighting, and a
    // surface accepting only a set of authors would be a narrower thing
    // wearing the same name.
    let weighted = roles.show_json(
        &roles.prover,
        &[
            "s",
            "--trust",
            &format!("{prover_did}=0.25"),
            "--trust",
            &format!("{director_did}=1.0"),
        ],
    );
    assert_eq!(weighted["trust"]["base"], "PeerContested");
    let authors = weighted["trust"]["authors"].as_array().unwrap();
    assert_eq!(authors.len(), 2);
    let weight_of = |did: &str| -> f64 {
        authors
            .iter()
            .find(|a| a["did"] == did)
            .unwrap_or_else(|| panic!("{did} missing from the declared trust base"))["weight"]
            .as_f64()
            .unwrap()
    };
    assert_eq!(weight_of(&prover_did), 0.25);
    assert_eq!(weight_of(&director_did), 1.0);

    // The two responses differ in a field day can read, not merely in day's
    // memory of what it asked for.
    assert_ne!(default["trust"], weighted["trust"]);
}

/// `.design/kan-read-contract.md` AC-2 / REQ-2: trust selection is
/// per-invocation. Two reads in one session naming different author sets
/// each get the set they named, in either order, with no intervening
/// configuration command — so comparing one subject under two frames is two
/// reads rather than a sequence of mutations.
#[test]
fn trust_selection_is_per_invocation_not_workspace_state() {
    let roles = Roles::new();
    let prover_did = roles.did(&roles.prover);
    let director_did = roles.did(&roles.director);
    for (key, text) in [
        (&roles.prover, "prover says"),
        (&roles.director, "director says"),
    ] {
        let (_, ok) = kan_as(roles.path(), Some(key), &["observe", "s", text]);
        assert!(ok);
    }

    let narrow = |did: &str| -> usize {
        roles.show_json(&roles.prover, &["s", "--trust", did])["claims"]
            .as_array()
            .unwrap()
            .len()
    };
    let wide = || -> usize {
        roles.show_json(
            &roles.prover,
            &["s", "--trust", &prover_did, "--trust", &director_did],
        )["claims"]
            .as_array()
            .unwrap()
            .len()
    };

    // Interleaved deliberately: a wide read between two narrow ones must not
    // change what either narrow read returns.
    assert_eq!(narrow(&prover_did), 1);
    assert_eq!(wide(), 2);
    assert_eq!(narrow(&director_did), 1);
    assert_eq!(wide(), 2);
    assert_eq!(narrow(&prover_did), 1);
}

/// `.design/kan-read-contract.md` AC-6 / REQ-6: a read discloses that the
/// trust base excluded claims, with the **negative control** that a subject
/// genuinely holding one claim reports no exclusion. The signal has to
/// distinguish *filtered* from *absent*, not warn unconditionally.
///
/// Whether `Solo` is the right default is a separate question (#121); this
/// is the strictly separable half — whatever the default, a consumer must be
/// able to tell that the view it was handed was partial.
#[test]
fn a_narrowed_read_discloses_what_it_excluded() {
    let roles = Roles::new();
    let prover_did = roles.did(&roles.prover);

    // `contested` holds two authors' claims; `alone` holds one.
    for (key, subject, text) in [
        (&roles.prover, "contested", "prover on contested"),
        (&roles.director, "contested", "director on contested"),
        (&roles.prover, "alone", "prover on alone"),
    ] {
        let (_, ok) = kan_as(roles.path(), Some(key), &["observe", subject, text]);
        assert!(ok);
    }

    let contested = roles.show_json(&roles.prover, &["contested", "--trust", &prover_did]);
    assert_eq!(contested["claims"].as_array().unwrap().len(), 1);
    assert_eq!(
        contested["excluded_by_trust"], 1,
        "a filtered view must say so: {contested}"
    );

    // Negative control: same trust base, a subject with nothing to exclude.
    let alone = roles.show_json(&roles.prover, &["alone", "--trust", &prover_did]);
    assert_eq!(alone["claims"].as_array().unwrap().len(), 1);
    assert_eq!(
        alone["excluded_by_trust"], 0,
        "an unfiltered view must not claim exclusions: {alone}"
    );

    // The human surface carries the same disclosure — the reproduction was
    // that `1 live claim(s)` read identically through both channels.
    let (rendered, ok) = kan_as(
        roles.path(),
        Some(&roles.prover),
        &["show", "contested", "--trust", &prover_did],
    );
    assert!(ok);
    assert!(
        rendered.contains("excluded by this view's trust base"),
        "rendered output hid the exclusion: {rendered}"
    );
}

/// The wholly-filtered case: every claim on a subject belongs to an author
/// this base does not trust, so the subject has no merge class at all and
/// `show` reports "no claims".
///
/// This is the sharpest form of the bug — "no claims" and "no such subject"
/// are the same sentence, and a per-class count would report zero because
/// there is no class to count. Hence `fold::excluded_by_trust` keying on the
/// claim's own subject.
#[test]
fn a_subject_filtered_to_nothing_is_distinguishable_from_an_absent_one() {
    let roles = Roles::new();
    let prover_did = roles.did(&roles.prover);
    let (_, ok) = kan_as(
        roles.path(),
        Some(&roles.director),
        &["observe", "directors-only", "only the director wrote here"],
    );
    assert!(ok);

    let filtered = roles.show_json(&roles.prover, &["directors-only", "--trust", &prover_did]);
    assert_eq!(filtered["claims"].as_array().unwrap().len(), 0);
    assert_eq!(
        filtered["excluded_by_trust"], 1,
        "a subject filtered to nothing must not look absent: {filtered}"
    );

    let absent = roles.show_json(&roles.prover, &["never-written", "--trust", &prover_did]);
    assert_eq!(absent["claims"].as_array().unwrap().len(), 0);
    assert_eq!(
        absent["excluded_by_trust"], 0,
        "a genuinely absent subject must not report exclusions: {absent}"
    );
}

/// `.design/kan-read-contract.md` AC-4 / REQ-4: a trust selector is never
/// accepted and ignored. Either it changes the view or the invocation fails
/// — the forbidden outcome is exit 0 carrying the `Solo` view.
///
/// This asks for no feature: clap rejects unknown arguments already. It is
/// asserted so the property cannot later be traded away for a tolerant
/// parameter, which is the single change that would break it.
#[test]
fn a_malformed_trust_selector_fails_rather_than_silently_narrowing() {
    let roles = Roles::new();
    let (_, ok) = kan_as(
        roles.path(),
        Some(&roles.prover),
        &["observe", "s", "a finding"],
    );
    assert!(ok);

    for bad in [
        "not-a-did",          // not an author at all
        "did:key:zTest=2.0",  // weight outside [0,1]
        "did:key:zTest=high", // weight not a number
        "did:key:zTest=-0.5", // negative weight
    ] {
        let (out, ok) = kan_as(
            roles.path(),
            Some(&roles.prover),
            &["show", "s", "--trust", bad],
        );
        assert!(
            !ok,
            "`--trust {bad}` exited 0 -- a selector must never be accepted and ignored: {out}"
        );
    }
}

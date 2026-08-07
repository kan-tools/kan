//! REQ-6 of `.design/v0.12-milestone.md`, second attempt: the cell table
//! **derived** rather than curated.
//!
//! `tests/identity_cells.rs` asserts hand-picked rows. Two consecutive cold
//! reviews each found rows missing from that hand-picked list — first four,
//! then four more, including one the prose had explicitly denied existed. The
//! second review's recommendation, adopted here: *where an enumeration keeps
//! missing cells, derive it rather than curate it harder.*
//!
//! So this file enumerates the **full product** of the dimensions it can
//! construct, runs both resolvers against every configuration, and writes the
//! outcomes to a golden. Completeness stops depending on anyone's care: a
//! configuration is in the table because the loop reached it, not because
//! somebody remembered it.
//!
//! **What it covers.** `KAN_IDENTITY_FILE` (4 states) × `.kan/identity` ×
//! `.kan/identity-id` × `.kan/seed` × `.kan/seed-id` × log empty-or-not —
//! 4 × 16 × 2 = **128 configurations**, each probed twice.
//!
//! **What it cannot cover, and why that is the point.** The keychain
//! dimension is pinned to "disabled": every identity test must set
//! `KAN_NO_KEYCHAIN` or a rebuilt binary blocks forever on a macOS
//! authorization prompt (#96). The keychain-reachable plane — which is where
//! #170 and #180 live — is unreachable from any test in this suite, and no
//! amount of derivation changes that. `.design/identity-resolution-cells.md`
//! carries those rows in prose because prose is the only instrument available.
//! REQ-3 is what moves them here.
//!
//! **Outcomes are symbolic, not DIDs.** Every identity in a fixture is
//! randomly minted, so the golden records *which artifact* the resolved key
//! came from — `identity`, `seed`, `override` — computed by deriving each
//! artifact's DID after the probe and matching. That keeps the document
//! stable across runs while still distinguishing the case that matters: the
//! two resolvers picking *different* artifacts.
//!
//! Regenerate deliberately, never reflexively:
//!
//! ```text
//! UPDATE_GOLDEN=1 cargo test --test derived_cells
//! ```

mod common;

use common::{compare_or_update, git_repo, kan_as};
use std::path::{Path, PathBuf};

use kan::sign::{Identity, Seed};

const GOLDEN: &str = "tests/fixtures/golden/derived-cells.txt";

/// One point in the product.
#[derive(Clone, Copy)]
struct Config {
    env: Env,
    identity: bool,
    identity_id: bool,
    seed: bool,
    seed_id: bool,
    log_has_claims: bool,
}

#[derive(Clone, Copy, PartialEq)]
enum Env {
    Unset,
    Exists,
    Missing,
    MissingDeclared,
}

impl Env {
    fn label(self) -> &'static str {
        match self {
            Env::Unset => "unset",
            Env::Exists => "exists",
            Env::Missing => "missing",
            Env::MissingDeclared => "missing-declared",
        }
    }
}

fn all_configs() -> Vec<Config> {
    let mut out = Vec::new();
    for env in [Env::Unset, Env::Exists, Env::Missing, Env::MissingDeclared] {
        for bits in 0u8..16 {
            for log_has_claims in [false, true] {
                out.push(Config {
                    env,
                    identity: bits & 1 != 0,
                    identity_id: bits & 2 != 0,
                    seed: bits & 4 != 0,
                    seed_id: bits & 8 != 0,
                    log_has_claims,
                });
            }
        }
    }
    out
}

impl Config {
    fn label(&self) -> String {
        fn flag(b: bool, name: &'static str) -> &'static str {
            if b {
                name
            } else {
                "-"
            }
        }
        format!(
            "env={:<16} identity={:<8} id={:<2} seed={:<4} seed-id={:<7} log={}",
            self.env.label(),
            flag(self.identity, "identity"),
            flag(self.identity_id, "id"),
            flag(self.seed, "seed"),
            flag(self.seed_id, "seed-id"),
            if self.log_has_claims {
                "claims"
            } else {
                "empty "
            }
        )
    }
}

/// A built workspace, plus the paths whose DIDs the outcome is matched against.
struct Built {
    dir: tempfile::TempDir,
    env_path: Option<PathBuf>,
}

impl Built {
    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn new(cfg: &Config) -> Self {
        let dir = git_repo();
        let kan_dir = dir.path().join(".kan");

        if cfg.log_has_claims {
            // A throwaway identity named by the environment, so seeding the
            // log touches none of the four artifacts under test.
            // The key is created explicitly: REQ-2 means naming a missing
            // path is an error, not a way to mint one.
            let writer = dir.path().join("keys/log-writer");
            std::fs::create_dir_all(writer.parent().unwrap()).unwrap();
            Identity::generate().save(&writer).unwrap();
            let (_, stderr, ok) = kan_as(
                dir.path(),
                Some(&writer),
                &["observe", "seeded by the fixture", "--subject", "cell"],
            );
            assert!(ok, "seeding the log failed: {stderr}");
        }
        std::fs::create_dir_all(&kan_dir).unwrap();

        if cfg.identity {
            Identity::generate()
                .save(&kan_dir.join("identity"))
                .unwrap();
        }
        if cfg.identity_id {
            std::fs::write(kan_dir.join("identity-id"), "kan-fixture-account").unwrap();
        }
        if cfg.seed {
            Seed::load_or_create(&kan_dir.join("seed")).unwrap();
        }
        if cfg.seed_id {
            std::fs::write(kan_dir.join("seed-id"), "kan-fixture-seed-account").unwrap();
        }

        let env_path = match cfg.env {
            Env::Unset => None,
            Env::Exists => {
                let p = dir.path().join("keys/override");
                std::fs::create_dir_all(p.parent().unwrap()).unwrap();
                Identity::generate().save(&p).unwrap();
                Some(p)
            }
            Env::Missing => Some(dir.path().join("keys/absent")),
            Env::MissingDeclared => {
                let p = dir.path().join("keys/absent-role");
                std::fs::write(
                    kan_dir.join("roles"),
                    format!("did:key:zFixtureRoleDid\tprover\t{}\n", p.display()),
                )
                .unwrap();
                Some(p)
            }
        };

        Built { dir, env_path }
    }

    /// Which artifact currently on disk derives to `did`.
    ///
    /// Computed *after* the probe, so a key the write just minted is matched
    /// the same way a pre-existing one is — which is what lets one symbol
    /// cover both "resolved the existing key" and "minted and signed with it".
    fn artifact_for(&self, did: &str) -> String {
        let kan_dir = self.path().join(".kan");
        let mut candidates: Vec<(&str, Option<String>)> = Vec::new();

        candidates.push((
            "identity",
            Identity::load_existing(&kan_dir.join("identity"))
                .ok()
                .map(|i| i.did()),
        ));
        // Existence is checked BEFORE loading, because `Seed::load_or_create`
        // creates the file when it is absent. Filtering afterwards -- which is
        // what this did first -- means the instrument writes a `.kan/seed`
        // into the very workspace whose `.kan/` layout it is measuring. It
        // happened to be inert (a freshly generated seed cannot match a DID
        // that already signed) but a measurement with a side effect is the
        // exact shape this milestone exists to remove from resolution.
        let seed_path = kan_dir.join("seed");
        candidates.push((
            "seed",
            seed_path
                .exists()
                .then(|| Seed::load_or_create(&seed_path).ok())
                .flatten()
                .and_then(|s| s.signing_identity().ok())
                .map(|i| i.did()),
        ));
        if let Some(p) = &self.env_path {
            candidates.push(("override", Identity::load_existing(p).ok().map(|i| i.did())));
        }

        for (name, candidate) in candidates {
            if candidate.as_deref() == Some(did) {
                return name.to_string();
            }
        }
        "UNMATCHED".to_string()
    }
}

/// What the read resolver said, symbolically.
fn read_outcome(built: &Built) -> String {
    let (stdout, stderr, ok) = kan_as(
        built.path(),
        built.env_path.as_deref(),
        &["show", "cell", "--trust", "me", "--json"],
    );
    if !ok {
        if stderr.contains("nothing for `me` to name") {
            return "none".to_string();
        }
        if stderr.contains("which does not exist") {
            return "selection-missing".to_string();
        }
        if stderr.contains("has no key at") {
            return "role-key-missing".to_string();
        }
        return "error".to_string();
    }
    let v: serde_json::Value = match serde_json::from_str(&stdout) {
        Ok(v) => v,
        Err(_) => return "error".to_string(),
    };
    match v["trust"]["authors"][0]["did"].as_str() {
        Some(did) => format!("resolved:{}", built.artifact_for(did)),
        None => "none".to_string(),
    }
}

/// What the write resolver did, symbolically — including which artifact the
/// signature actually traces back to.
fn write_outcome(built: &Built) -> String {
    let (_, stderr, ok) = kan_as(
        built.path(),
        built.env_path.as_deref(),
        &["observe", "the write probe", "--subject", "probe"],
    );
    if !ok {
        if stderr.contains("this repo already has an identity") {
            return "refused:guard".to_string();
        }
        if stderr.contains("has no key at") {
            return "refused:role-key-missing".to_string();
        }
        if stderr.contains("which does not exist") {
            return "refused:selection-missing".to_string();
        }
        return "refused:other".to_string();
    }
    let (out, _, ok) = kan_as(
        built.path(),
        built.env_path.as_deref(),
        &["show", "probe", "--json"],
    );
    if !ok {
        return "signed:UNREADABLE".to_string();
    }
    let v: serde_json::Value = match serde_json::from_str(&out) {
        Ok(v) => v,
        Err(_) => return "signed:UNREADABLE".to_string(),
    };
    match v["claims"][0]["author"].as_str() {
        Some(did) => format!("signed:{}", built.artifact_for(did)),
        None => "signed:UNREADABLE".to_string(),
    }
}

/// Both probes over one configuration, on **separate** workspaces — the read
/// is not side-effect free (`tests/identity_cells.rs`), so sharing one would
/// let the read's mutations reach the write.
fn probe(cfg: &Config) -> (String, String) {
    let read = read_outcome(&Built::new(cfg));
    let write = write_outcome(&Built::new(cfg));
    (read, write)
}

/// The derived table.
///
/// Split across four `#[test]`s by `KAN_IDENTITY_FILE` state so the harness
/// runs them in parallel — 128 configurations × 2 workspaces is otherwise a
/// long serial stretch. Each writes its own golden section.
fn run_plane(env: Env, golden: &str) {
    let mut doc = String::new();
    doc.push_str(&format!(
        "# derived cell table -- KAN_IDENTITY_FILE={}\n\
         # keychain: DISABLED for every row (KAN_NO_KEYCHAIN); the reachable-keychain\n\
         # plane is unreachable from this suite (#96) and lives in prose instead.\n\n",
        env.label()
    ));
    for cfg in all_configs().into_iter().filter(|c| c.env == env) {
        let (read, write) = probe(&cfg);
        doc.push_str(&format!(
            "{}  ->  read={:<20} write={}\n",
            cfg.label(),
            read,
            write
        ));
    }
    compare_or_update(
        golden,
        &doc,
        "a derived cell outcome changed.\n\n\
         This table is GENERATED by enumerating the product of the dimensions, not \
         curated -- so a diff here is a real change in what identity resolution does, \
         for a configuration nobody had to remember to list. Accept it with \
         `UPDATE_GOLDEN=1` in a commit that names the requirement it belongs to, and \
         read every changed line: `resolved:` and `signed:` name WHICH artifact the key \
         traces to, so a line changing from `resolved:identity` to `resolved:override` \
         is a misattribution, not a cosmetic move.",
    );
}

#[test]
fn derived_plane_env_unset() {
    run_plane(Env::Unset, "tests/fixtures/golden/derived-cells-unset.txt");
}

#[test]
fn derived_plane_env_exists() {
    run_plane(
        Env::Exists,
        "tests/fixtures/golden/derived-cells-exists.txt",
    );
}

#[test]
fn derived_plane_env_missing() {
    run_plane(
        Env::Missing,
        "tests/fixtures/golden/derived-cells-missing.txt",
    );
}

#[test]
fn derived_plane_env_missing_declared() {
    run_plane(
        Env::MissingDeclared,
        "tests/fixtures/golden/derived-cells-missing-declared.txt",
    );
}

/// The enumeration is the whole claim, so assert its size directly: if a
/// dimension is ever added to `Config` without extending `all_configs`, this
/// fails rather than silently shrinking the table.
#[test]
fn the_product_is_fully_enumerated() {
    let configs = all_configs();
    assert_eq!(
        configs.len(),
        4 * 16 * 2,
        "the enumeration no longer covers the full product of its dimensions"
    );
    let mut seen = std::collections::HashSet::new();
    for c in &configs {
        assert!(
            seen.insert(c.label()),
            "duplicate configuration in the enumeration: {}",
            c.label()
        );
    }
}

/// Unused in the golden path, but keeps `GOLDEN` meaningful as the documented
/// entry point for the four section files.
#[allow(dead_code)]
const _: &str = GOLDEN;

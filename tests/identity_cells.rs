//! REQ-6 / AC-3 of `.design/v0.12-milestone.md`: one assertion per reachable
//! cell of identity resolution, against **both** resolvers.
//!
//! The table this pins is `.design/identity-resolution-cells.md`. Read that
//! first — it is the map, this is the check that the map matches the ground.
//!
//! **Why both probes.** Question 1 has two implementations today
//! (`.design/identity-resolution.md` Consequence 3), so a cell has two
//! answers and the interesting ones are where they differ:
//!
//! - the **read** probe is `kan show <subject> --trust me --json`, which
//!   calls `sign::existing_identity` and cannot mint;
//! - the **write** probe is `kan observe`, which calls
//!   `Workspace::commit_identity` → `Identity::load_or_create_for_workspace`.
//!
//! Note that `kan identity did` is a *write*-path command
//! (`src/cli/mod.rs:846`), which is exactly why #170 reads as "`identity did`
//! resolves fine but `--trust me` does not". Using it as a read probe would
//! assert nothing about the read path. Nine v0.11 tests had to change probe
//! rather than expectation for the mirror-image reason.
//!
//! **Everything here runs under `KAN_NO_KEYCHAIN`**, because a rebuilt binary
//! blocks forever on a macOS authorization prompt (#96) and a suite that hangs
//! locally while passing in CI is worse than one that fails. That is also the
//! finding: the cells containing #170 are precisely the cells no test can
//! reach. See the table's "What CI cannot reach".

use std::path::{Path, PathBuf};
use std::process::Command;

use kan::sign::{Identity, Seed};

// ---------------------------------------------------------------- fixtures

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

fn kan(dir: &Path, env: Option<&Path>, args: &[&str]) -> (String, String, bool) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kan"));
    cmd.args(args).current_dir(dir).env("KAN_NO_KEYCHAIN", "1");
    match env {
        Some(p) => {
            cmd.env("KAN_IDENTITY_FILE", p);
        }
        None => {
            cmd.env_remove("KAN_IDENTITY_FILE");
        }
    }
    let out = cmd.output().expect("failed to run kan");
    (
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
        out.status.success(),
    )
}

// ------------------------------------------------------------- cell inputs

/// Which of the four `.kan/` identity artifacts exist before the probe runs.
#[derive(Clone, Copy)]
struct Layout {
    identity: bool,
    identity_id: bool,
    seed: bool,
    seed_id: bool,
}

const NOTHING: Layout = Layout {
    identity: false,
    identity_id: false,
    seed: false,
    seed_id: false,
};
const KEY: Layout = Layout {
    identity: true,
    ..NOTHING
};
const ID: Layout = Layout {
    identity_id: true,
    ..NOTHING
};
const SEED: Layout = Layout {
    seed: true,
    ..NOTHING
};
const SEED_ID: Layout = Layout {
    seed_id: true,
    ..NOTHING
};
const SEED_AND_KEY: Layout = Layout {
    identity: true,
    seed: true,
    ..NOTHING
};
const SEED_ID_AND_KEY: Layout = Layout {
    identity: true,
    seed_id: true,
    ..NOTHING
};
const ID_AND_KEY: Layout = Layout {
    identity: true,
    identity_id: true,
    ..NOTHING
};

#[derive(Clone, Copy, PartialEq)]
enum Env {
    Unset,
    /// `KAN_IDENTITY_FILE` naming a key file that exists.
    Exists,
    /// Naming a path that does not exist.
    Missing,
    /// Naming a path that does not exist, which `.kan/roles` declares.
    MissingDeclared,
}

/// What a probe should produce. `Key`/`Seed`/`Override` name *which* identity,
/// because "it resolved something" is the assertion that cannot fail.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Expect {
    /// The read has no `me` to name, or the write refuses — distinguished by
    /// which probe is asking.
    None_,
    Key,
    SeedDerived,
    Override,
    /// The guard fired: `WouldMintSecondIdentity`.
    Refuses,
    /// Succeeded and left this workspace seed-rooted, having had no identity.
    MintsSeed,
    /// Succeeded by creating `.kan/identity`.
    MintsKeyFile,
    /// Succeeded by creating a key at the `KAN_IDENTITY_FILE` path.
    MintsAtOverride,
    RoleKeyMissing,
}

struct Cell {
    row: u32,
    env: Env,
    layout: Layout,
    log_has_claims: bool,
    read: Expect,
    write: Expect,
}

/// Rows 1–18 of `.design/identity-resolution-cells.md` — every cell reachable
/// with the keychain disabled. Rows 19–23 need a live keychain and are
/// documented rather than tested, which is itself the finding.
fn cells() -> Vec<Cell> {
    use Env::*;
    use Expect::*;
    vec![
        Cell {
            row: 1,
            env: Unset,
            layout: NOTHING,
            log_has_claims: false,
            read: None_,
            write: MintsSeed,
        },
        Cell {
            row: 2,
            env: Unset,
            layout: NOTHING,
            log_has_claims: true,
            read: None_,
            write: Refuses,
        },
        Cell {
            row: 3,
            env: Unset,
            layout: KEY,
            log_has_claims: false,
            read: Key,
            write: Key,
        },
        Cell {
            row: 4,
            env: Unset,
            layout: KEY,
            log_has_claims: true,
            read: Key,
            write: Key,
        },
        // `identity-id` alone makes `fresh` false, so the write falls to the
        // plaintext branch and mints a KEY FILE rather than seed-rooting.
        Cell {
            row: 5,
            env: Unset,
            layout: ID,
            log_has_claims: false,
            read: None_,
            write: MintsKeyFile,
        },
        Cell {
            row: 6,
            env: Unset,
            layout: ID,
            log_has_claims: true,
            read: None_,
            write: Refuses,
        },
        Cell {
            row: 7,
            env: Unset,
            layout: SEED,
            log_has_claims: false,
            read: SeedDerived,
            write: SeedDerived,
        },
        Cell {
            row: 8,
            env: Unset,
            layout: SEED_ID,
            log_has_claims: false,
            read: None_,
            write: Refuses,
        },
        Cell {
            row: 9,
            env: Unset,
            layout: SEED_ID,
            log_has_claims: true,
            read: None_,
            write: Refuses,
        },
        Cell {
            row: 10,
            env: Unset,
            layout: SEED_AND_KEY,
            log_has_claims: true,
            read: SeedDerived,
            write: SeedDerived,
        },
        Cell {
            row: 11,
            env: Unset,
            layout: SEED_ID_AND_KEY,
            log_has_claims: true,
            read: Key,
            write: Key,
        },
        Cell {
            row: 12,
            env: Unset,
            layout: ID_AND_KEY,
            log_has_claims: true,
            read: Key,
            write: Key,
        },
        Cell {
            row: 13,
            env: Exists,
            layout: NOTHING,
            log_has_claims: true,
            read: Override,
            write: Override,
        },
        Cell {
            row: 14,
            env: Missing,
            layout: NOTHING,
            log_has_claims: false,
            read: None_,
            write: MintsAtOverride,
        },
        Cell {
            row: 15,
            env: Missing,
            layout: NOTHING,
            log_has_claims: true,
            read: None_,
            write: Refuses,
        },
        Cell {
            row: 16,
            env: Missing,
            layout: KEY,
            log_has_claims: false,
            read: None_,
            write: Refuses,
        },
        Cell {
            row: 17,
            env: Missing,
            layout: SEED,
            log_has_claims: false,
            read: None_,
            write: Refuses,
        },
        Cell {
            row: 18,
            env: MissingDeclared,
            layout: NOTHING,
            log_has_claims: false,
            read: None_,
            write: RoleKeyMissing,
        },
    ]
}

// ------------------------------------------------------------------- setup

struct Built {
    dir: tempfile::TempDir,
    env_path: Option<PathBuf>,
    key_did: Option<String>,
    seed_did: Option<String>,
    override_did: Option<String>,
}

impl Built {
    fn path(&self) -> &Path {
        self.dir.path()
    }

    /// The `.kan/` layout is assembled **after** any log is written, because
    /// writing the log is itself a resolution that would otherwise create
    /// artifacts the cell does not call for.
    fn new(cell: &Cell) -> Self {
        let dir = git_repo();
        let kan_dir = dir.path().join(".kan");

        if cell.log_has_claims {
            // A throwaway identity, named by the environment so this write
            // touches none of the four artifacts under test.
            let writer = dir.path().join("keys/log-writer");
            let (_, stderr, ok) = kan(
                dir.path(),
                Some(&writer),
                &["observe", "seeded by the fixture", "--subject", "cell"],
            );
            assert!(ok, "row {}: seeding the log failed: {stderr}", cell.row);
            assert!(
                kan_dir.join("log/repo.car").exists(),
                "row {}: seeding produced no log",
                cell.row
            );
        }
        std::fs::create_dir_all(&kan_dir).unwrap();

        let mut key_did = None;
        if cell.layout.identity {
            let id = Identity::generate();
            id.save(&kan_dir.join("identity")).unwrap();
            key_did = Some(id.did());
        }
        if cell.layout.identity_id {
            std::fs::write(kan_dir.join("identity-id"), "kan-fixture-account").unwrap();
        }
        let mut seed_did = None;
        if cell.layout.seed {
            let seed = Seed::load_or_create(&kan_dir.join("seed")).unwrap();
            seed_did = Some(seed.signing_identity().unwrap().did());
        }
        if cell.layout.seed_id {
            std::fs::write(kan_dir.join("seed-id"), "kan-fixture-seed-account").unwrap();
        }

        let mut env_path = None;
        let mut override_did = None;
        match cell.env {
            Env::Unset => {}
            Env::Exists => {
                let p = dir.path().join("keys/override");
                std::fs::create_dir_all(p.parent().unwrap()).unwrap();
                let id = Identity::generate();
                id.save(&p).unwrap();
                override_did = Some(id.did());
                env_path = Some(p);
            }
            Env::Missing => env_path = Some(dir.path().join("keys/absent")),
            Env::MissingDeclared => {
                let p = dir.path().join("keys/absent-role");
                std::fs::write(
                    kan_dir.join("roles"),
                    format!("did:key:zFixtureRoleDid\tprover\t{}\n", p.display()),
                )
                .unwrap();
                env_path = Some(p);
            }
        }

        Built {
            dir,
            env_path,
            key_did,
            seed_did,
            override_did,
        }
    }

    fn expected_did(&self, e: Expect, row: u32) -> String {
        match e {
            Expect::Key => self.key_did.clone().expect("cell declares no key file"),
            Expect::SeedDerived => self.seed_did.clone().expect("cell declares no seed"),
            Expect::Override => self
                .override_did
                .clone()
                .expect("cell declares no override"),
            other => panic!("row {row}: {other:?} names no identity"),
        }
    }
}

// ------------------------------------------------------------------ probes

fn check_read(cell: &Cell, built: &Built) {
    let env = built.env_path.as_deref();
    let (stdout, stderr, ok) = kan(
        built.path(),
        env,
        &["show", "cell", "--trust", "me", "--json"],
    );

    match cell.read {
        Expect::None_ => {
            assert!(
                !ok,
                "row {}: the read resolved an identity where the table says there is none.\n\
                 stdout: {stdout}",
                cell.row
            );
            assert!(
                stderr.contains("nothing for `me` to name"),
                "row {}: the read failed, but not because `me` is unnameable -- so this cell \
                 is asserting the wrong thing.\nstderr: {stderr}",
                cell.row
            );
        }
        named => {
            assert!(ok, "row {}: the read failed: {stderr}", cell.row);
            let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
            let got = v["trust"]["authors"][0]["did"].as_str().unwrap_or("<none>");
            assert_eq!(
                got,
                built.expected_did(named, cell.row),
                "row {}: the read resolved the wrong identity",
                cell.row
            );
        }
    }
}

fn check_write(cell: &Cell, built: &Built) {
    let env = built.env_path.as_deref();
    let kan_dir = built.path().join(".kan");
    let (stdout, stderr, ok) = kan(
        built.path(),
        env,
        &["observe", "the write probe", "--subject", "probe"],
    );

    match cell.write {
        Expect::Refuses => {
            assert!(
                !ok,
                "row {}: the write succeeded where the guard should have refused.\n{stdout}",
                cell.row
            );
            assert!(
                stderr.contains("this repo already has an identity"),
                "row {}: the write failed for some reason other than the guard, so this cell \
                 asserts nothing about it.\nstderr: {stderr}",
                cell.row
            );
        }
        Expect::RoleKeyMissing => {
            assert!(!ok, "row {}: the write succeeded: {stdout}", cell.row);
            assert!(
                stderr.contains("has no key at"),
                "row {}: expected the declared-role refusal.\nstderr: {stderr}",
                cell.row
            );
        }
        Expect::MintsSeed => {
            assert!(ok, "row {}: the write failed: {stderr}", cell.row);
            assert!(
                kan_dir.join("seed").exists() || kan_dir.join("seed-id").exists(),
                "row {}: the write succeeded without seed-rooting the workspace",
                cell.row
            );
        }
        Expect::MintsKeyFile => {
            assert!(ok, "row {}: the write failed: {stderr}", cell.row);
            assert!(
                kan_dir.join("identity").exists(),
                "row {}: the write succeeded without creating .kan/identity",
                cell.row
            );
            assert!(
                !kan_dir.join("seed").exists(),
                "row {}: the write seed-rooted the workspace instead of minting a key file",
                cell.row
            );
        }
        Expect::MintsAtOverride => {
            assert!(ok, "row {}: the write failed: {stderr}", cell.row);
            assert!(
                built.env_path.as_ref().unwrap().exists(),
                "row {}: the write succeeded without creating the override key",
                cell.row
            );
        }
        Expect::None_ => panic!("row {}: a write cannot resolve to nothing", cell.row),
        named => {
            assert!(ok, "row {}: the write failed: {stderr}", cell.row);
            let (out, stderr, ok) = kan(built.path(), env, &["show", "probe", "--json"]);
            assert!(
                ok,
                "row {}: reading back the write failed: {stderr}",
                cell.row
            );
            let v: serde_json::Value = serde_json::from_str(&out).unwrap();
            let author = v["claims"][0]["author"].as_str().unwrap_or("<none>");
            assert_eq!(
                author,
                built.expected_did(named, cell.row),
                "row {}: the claim was signed by the wrong identity",
                cell.row
            );
        }
    }
}

// ------------------------------------------------------------------- tests

/// The read side of every cell. Runs on its own workspace per cell, because
/// the write probe mutates and would contaminate the next one.
#[test]
fn every_cell_resolves_as_the_table_says_on_the_read_path() {
    for cell in cells() {
        let built = Built::new(&cell);
        check_read(&cell, &built);
    }
}

#[test]
fn every_cell_resolves_as_the_table_says_on_the_write_path() {
    for cell in cells() {
        let built = Built::new(&cell);
        check_write(&cell, &built);
    }
}

/// The table's headline claim, asserted directly rather than left to be
/// inferred from eighteen rows: **the two resolvers disagree**, and they
/// disagree in a specific and enumerable set of cells.
///
/// This is what REQ-1 collapses. When question 1 has one implementation this
/// test should assert an empty set — and changing it is the point, so it
/// fails loudly rather than being quietly satisfied.
#[test]
fn the_two_resolvers_disagree_in_exactly_these_cells() {
    let disagreements: Vec<u32> = cells()
        .iter()
        .filter(|c| {
            // A cell disagrees when the read finds nothing while the write
            // has a definite identity to sign with. A write that *refuses* is
            // not a disagreement: both sides are saying "not this".
            c.read == Expect::None_
                && matches!(
                    c.write,
                    Expect::Key | Expect::SeedDerived | Expect::Override
                )
        })
        .map(|c| c.row)
        .collect();

    assert_eq!(
        disagreements,
        Vec::<u32>::new(),
        "the set of cells where the read reports no identity while the write resolves one \
         has changed. With the keychain disabled this set is empty -- every such cell (19, \
         23, and #170 itself) needs a reachable keychain, which is why the suite could not \
         have caught #170. If this set becomes non-empty, a NEW divergence has been \
         introduced on the testable plane."
    );
}

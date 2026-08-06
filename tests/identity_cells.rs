//! REQ-6 / AC-3 of `.design/v0.12-milestone.md`: one **independently failing**
//! test per reachable cell of identity resolution, against **both** resolvers.
//!
//! The table this pins is `.design/identity-resolution-cells.md`. Read that
//! first — it is the map, this is the check that the map matches the ground.
//!
//! **Why both probes.** Question 1 has two implementations today
//! (`.design/identity-resolution.md` Consequence 3), so a cell has two
//! answers and the interesting ones are where they differ:
//!
//! - the **read** probe is `kan show <subject> --trust me --json`, which
//!   calls `sign::existing_identity`;
//! - the **write** probe is `kan observe`, which calls
//!   `Workspace::commit_identity` → `Identity::load_or_create_for_workspace`.
//!
//! `kan identity did` is a *write*-path command (`src/cli/mod.rs:846`), which
//! is why #170 reads as "`identity did` resolves fine but `--trust me` does
//! not". Using it as a read probe would assert nothing about the read path.
//!
//! **One test per cell, not one loop over cells.** AC-3 requires that each
//! assertion be verifiable by reverting its own hunk and watching *that* test
//! go red. A `for` loop with panicking asserts cannot deliver that: the first
//! failing cell aborts the rest, so eight moved cells report one failure.
//! Every cell therefore gets its own named `#[test]`.
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

/// What a probe should produce. The identity-naming variants exist so a cell
/// asserts *which* identity resolved; "it resolved something" is the
/// assertion that cannot fail.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Expect {
    /// The read has no `me` to name.
    None_,
    Key,
    SeedDerived,
    Override,
    /// The guard fired: `WouldMintSecondIdentity`.
    Refuses,
    /// Seed-rooted the workspace, and signed with the seed it created.
    MintsSeed,
    /// Created `.kan/identity`, and signed with it.
    MintsKeyFile,
    /// Created a key at the `KAN_IDENTITY_FILE` path, and signed with it.
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

/// Rows 1–20 of `.design/identity-resolution-cells.md` — every cell reachable
/// with the keychain disabled. Rows 21–27 need a live keychain and are
/// documented rather than tested, which is itself the finding.
#[rustfmt::skip]
fn cells() -> Vec<Cell> {
    use Env::*;
    use Expect::*;
    vec![
        Cell { row: 1,  env: Unset, layout: NOTHING, log_has_claims: false, read: None_, write: MintsSeed },
        Cell { row: 2,  env: Unset, layout: NOTHING, log_has_claims: true,  read: None_, write: Refuses },
        Cell { row: 3,  env: Unset, layout: KEY,     log_has_claims: false, read: Key,   write: Key },
        Cell { row: 4,  env: Unset, layout: KEY,     log_has_claims: true,  read: Key,   write: Key },
        // `identity-id` alone makes `fresh` false (`src/sign.rs:508`), so the
        // write falls to the plaintext branch and mints a KEY FILE rather
        // than seed-rooting.
        Cell { row: 5,  env: Unset, layout: ID,      log_has_claims: false, read: None_, write: MintsKeyFile },
        Cell { row: 6,  env: Unset, layout: ID,      log_has_claims: true,  read: None_, write: Refuses },
        Cell { row: 7,  env: Unset, layout: SEED,    log_has_claims: false, read: SeedDerived, write: SeedDerived },
        Cell { row: 8,  env: Unset, layout: SEED_ID, log_has_claims: false, read: None_, write: Refuses },
        Cell { row: 9,  env: Unset, layout: SEED_ID, log_has_claims: true,  read: None_, write: Refuses },
        Cell { row: 10, env: Unset, layout: SEED_AND_KEY,    log_has_claims: true, read: SeedDerived, write: SeedDerived },
        Cell { row: 11, env: Unset, layout: SEED_ID_AND_KEY, log_has_claims: true, read: Key, write: Key },
        Cell { row: 12, env: Unset, layout: ID_AND_KEY,      log_has_claims: true, read: Key, write: Key },
        Cell { row: 13, env: Exists,  layout: NOTHING, log_has_claims: true,  read: Override, write: Override },
        Cell { row: 14, env: Missing, layout: NOTHING, log_has_claims: false, read: None_, write: MintsAtOverride },
        Cell { row: 15, env: Missing, layout: NOTHING, log_has_claims: true,  read: None_, write: Refuses },
        Cell { row: 16, env: Missing, layout: KEY,     log_has_claims: false, read: None_, write: Refuses },
        Cell { row: 17, env: Missing, layout: SEED,    log_has_claims: false, read: None_, write: Refuses },
        // Rows 18 and 19 were MISSING from the table's first draft and were
        // found by a cold adversarial review. 18 completes the guard's
        // three-member evidence set (`src/sign.rs:661`), which the first draft
        // enumerated two-thirds of. 19 is a mint the table's prose explicitly
        // denied: `identity-id` is the one artifact
        // `existing_identity_evidence` deliberately ignores, so a workspace
        // that demonstrably HAS had an identity mints a second one here.
        Cell { row: 18, env: Missing, layout: SEED_ID, log_has_claims: false, read: None_, write: Refuses },
        Cell { row: 19, env: Missing, layout: ID,      log_has_claims: false, read: None_, write: MintsAtOverride },
        Cell { row: 20, env: MissingDeclared, layout: NOTHING, log_has_claims: false, read: None_, write: RoleKeyMissing },
    ]
}

fn cell(row: u32) -> Cell {
    cells()
        .into_iter()
        .find(|c| c.row == row)
        .unwrap_or_else(|| panic!("no cell numbered {row}"))
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
            // The key is created explicitly: REQ-2 means naming a missing
            // path is an error, not a way to mint one.
            let writer = dir.path().join("keys/log-writer");
            std::fs::create_dir_all(writer.parent().unwrap()).unwrap();
            Identity::generate().save(&writer).unwrap();
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

    /// Who signed the claim the write probe just made.
    fn claim_author(&self, row: u32) -> String {
        let (out, stderr, ok) = kan(
            self.path(),
            self.env_path.as_deref(),
            &["show", "probe", "--json"],
        );
        assert!(ok, "row {row}: reading back the write failed: {stderr}");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        v["claims"][0]["author"]
            .as_str()
            .unwrap_or("<none>")
            .to_string()
    }
}

// ------------------------------------------------------------------ probes

/// `Some(did)` when the read names an identity, `None` when it honestly has
/// none. Used both by the per-cell assertions and by the measured
/// disagreement check, so the two cannot drift.
fn read_resolves(built: &Built) -> Option<String> {
    let (stdout, _, ok) = kan(
        built.path(),
        built.env_path.as_deref(),
        &["show", "cell", "--trust", "me", "--json"],
    );
    if !ok {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(&stdout).ok()?;
    v["trust"]["authors"][0]["did"]
        .as_str()
        .map(|s| s.to_string())
}

/// `Some(did)` when the write signs a claim, `None` when it refuses.
fn write_resolves(built: &Built, row: u32) -> Option<String> {
    let (_, _, ok) = kan(
        built.path(),
        built.env_path.as_deref(),
        &["observe", "the write probe", "--subject", "probe"],
    );
    if !ok {
        return None;
    }
    Some(built.claim_author(row))
}

fn run_read(row: u32) {
    let cell = cell(row);
    let built = Built::new(&cell);

    match cell.read {
        Expect::None_ => {
            let (stdout, stderr, ok) = kan(
                built.path(),
                built.env_path.as_deref(),
                &["show", "cell", "--trust", "me", "--json"],
            );
            assert!(
                !ok,
                "row {row}: the read resolved an identity where the table says there is \
                 none.\nstdout: {stdout}"
            );
            assert!(
                stderr.contains("nothing for `me` to name"),
                "row {row}: the read failed, but not because `me` is unnameable -- so this \
                 cell is asserting the wrong thing.\nstderr: {stderr}"
            );
        }
        named => {
            let got = read_resolves(&built)
                .unwrap_or_else(|| panic!("row {row}: the read resolved no identity"));
            assert_eq!(
                got,
                built.expected_did(named, row),
                "row {row}: the read resolved the wrong identity"
            );
        }
    }
}

fn run_write(row: u32) {
    let cell = cell(row);
    let built = Built::new(&cell);
    let kan_dir = built.path().join(".kan");
    let (stdout, stderr, ok) = kan(
        built.path(),
        built.env_path.as_deref(),
        &["observe", "the write probe", "--subject", "probe"],
    );

    match cell.write {
        Expect::Refuses => {
            assert!(
                !ok,
                "row {row}: the write succeeded where the guard should have refused.\n{stdout}"
            );
            assert!(
                stderr.contains("this repo already has an identity"),
                "row {row}: the write failed for some reason other than the guard, so this \
                 cell asserts nothing about it.\nstderr: {stderr}"
            );
        }
        Expect::RoleKeyMissing => {
            assert!(!ok, "row {row}: the write succeeded: {stdout}");
            assert!(
                stderr.contains("has no key at"),
                "row {row}: expected the declared-role refusal.\nstderr: {stderr}"
            );
        }
        // The three minting outcomes all assert the same two things: the
        // artifact appeared, AND the claim was signed by the key inside it.
        // Asserting only that a file appeared -- which the first draft did --
        // would pass a write that created the file and then signed as somebody
        // else, which is the misattribution this project exists to prevent.
        Expect::MintsSeed => {
            assert!(ok, "row {row}: the write failed: {stderr}");
            let seed_path = kan_dir.join("seed");
            assert!(
                seed_path.exists(),
                "row {row}: the write succeeded without seed-rooting the workspace"
            );
            let derived = Seed::load_or_create(&seed_path)
                .unwrap()
                .signing_identity()
                .unwrap()
                .did();
            assert_eq!(
                built.claim_author(row),
                derived,
                "row {row}: the write seed-rooted the workspace but signed with a different key"
            );
        }
        Expect::MintsKeyFile => {
            assert!(ok, "row {row}: the write failed: {stderr}");
            let key_path = kan_dir.join("identity");
            assert!(
                key_path.exists(),
                "row {row}: the write succeeded without creating .kan/identity"
            );
            assert!(
                !kan_dir.join("seed").exists(),
                "row {row}: the write seed-rooted the workspace instead of minting a key file"
            );
            assert_eq!(
                built.claim_author(row),
                Identity::load_existing(&key_path).unwrap().did(),
                "row {row}: the write created .kan/identity but signed with a different key"
            );
        }
        Expect::MintsAtOverride => {
            assert!(ok, "row {row}: the write failed: {stderr}");
            let key_path = built.env_path.clone().unwrap();
            assert!(
                key_path.exists(),
                "row {row}: the write succeeded without creating the override key"
            );
            assert_eq!(
                built.claim_author(row),
                Identity::load_existing(&key_path).unwrap().did(),
                "row {row}: the write created the override key but signed with a different key"
            );
        }
        Expect::None_ => panic!("row {row}: a write cannot resolve to nothing"),
        named => {
            assert!(ok, "row {row}: the write failed: {stderr}");
            assert_eq!(
                built.claim_author(row),
                built.expected_did(named, row),
                "row {row}: the claim was signed by the wrong identity"
            );
        }
    }
}

// ------------------------------------------------------------------- tests

/// One `#[test]` per cell per path, so each assertion fails alone and AC-3's
/// revert-the-hunk method is implementable against the shape shipped.
macro_rules! cell_tests {
    ($($name:ident : $row:expr),+ $(,)?) => {
        $(
            mod $name {
                #[test]
                fn read_path() { super::run_read($row); }
                #[test]
                fn write_path() { super::run_write($row); }
            }
        )+
    };
}

cell_tests! {
    cell_01: 1, cell_02: 2, cell_03: 3, cell_04: 4, cell_05: 5,
    cell_06: 6, cell_07: 7, cell_08: 8, cell_09: 9, cell_10: 10,
    cell_11: 11, cell_12: 12, cell_13: 13, cell_14: 14, cell_15: 15,
    cell_16: 16, cell_17: 17, cell_18: 18, cell_19: 19, cell_20: 20,
}

/// The table's headline claim, **measured**: for every cell, run both probes
/// against freshly built workspaces and compare what each actually resolved.
///
/// The first version of this test filtered the `cells()` literals on their own
/// declared expectations and asserted the result was empty. It called nothing,
/// touched no filesystem, and passed with the `kan` binary deleted — while
/// carrying a doc comment claiming it would "fail loudly". A cold review
/// caught it. It was `assert_eq!(vec![], vec![])` with a rationale attached,
/// in the milestone whose subject is tests that cannot fail.
///
/// It now derives both sides from subprocess output, so deleting the binary
/// fails it, and a resolver change that introduces a divergence fails it
/// without anyone having to update a table first.
#[test]
fn the_two_resolvers_disagree_in_exactly_these_cells() {
    let mut disagreements = Vec::new();
    for cell in cells() {
        // Separate workspaces: the read probe is not side-effect free (see
        // `a_read_that_resolves_an_identity_still_has_side_effects`), so
        // sharing one would let the read's mutations reach the write.
        let read = read_resolves(&Built::new(&cell));
        let write = write_resolves(&Built::new(&cell), cell.row);
        // A write that *refuses* is not a disagreement: both sides are saying
        // "not this". A divergence is the read finding nothing while the
        // write has a definite identity to sign with.
        if read.is_none() {
            if let Some(did) = write {
                disagreements.push((cell.row, did));
            }
        }
    }

    let rows: Vec<u32> = disagreements.iter().map(|(r, _)| *r).collect();
    assert_eq!(
        rows,
        vec![1, 5, 14, 19],
        "the measured set of cells where the read reports no identity while the write \
         resolves one has changed.\n\n\
         These four are expected, and they are exactly the cells whose write MINTS: the \
         write creates the identity it then signs with, so the read could not have found \
         it beforehand. (Rows 1 and 5 belong here for the same reason 14 and 19 do -- the \
         literal expectation this test shipped with named only the two override mints, and \
         measuring corrected it on the first run.) A cell where the read finds nothing and \
         the write resolves an identity it did NOT create requires a reachable keychain -- \
         #170 is that shape -- which is why the suite could not have caught it.\n\n\
         A new row here means a divergence has been introduced on the testable plane. A \
         missing row means one has been fixed -- which REQ-1 should do deliberately, by \
         changing this expectation in the same commit.\n\n\
         measured: {disagreements:?}"
    );
}

/// **A read that resolves an identity is not side-effect free today.**
///
/// `existing_identity`'s `KAN_IDENTITY_FILE` branch calls
/// `Identity::load_or_create` (`src/sign.rs:849`), not `load_existing`, so a
/// pure read `create_dir_all`s `.kan/` and tightens the named key's
/// permissions. `src/sign.rs:833-838`'s own comment says the key-file branch
/// "uses `load_existing` ... so it cannot ... write" — true of the branch it
/// sits above, false of the env branch three lines earlier.
///
/// This pins the **defect**, not the desired behaviour: REQ-1 makes
/// `workspace_identity` pure, and AC-8 asserts `.kan/` is byte-identical
/// across a read. When that lands this test must be inverted in the same
/// commit — which is the point of pinning it now rather than discovering it
/// then.
///
/// `tests/write_guards.rs::a_read_creates_no_workspace` misses this because it
/// points `KAN_IDENTITY_FILE` at a path that does not exist, so the resolving
/// branch is never entered.
#[test]
fn a_read_that_resolves_an_identity_still_has_side_effects() {
    let dir = git_repo();
    let key = dir.path().join("keys/k");
    std::fs::create_dir_all(key.parent().unwrap()).unwrap();
    Identity::generate().save(&key).unwrap();
    // `save` already restricts; loosen it so the chmod is observable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    std::fs::remove_dir_all(dir.path().join(".kan")).ok();
    assert!(!dir.path().join(".kan").exists(), "setup left a .kan/");

    let (_, _, ok) = kan(
        dir.path(),
        Some(&key),
        &["show", "nothing", "--trust", "me", "--json"],
    );
    assert!(ok, "the read failed");

    assert!(
        dir.path().join(".kan").exists(),
        "a read no longer creates .kan/ -- if REQ-1 landed, invert this test in that commit"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "a read no longer tightens the named key's permissions"
        );
    }
}

/// The control for the test above: without `--trust me` the read resolves no
/// identity and has no side effects, which is what isolates the cause to
/// resolution rather than to opening a workspace.
#[test]
fn a_read_that_resolves_nothing_has_no_side_effects() {
    let dir = git_repo();
    let key = dir.path().join("keys/k");
    std::fs::create_dir_all(key.parent().unwrap()).unwrap();
    Identity::generate().save(&key).unwrap();
    std::fs::remove_dir_all(dir.path().join(".kan")).ok();

    let (_, _, ok) = kan(dir.path(), Some(&key), &["show", "nothing", "--json"]);
    assert!(ok, "the read failed");
    assert!(
        !dir.path().join(".kan").exists(),
        "a read that names no identity created .kan/"
    );
}

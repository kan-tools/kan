//! AC-2 of `.design/v0.12-milestone.md`: the **change ledger** golden.
//!
//! Where `tests/golden_reads.rs` freezes the case that must not move, this one
//! freezes precisely the surfaces v0.12 *will* move, generated against the
//! pre-change binary and committed before any of them change:
//!
//! - the `--trust` vocabulary (REQ-4, REQ-5) — `me`, `roles`, `role:<name>`,
//!   a bare DID, a weighted DID, and the default
//! - the **overlapping-author** case (REQ-8) — an author with claims in *both*
//!   the log and `.claims/`, which is the case REQ-6 of the previous milestone
//!   passed while being half-delivered, because its test only covered disjoint
//!   authors
//! - the disjoint stranger case, so the two can be compared side by side
//! - `.kan/` layout (REQ-3) — the at-rest flip is a change to *which files
//!   exist*, and nothing else in the suite would notice it
//! - `.claims/` layout (REQ-9) — the published filename is what #131 collides
//!
//! **This fixture is expected to change.** That is the difference between it
//! and the invariant golden, and it is the whole point: a diff here must be
//! *accepted deliberately*, with the requirement it belongs to named in the
//! commit that accepts it. Silence is what the previous milestone got wrong —
//! not change.
//!
//! Regenerate deliberately, never reflexively:
//!
//! ```text
//! UPDATE_GOLDEN=1 cargo test --test golden_trust_and_identity
//! ```

mod common;

use common::{capture, compare_or_update, first_difference, git_repo, kan_as, normalize};
use std::path::{Path, PathBuf};

use kan::{
    claim::{Anchor, AuthorId, ClaimBody, ClaimContent, Rkey, SubjectRef},
    sign::Identity,
};

const GOLDEN: &str = "tests/fixtures/golden/trust-and-identity.txt";

struct Fixture {
    dir: tempfile::TempDir,
    alice: PathBuf,
    bob: PathBuf,
}

impl Fixture {
    /// Both key files are minted **while the log is empty**, which is
    /// load-bearing: the `WouldMintSecondIdentity` guard (ADR-77) refuses a
    /// second identity's first reference to a non-empty log, so a key minted
    /// after the first write would be refused rather than created.
    ///
    /// **`alice` is whichever key sorts first by DID**, and that is not
    /// cosmetic. `TrustBase::authors()` sorts on `(did, agent)` — correctly
    /// and deliberately (`src/fold/trust.rs:243`) — while DIDs here are
    /// randomly minted, so which of two identities leads a serialized trust
    /// array flips between runs. Numbering the placeholders by first
    /// appearance then assigns `<DID-0>` inconsistently and the fixture
    /// measures its own noise. Binding the *name* to the sort order removes
    /// the ambiguity at the source rather than papering over it in the
    /// normalizer, which would have cost the fixture its ability to see a
    /// genuine ordering change later.
    ///
    /// Caught by `normalization_is_reproducible_across_workspaces` on the
    /// first run, which is what that test is for.
    fn build() -> Self {
        let dir = git_repo();
        let first = dir.path().join("keys/first");
        let second = dir.path().join("keys/second");
        // Created with the library rather than by naming a missing path:
        // REQ-2 makes `KAN_IDENTITY_FILE` a selection, so a missing target is
        // an error instead of a mint.
        let mut minted: Vec<(String, PathBuf)> = Vec::new();
        for key in [first, second] {
            std::fs::create_dir_all(key.parent().unwrap()).unwrap();
            let identity = Identity::generate();
            identity.save(&key).unwrap();
            minted.push((identity.did(), key));
        }
        minted.sort();
        let bob = minted.pop().unwrap().1;
        let alice = minted.pop().unwrap().1;

        let fixture = Self { dir, alice, bob };
        fixture.write_log();
        fixture.plant_foreign_claims();
        fixture
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Two authors writing *through* this workspace, which is what makes them
    /// members of `TrustBase::Local`.
    fn write_log(&self) {
        let writes: &[(&Path, &[&str])] = &[
            (
                &self.alice,
                &[
                    "observe",
                    "alice wrote this through the workspace",
                    "--subject",
                    "shared",
                    "--title",
                    "A subject two authors touch",
                    "--kind",
                    "issue",
                ],
            ),
            (
                &self.bob,
                &[
                    "observe",
                    "bob wrote this through the workspace",
                    "--subject",
                    "shared",
                ],
            ),
            (
                &self.alice,
                &["observe", "alice also wrote here", "--subject", "overlap"],
            ),
            (&self.alice, &["publish", "shared"]),
        ];
        for (key, args) in writes {
            let (_, stderr, ok) = kan_as(self.path(), Some(key), args);
            assert!(ok, "setup write {args:?} failed: {stderr}");
        }
    }

    /// Records that *arrived at* this workspace as committed files rather than
    /// being written through it.
    ///
    /// Two shapes, deliberately side by side. `foreign` is a stranger — a DID
    /// with no log presence at all, which is the case the previous milestone
    /// tested. `overlap` is authored by **alice**, who has also written
    /// through this workspace, which is the case it did not: under a per-author
    /// trust predicate she is trusted, so her file-borne claim folds into the
    /// default view. REQ-8 is what changes that, and this is where it shows.
    fn plant_foreign_claims(&self) {
        let stranger = Identity::generate();
        self.plant(
            &stranger,
            "foreign",
            "a stranger's record, arrived as a file",
        );

        let alice = Identity::load_existing(&self.alice).expect("alice's key should load");
        self.plant(&alice, "overlap", "alice's record, arrived as a file");
    }

    fn plant(&self, identity: &Identity, subject: &str, text: &str) {
        let content = ClaimContent {
            author: AuthorId {
                did: identity.did(),
                agent: None,
            },
            // A fixed anchor rather than this repo's genesis: the planted
            // record stands in for one that arrived from elsewhere, and a
            // constant keeps its CID a pure function of author and text.
            workspace: Anchor::Workspace("elsewhere".to_string()),
            subject: SubjectRef::Local(Rkey::from(subject)),
            body: ClaimBody::Observation {
                text: text.to_string(),
            },
            cites: vec![],
            artifacts: vec![],
            recorded_at: None,
        };
        let cid = kan::cid::content_cid(&content).unwrap();
        let claim = kan::claim::Claim {
            content,
            sig: identity.sign(&cid.to_bytes()).unwrap(),
        };
        kan::transport::git_tree::write_subject(
            self.path(),
            &SubjectRef::Local(Rkey::from(subject)),
            &[(claim, None)],
        )
        .unwrap();
    }

    fn did(&self, key: &Path) -> String {
        let (did, stderr, ok) = kan_as(self.path(), Some(key), &["identity", "did"]);
        assert!(ok, "reading a did failed: {stderr}");
        did.trim().to_string()
    }
}

/// Every file under `rel`, by name, sorted — never contents.
///
/// The at-rest flip (REQ-3) and the published-filename change (REQ-9) are both
/// changes to *which files exist*, and no other test in the suite would
/// notice either. Sizes and mtimes are deliberately excluded: they are
/// volatile, and the question here is layout.
fn tree_listing(root: &Path, rel: &str, doc: &mut String) {
    let base = root.join(rel);
    let mut found = Vec::new();
    fn walk(dir: &Path, base: &Path, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let shown = path
                .strip_prefix(base)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();
            if path.is_dir() {
                out.push(format!("{shown}/"));
                walk(&path, base, out);
            } else {
                out.push(shown);
            }
        }
    }
    walk(&base, &base, &mut found);
    found.sort();

    doc.push_str(&format!("$ find {rel} -printf '%P\\n' | sort\n"));
    if found.is_empty() {
        doc.push_str("(absent)\n");
    }
    for name in found {
        doc.push_str(&name);
        doc.push('\n');
    }
    doc.push_str("=====================================================\n");
}

fn capture_document(fixture: &Fixture) -> String {
    let dir = fixture.path();
    let alice_did = fixture.did(&fixture.alice);
    let bob_did = fixture.did(&fixture.bob);
    let mut doc = String::new();

    // FIRST, and the ordering is load-bearing. DID placeholders are numbered
    // by first appearance, so pinning alice as `<DID-0>` and bob as `<DID-1>`
    // here makes the rest of the document independent of whatever order the
    // fold happens to emit claims in. Without this the two DIDs could swap
    // numbers between runs and the fixture would be testing its own noise.
    capture(dir, Some(&fixture.alice), &["identity", "did"], &mut doc);
    capture(dir, Some(&fixture.bob), &["identity", "did"], &mut doc);
    capture(
        dir,
        Some(&fixture.alice),
        &["identity", "role", "list"],
        &mut doc,
    );

    // The default view, and the two foreign shapes side by side.
    for args in [
        &["show", "shared"][..],
        &["show", "shared", "--json"][..],
        &["show", "foreign", "--json"][..],
        &["show", "overlap", "--json"][..],
        &["show", "--all", "--json"][..],
        &["status", "--json"][..],
        &["issues"][..],
        &["context", "--budget", "400", "--json"][..],
    ] {
        capture(dir, Some(&fixture.alice), args, &mut doc);
    }

    // The `--trust` vocabulary, every spelling the help text advertises.
    for args in [
        &["show", "shared", "--trust", "me", "--json"][..],
        &["show", "overlap", "--trust", "me", "--json"][..],
        &["show", "shared", "--trust", "roles", "--json"][..],
        &["show", "shared", "--trust", "role:primary", "--json"][..],
        &["show", "shared", "--trust", &alice_did, "--json"][..],
        &["show", "shared", "--trust", &bob_did, "--json"][..],
        &["show", "overlap", "--trust", &alice_did, "--json"][..],
    ] {
        capture(dir, Some(&fixture.alice), args, &mut doc);
    }
    let weighted = format!("{alice_did}=0.5");
    capture(
        dir,
        Some(&fixture.alice),
        &["show", "shared", "--trust", &weighted, "--json"],
        &mut doc,
    );

    // `--trust me` with **no** identity selected. This is #170's shape on a
    // workspace that has never minted its own key, and freezing it is how the
    // fix becomes visible rather than merely asserted.
    capture(
        dir,
        None,
        &["show", "shared", "--trust", "me", "--json"],
        &mut doc,
    );

    tree_listing(dir, ".kan", &mut doc);
    tree_listing(dir, ".claims", &mut doc);

    doc
}

#[test]
fn trust_and_identity_surfaces_match_the_golden() {
    let fixture = Fixture::build();
    let doc = normalize(&capture_document(&fixture), fixture.path());

    compare_or_update(
        GOLDEN,
        &doc,
        "the trust/identity surfaces changed.\n\n\
         AC-2 of `.design/v0.12-milestone.md`: this fixture is EXPECTED to change during \
         the milestone -- it freezes exactly the surfaces v0.12 moves. A diff is not a \
         failure by itself; an UNARGUED diff is. Accept it with `UPDATE_GOLDEN=1` in a \
         commit that names the requirement it belongs to, and check the diff is only what \
         that requirement should have moved.",
    );
}

/// The same reproducibility guard the invariant golden carries, and it matters
/// more here: this document contains three DIDs rather than one, and
/// placeholders are numbered by first appearance. If the fold emitted claims
/// in a content-derived order, two runs would number them differently and the
/// fixture would be measuring noise.
#[test]
fn normalization_is_reproducible_across_workspaces() {
    let a = Fixture::build();
    let doc_a = normalize(&capture_document(&a), a.path());

    let b = Fixture::build();
    let doc_b = normalize(&capture_document(&b), b.path());

    assert_eq!(
        doc_a,
        doc_b,
        "two identically-built workspaces normalized differently, so this fixture would be \
         testing run-to-run noise rather than behaviour.\n\n\
         --- first difference ---\n{}\n",
        first_difference(&doc_a, &doc_b)
    );
}

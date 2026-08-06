//! AC-1 of `.design/identity-surface.md`, carried forward as
//! `.design/v0.12-milestone.md`'s **invariant** golden: a single-author
//! workspace produces **byte-identical** `show`, `status`, `issues` and
//! `context` output across the milestone, on both the human and `--json`
//! surfaces.
//!
//! **This fixture must not change in v0.12.** Nothing the milestone does —
//! the resolution rewrite, the at-rest flip, the origin-aware fold — has any
//! business moving what a lone author sees in a workspace with no roles and
//! no foreign claims. That is the whole of its value: it is the case that
//! must stay still while everything around it moves. The surfaces v0.12 *does*
//! move are frozen separately, in `tests/golden_trust_and_identity.rs`, where
//! a diff is expected and has to be argued for.
//!
//! **Why a golden file rather than assertions.** Hand-written assertions test
//! what the author thought to check, and the claim here is the opposite shape
//! — that *nothing at all* changed. Several defects in this project were
//! tests that could not fail (`docs/DECISIONS.md` ADR-48, ADR-82); an
//! assertion list over read output is that shape by construction, because
//! every field nobody thought to assert is a field the change may silently
//! move. A whole-document comparison inverts the default: a difference has to
//! be *accepted* into the fixture rather than merely not noticed.
//!
//! **The fixture is generated against the pre-change binary and committed
//! first.** That ordering is the whole point. A golden regenerated in the
//! same commit as the behaviour change proves nothing.
//!
//! Volatile tokens — the minted DID, content CIDs, wall-clock timestamps, the
//! repo's genesis hash, the temp path — are normalized to stable placeholders
//! (`tests/common/mod.rs`), which is what makes the document reproducible
//! without making it vacuous: a CID becomes `<CID-3>` by *first appearance*,
//! so a claim that moves, vanishes, or arrives still shifts the document.
//!
//! Regenerate deliberately, never reflexively:
//!
//! ```text
//! UPDATE_GOLDEN=1 cargo test --test golden_reads
//! ```

mod common;

use common::{capture, compare_or_update, first_difference, git_repo, kan, normalize};
use std::path::Path;

const GOLDEN: &str = "tests/fixtures/golden/single-author-reads.txt";

/// The writes that build the fixture workspace.
///
/// Deliberately covers more than one subject, a status transition, a relation,
/// a retraction and a publication, because the golden is only as good as the
/// shapes it contains: a document with one observation in it would stay
/// byte-identical under almost any change to the fold.
fn build_workspace(dir: &Path) {
    let writes: &[&[&str]] = &[
        &[
            "observe",
            "the fold reads morphisms and never mutates objects",
            "--subject",
            "alpha",
            "--title",
            "Alpha, the first subject",
            "--kind",
            "issue",
        ],
        &["plan", "add a golden fixture first", "--subject", "alpha"],
        &["block", "alpha", "waiting on the fixture to exist"],
        &[
            "observe",
            "beta was noticed in passing",
            "--subject",
            "beta",
        ],
        &["relate", "beta", "blocks", "alpha"],
        &[
            "observe",
            "this observation is a mistake",
            "--subject",
            "beta",
        ],
        &["resolve", "beta", "beta turned out to be nothing"],
        &["mark", "alpha", "open"],
        &["publish", "alpha"],
    ];
    for args in writes {
        let (_, stderr, ok) = kan(dir, args);
        assert!(ok, "setup write {args:?} failed: {stderr}");
    }

    // Retract the mistaken observation by CID, so the golden contains a
    // superseded claim rather than only live ones.
    let (stdout, stderr, ok) = kan(dir, &["show", "beta", "--json"]);
    assert!(ok, "reading beta failed: {stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let mistake = v["claims"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["text"].as_str() == Some("this observation is a mistake"))
        .expect("the mistaken observation should be live before it is retracted")["cid"]
        .as_str()
        .unwrap()
        .to_string();
    let (_, stderr, ok) = kan(dir, &["retract", &mistake]);
    assert!(ok, "retract failed: {stderr}");
}

/// Every read surface AC-1 names, in a fixed order.
const READS: &[&[&str]] = &[
    &["show", "alpha"],
    &["show", "beta"],
    &["show", "alpha", "--json"],
    &["show", "--all", "--json"],
    &["status"],
    &["status", "alpha"],
    &["status", "--json"],
    &["issues"],
    &["issues", "--json"],
    &["context", "--budget", "400"],
    &["context", "--budget", "400", "--json"],
];

fn capture_reads(dir: &Path) -> String {
    let mut doc = String::new();
    for args in READS {
        capture(dir, None, args, &mut doc);
    }
    doc
}

#[test]
fn single_author_reads_match_the_golden() {
    let dir = git_repo();
    build_workspace(dir.path());
    let doc = normalize(&capture_reads(dir.path()), dir.path());

    compare_or_update(
        GOLDEN,
        &doc,
        "single-author read output changed.\n\n\
         AC-1 of `.design/v0.12-milestone.md` says this document is byte-identical across \
         the milestone: a lone author with no roles and no foreign claims is the case that \
         must stay still while identity resolution, at-rest storage and the fold all move \
         around it. A diff here is a regression until argued otherwise -- the surfaces v0.12 \
         deliberately changes are frozen in `tests/golden_trust_and_identity.rs` instead.",
    );
}

/// The normalizer has to be reproducible itself, or the fixture is measuring
/// its own noise. Two independently built workspaces — different temp dirs,
/// different genesis hashes, different DIDs, different wall-clock — must
/// normalize to the same document.
#[test]
fn normalization_is_reproducible_across_workspaces() {
    let a = git_repo();
    build_workspace(a.path());
    let doc_a = normalize(&capture_reads(a.path()), a.path());

    let b = git_repo();
    build_workspace(b.path());
    let doc_b = normalize(&capture_reads(b.path()), b.path());

    assert_eq!(
        doc_a,
        doc_b,
        "two identically-built workspaces normalized differently, so the golden fixture \
         would be testing run-to-run noise rather than behaviour.\n\n\
         --- first difference ---\n{}\n",
        first_difference(&doc_a, &doc_b)
    );
}

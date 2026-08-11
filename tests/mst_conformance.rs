//! The MST is structurally conformant, checked against a second implementation.
//!
//! ADR-11/12 established the storage-crate stress test this repo runs before
//! trusting a dependency: sequential inserts, full reachability checked after
//! every single one. That test caught `atrium-repo`'s data-loss bug. It does
//! **not** catch the bug in `atproto-repo` 0.14.5 (kan#204), because nothing is
//! lost there — every key stays reachable. The tree is simply not a tree: every
//! key went into one flat root node, which is rewritten in full on every insert
//! (CAR bytes ~52n², a hard write cliff at ~1,431 claims) and yields a root CID
//! no conformant implementation agrees with.
//!
//! So reachability is necessary and not sufficient, and this file runs both:
//!
//! - [`root_cid_matches_the_reference_implementation`] — the structural check.
//!   The expected value is not our reading of the spec; it is the output of
//!   `@atproto/repo` 0.10.10 over the same key set, recorded in the fixture.
//! - [`every_key_readable_after_every_insert`] — ADR-11/12's protocol, which
//!   matters more than usual here: until kan took ownership of `src/mst`,
//!   the read path had only ever been exercised against a single flat node,
//!   because the writer never produced anything else.

use atproto_dasl::storage::BlockStorage;
use atproto_dasl::Cid;
use kan::mst::Mst;
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    expected_root: String,
    reference_impl: String,
    pairs: Vec<(String, String)>,
}

fn fixture() -> Fixture {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/mst-conformance.json"
    ))
    .expect("mst-conformance.json is checked in");
    serde_json::from_str(&raw).expect("fixture parses")
}

fn value_cid(s: &str) -> Cid {
    s.parse::<Cid>().expect("fixture value is a valid CID")
}

#[tokio::test]
async fn root_cid_matches_the_reference_implementation() {
    let f = fixture();
    let mut mst = Mst::new_in_memory();
    for (key, value) in &f.pairs {
        mst.insert(key, value_cid(value))
            .await
            .expect("insert succeeds");
    }

    let root = mst.root().expect("non-empty tree has a root").to_string();
    assert_eq!(
        root,
        f.expected_root,
        "MST root CID diverges from {} over the same {} keys. This is a \
         CONFORMANCE failure, not a performance one: a repo whose root CID \
         disagrees with the reference is not an atproto repo, which is the \
         whole reason ADR-12 chose this dependency. See src/mst/mod.rs and ADR-90.",
        f.reference_impl,
        f.pairs.len()
    );

    // Second, independent signal: write amplification, which is what the cliff
    // actually was. `storage` holds every node version written across all the
    // inserts, not just the final tree's `expected_nodes`, so this measures the
    // total the CAR would have to carry.
    //
    // The flat implementation rewrote a whole ~104-byte-per-entry root on every
    // insert, i.e. ~52n² bytes — about 10.4 MB at this fixture's size. A
    // correct tree touches only the root-to-leaf path, ~O(log n) small nodes
    // per insert. The bound below sits far under the flat figure and far over
    // the conformant one, so it fails loudly if the tree ever goes flat again
    // without depending on an exact byte count.
    let mut total_bytes = 0usize;
    let cids: Vec<_> = mst.storage().cids().collect();
    for cid in &cids {
        total_bytes += mst
            .storage()
            .get(cid)
            .await
            .expect("storage get succeeds")
            .expect("cid came from this storage's own iterator")
            .len();
    }
    assert!(
        total_bytes < 2_000_000,
        "write amplification regressed: {} node-versions totalling {} bytes for \
         {} sequential inserts. A flat tree costs ~52n² here (~10.4 MB); a \
         conformant one costs well under 1 MB. See kan#204.",
        cids.len(),
        total_bytes,
        f.pairs.len()
    );
}

#[tokio::test]
async fn every_key_readable_after_every_insert() {
    let f = fixture();
    let mut mst = Mst::new_in_memory();
    let mut inserted: Vec<(String, Cid)> = Vec::new();

    for (key, value) in &f.pairs {
        let cid = value_cid(value);
        mst.insert(key, cid.clone()).await.expect("insert succeeds");
        inserted.push((key.clone(), cid));

        for (k, want) in &inserted {
            let got = mst.get(k).await.expect("get succeeds");
            assert_eq!(
                got.as_ref(),
                Some(want),
                "key {k} became unreachable after {} inserts — the ADR-11/12 \
                 failure mode, checked after every insert rather than only at \
                 the end because that is how the atrium-repo bug hid",
                inserted.len()
            );
        }

        assert_eq!(
            mst.entries().await.expect("entries succeeds").len(),
            inserted.len(),
            "entries() lost a key after {} inserts",
            inserted.len()
        );
    }
}

/// A tree a non-conformant writer has touched is REPAIRED by the next write,
/// not propagated and not refused.
///
/// This reproduces, without needing an old binary, what `atproto-repo` 0.14.5's
/// `insert` does to a tree that is already correct: it splices the key into the
/// root node's entry list by sort order, ignoring the key's layer, and leaves
/// the neighbouring sub-tree pointers alone. The claim is still findable at that
/// point — the precondition below asserts exactly that, so this test cannot
/// quietly stop reproducing the bug.
///
/// What made it *unfindable* was the next conformant write. The in-order walk
/// emits the misplaced key at its wrong tree position, so the sequence handed to
/// the rebuild is not ascending, and `build_canonical` partitions by index
/// range. The rebuilt tree kept every block reachable by a full walk while
/// putting one key in a sub-tree whose range does not contain it, so ordered
/// descent could no longer reach it: present in the log, invisible to the fold.
///
/// Sorting the walk before building is the whole repair. Revert that one
/// `sort_by` in `src/mst/tree.rs` and this test fails; the rest of the suite
/// still passes, which is why it has to exist.
///
/// Note the fixture's pairs are in KEY ORDER, so the sample is interleaved
/// rather than a prefix — a contiguous slice puts every remaining key past the
/// end of the tree, where a splice causes no disorder and the test proves
/// nothing. It was written that way first.
#[tokio::test]
async fn a_write_repairs_a_tree_a_non_conformant_writer_touched() {
    use kan::mst::{MstNode, TreeEntry};

    let f = fixture();
    let sample: Vec<_> = f.pairs.iter().step_by(2).collect();
    let candidates: Vec<_> = f.pairs.iter().skip(1).step_by(2).collect();

    let mut mst = Mst::new_in_memory();
    for (key, value) in &sample {
        mst.insert(key, value_cid(value)).await.unwrap();
    }

    // Splice a key into the ROOT by sort order, ignoring its layer, exactly as
    // the flat implementation did, leaving neighbouring sub-tree pointers alone.
    //
    // Search on the PROPERTY we need rather than a proxy for it: try candidates
    // until one actually disorders the walk. An earlier version guessed that the
    // key had to land strictly between two root entries; the root usually holds
    // a single top-layer key, so that condition was almost never satisfiable,
    // and the version before that spliced past the end of the tree where no
    // disorder is possible at all. Both "passed" by testing nothing.
    let root_cid = *mst.root().unwrap();
    let root_bytes = mst.storage().get(&root_cid).await.unwrap().unwrap();
    let mut chosen = None;
    for cand in &candidates {
        let mut root = MstNode::from_bytes(&root_bytes).unwrap();
        let mut prev = String::new();
        let mut at = root.entries.len();
        for (i, e) in root.entries.iter().enumerate() {
            let k = e.reconstruct_key(&prev).unwrap();
            if k.as_str() > cand.0.as_str() {
                at = i;
                break;
            }
            prev = k;
        }
        root.entries.insert(
            at,
            TreeEntry::with_prefix(&prev, &cand.0, value_cid(&cand.1)),
        );
        let bytes = root.to_bytes().unwrap();
        let cid = root.cid().unwrap();
        mst.storage_mut().put(&cid, bytes).await.unwrap();

        let live = Mst::from_root(cid, std::mem::take(mst.storage_mut()), Default::default());
        let walk: Vec<String> = live
            .entries()
            .await
            .unwrap()
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        let disordered = walk.windows(2).any(|w| w[0] >= w[1]);
        *mst.storage_mut() = live.into_storage();
        if disordered {
            chosen = Some((cand, cid));
            break;
        }
    }
    let ((stray_key, _), spliced_root) =
        chosen.expect("no candidate splice disordered the walk — the test would prove nothing");

    let mut mst = Mst::from_root(spliced_root, mst.into_storage(), Default::default());

    // PRECONDITIONS: the damage exists, and is not yet visible as a missing key.
    assert!(
        mst.get(stray_key).await.unwrap().is_some(),
        "the spliced key is findable before the rebuild — the loss comes later"
    );

    // The write that used to orphan it.
    let (new_key, new_value) = candidates
        .iter()
        .find(|(k, _)| k != stray_key)
        .expect("another candidate exists");
    mst.insert(new_key, value_cid(new_value)).await.unwrap();

    for (key, _) in &sample {
        assert!(
            mst.get(key).await.unwrap().is_some(),
            "pre-existing key {key} unreachable after the repairing write"
        );
    }
    assert!(
        mst.get(stray_key).await.unwrap().is_some(),
        "the spliced key is unreachable by ordered descent after the rebuild — \
         still in the tree, invisible to the fold. kan#204's read-invisibility \
         path; see .design/mst-migration.md"
    );
    assert!(
        mst.get(new_key).await.unwrap().is_some(),
        "the newly written key must be findable too"
    );
}

/// No state a *released* kan can produce leaves a claim unreachable.
///
/// This is the property the read-side detector exists to assert, and asserting
/// it turned out to matter more than the detector itself.
///
/// The invisible-claim failure (kan#204) needed a rebuild from a DISORDERED
/// walk. Only one build ever did that — the intermediate one written while
/// fixing this, between adding the canonical rebuild and adding the sort in
/// front of it. Every released kan either splices flat (pre-fix, never
/// rebuilds) or sorts before rebuilding (post-fix), so neither produces it.
///
/// What a released pair of binaries *can* produce is the state below: an old
/// flat-MST binary splicing into a canonical tree, which disorders the walk.
/// This asserts that state still leaves every claim reachable — benign, and
/// repaired by the next write.
#[tokio::test]
async fn no_reachable_state_leaves_a_claim_invisible() {
    use kan::mst::{MstNode, TreeEntry};

    let f = fixture();
    let sample: Vec<_> = f.pairs.iter().step_by(2).collect();
    let candidates: Vec<_> = f.pairs.iter().skip(1).step_by(2).collect();

    let mut mst = Mst::new_in_memory();
    for (key, value) in &sample {
        mst.insert(key, value_cid(value)).await.unwrap();
    }
    assert!(
        mst.unreachable_by_ordered_descent()
            .await
            .unwrap()
            .is_empty(),
        "a conformant tree has nothing unreachable"
    );

    // Splice as a flat-MST binary does: into the root, by sort order, ignoring
    // layer and leaving neighbouring sub-tree pointers alone.
    let root_cid = *mst.root().unwrap();
    let root_bytes = mst.storage().get(&root_cid).await.unwrap().unwrap();
    let mut disordered_root = None;
    for cand in &candidates {
        let mut root = MstNode::from_bytes(&root_bytes).unwrap();
        let mut prev = String::new();
        let mut at = root.entries.len();
        for (i, e) in root.entries.iter().enumerate() {
            let k = e.reconstruct_key(&prev).unwrap();
            if k.as_str() > cand.0.as_str() {
                at = i;
                break;
            }
            prev = k;
        }
        root.entries.insert(
            at,
            TreeEntry::with_prefix(&prev, &cand.0, value_cid(&cand.1)),
        );
        let bytes = root.to_bytes().unwrap();
        let cid = root.cid().unwrap();
        mst.storage_mut().put(&cid, bytes).await.unwrap();

        let live = Mst::from_root(cid, std::mem::take(mst.storage_mut()), Default::default());
        let walk: Vec<String> = live
            .entries()
            .await
            .unwrap()
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        let disordered = walk.windows(2).any(|w| w[0] >= w[1]);
        *mst.storage_mut() = live.into_storage();
        if disordered {
            disordered_root = Some(cid);
            break;
        }
    }
    let cid = disordered_root.expect("no candidate splice disordered the walk");
    let mut mst = Mst::from_root(cid, mst.into_storage(), Default::default());

    assert!(
        mst.unreachable_by_ordered_descent()
            .await
            .unwrap()
            .is_empty(),
        "an old binary's splice disorders the walk but must leave every claim \
         reachable — if this ever fails, a released binary CAN hide a claim and \
         the read-time warning in Log::iter_all stops being theoretical"
    );

    // And the next write repairs the disorder itself.
    let (k, v) = candidates.last().expect("a candidate exists");
    mst.insert(k, value_cid(v)).await.unwrap();
    let walk: Vec<String> = mst
        .entries()
        .await
        .unwrap()
        .into_iter()
        .map(|(k, _)| k)
        .collect();
    assert!(
        walk.windows(2).all(|w| w[0] < w[1]),
        "a write must restore ascending order"
    );
}

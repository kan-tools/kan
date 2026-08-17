//! MST tree operations.
//!
//! The main `Mst` struct provides CRUD operations on the Merkle Search Tree.

use super::entry::TreeEntry;
use super::key::key_height;
use super::Error;
use super::MstConfig;
use super::MstNode;
use atproto_dasl::storage::{BlockStorage, MemoryStorage};
use atproto_dasl::{Cid, CidCore};

/// Merkle Search Tree backed by pluggable block storage.
///
/// Supports streaming traversal for memory-efficient processing of large trees.
///
/// # Example
///
/// ```rust,ignore
/// use atproto_repo::mst::Mst;
/// use atproto_repo::storage::MemoryStorage;
///
/// async fn example() -> anyhow::Result<()> {
///     let storage = MemoryStorage::new();
///     let mut mst = Mst::new(storage, MstConfig::default());
///
///     // Insert a key-value pair
///     let cid = compute_cid(b"record data");
///     let new_root = mst.insert("app.bsky.feed.post/abc", cid.into()).await?;
///
///     // Lookup
///     let value = mst.get("app.bsky.feed.post/abc").await?;
///
///     Ok(())
/// }
/// ```
pub struct Mst<S: BlockStorage> {
    /// Block storage backend.
    storage: S,
    /// Root CID (None if empty tree).
    root: Option<CidCore>,
    /// Configuration with limits.
    config: MstConfig,
}

impl<S: BlockStorage> Mst<S> {
    /// Create an empty MST with storage backend.
    #[must_use]
    pub fn new(storage: S, config: MstConfig) -> Self {
        Self {
            storage,
            root: None,
            config,
        }
    }

    /// Create MST from an existing root CID.
    #[must_use]
    pub fn from_root(root: CidCore, storage: S, config: MstConfig) -> Self {
        Self {
            storage,
            root: Some(root),
            config,
        }
    }

    /// Get the root CID.
    #[must_use]
    pub fn root(&self) -> Option<&CidCore> {
        self.root.as_ref()
    }

    /// Check if the tree is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.root.is_none()
    }

    /// Get reference to the storage backend.
    #[must_use]
    pub fn storage(&self) -> &S {
        &self.storage
    }

    /// Get mutable reference to the storage backend.
    pub fn storage_mut(&mut self) -> &mut S {
        &mut self.storage
    }

    /// Consume MST and return storage.
    #[must_use]
    pub fn into_storage(self) -> S {
        self.storage
    }

    /// Get the configuration.
    #[must_use]
    pub fn config(&self) -> &MstConfig {
        &self.config
    }

    /// Load a node from storage.
    async fn load_node(&self, cid: &CidCore) -> Result<MstNode, Error> {
        let bytes = self
            .storage
            .get(cid)
            .await?
            .ok_or_else(|| Error::NodeNotFound {
                cid: cid.to_string(),
            })?;

        MstNode::from_bytes(&bytes)
    }

    /// Store a node in storage.
    async fn store_node(&mut self, node: &MstNode) -> Result<CidCore, Error> {
        let bytes = node.to_bytes()?;
        let cid = atproto_repo::compute_cid(&bytes);
        self.storage.put(&cid, bytes).await?;
        Ok(cid)
    }

    /// Get a value by key.
    ///
    /// Lazily loads nodes from storage as needed.
    ///
    /// # Errors
    ///
    /// Returns `Error` if the key is invalid or node loading fails.
    pub async fn get(&self, key: &str) -> Result<Option<Cid>, Error> {
        let root_cid = match &self.root {
            Some(cid) => cid,
            None => return Ok(None),
        };

        self.get_recursive(root_cid, key, 0).await
    }

    async fn get_recursive(
        &self,
        cid: &CidCore,
        key: &str,
        depth: usize,
    ) -> Result<Option<Cid>, Error> {
        // Check depth limit
        if depth > self.config.max_depth {
            return Err(Error::StructureViolation {
                reason: format!("max depth {} exceeded", self.config.max_depth),
            });
        }

        let node = self.load_node(cid).await?;
        let target_height = key_height(key);

        // Find the entry or subtree
        let mut prev_key = String::new();

        for entry in &node.entries {
            let entry_key = entry.reconstruct_key(&prev_key)?;

            if entry_key == key {
                return Ok(Some(entry.value.clone()));
            }

            if entry_key.as_str() > key {
                // Key would be before this entry - check left or entry's tree
                // First check if we should go into a subtree
                break;
            }

            // Check if we should descend into this entry's subtree
            if let Some(ref tree_cid) = entry.tree {
                let entry_height = key_height(&entry_key);
                if target_height <= entry_height && key > entry_key.as_str() {
                    // Key might be in this subtree
                    if let result @ Some(_) =
                        Box::pin(self.get_recursive(tree_cid, key, depth + 1)).await?
                    {
                        return Ok(result);
                    }
                }
            }

            prev_key = entry_key;
        }

        // Check left subtree
        if let Some(ref left_cid) = node.left {
            return Box::pin(self.get_recursive(left_cid, key, depth + 1)).await;
        }

        Ok(None)
    }

    /// Insert a key-value pair. Returns the new root CID.
    ///
    /// Creates new nodes in storage for the modified path.
    ///
    /// # Errors
    ///
    /// Returns `Error` if the key is invalid or storage fails.
    pub async fn insert(&mut self, key: &str, value: Cid) -> Result<CidCore, Error> {
        super::key::validate_key(key).map_err(|reason| Error::InvalidNode { reason })?;

        // Upstream 0.14.5 inserted every key into the root node's flat entry
        // list: `insert_recursive` computed `key_height` into `_target_height`,
        // discarded it, and never recursed. The tree never split, so the root
        // grew without bound and was rewritten in full on every insert -- CAR
        // bytes ~52n^2, a hard write-failure cliff at ~1,431 records against
        // atproto-dasl's 100 MiB default, and a root CID that no conformant
        // implementation agrees with.
        //
        // An MST's shape is a pure function of its key SET, not of insertion
        // order, so rebuilding canonically is exactly equivalent to a correct
        // incremental insert, byte for byte. Unchanged sub-trees keep their
        // CIDs and are deduplicated by the caller's persisted-block set, so a
        // rebuild still only adds O(log n) NEW blocks to the CAR -- which is
        // the property the cliff was about. A true incremental insert is a
        // later optimization; `build_canonical` is its oracle.
        //
        // `collect_entries` visits every entry unconditionally, so this returns
        // the COMPLETE key set even when a non-conformant writer has put a key
        // in the wrong node. What it does not guarantee is ORDER: a misplaced
        // key is emitted at its wrong tree position, so the sequence is not
        // ascending.
        let mut pairs = self.entries().await?;

        // Which matters because `build_canonical` requires sorted input -- it
        // partitions by index range. Handed an unsorted list it builds a tree
        // where every block is still reachable by a full walk, but a key sits
        // in a sub-tree whose range does not contain it, so ORDERED DESCENT
        // (`get`, and therefore the fold) can no longer find it. Measured: a
        // claim written by an old flat-MST binary went invisible to `kan show`
        // while remaining present in the MST -- orphaned, not destroyed.
        //
        // Sorting here is the whole repair. It is not defensive tidying: it is
        // what lets a conformant binary heal a log an old one has written into,
        // rather than propagating the disorder.
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
        if let Some(w) = pairs.windows(2).find(|w| w[0].0 == w[1].0) {
            return Err(Error::StructureViolation {
                reason: format!("duplicate key {} in the tree", w[0].0),
            });
        }

        match pairs.binary_search_by(|(k, _)| k.as_str().cmp(key)) {
            Ok(i) => pairs[i].1 = value,
            Err(i) => pairs.insert(i, (key.to_string(), value)),
        }

        let new_root = self
            .build_canonical(&pairs)
            .await?
            .ok_or_else(|| Error::InvalidNode {
                reason: "canonical build produced no root for a non-empty key set".to_string(),
            })?;

        // POST-CONDITION, checked rather than reasoned about. Every key that
        // went in must come back out of the tree that was built, in order. This
        // is deliberately a check on the RESULT and not a pre-flight check on
        // the input shape: the failure mode above was found only because the
        // key set was compared before and after, and no amount of inspecting
        // the input would have predicted which key ordered descent would lose.
        // A pre-condition can only reject shapes already imagined; this rejects
        // any rebuild that did not preserve the data, whatever caused it.
        let rebuilt = self.collect_keys(&new_root).await?;
        if rebuilt.len() != pairs.len() {
            return Err(Error::StructureViolation {
                reason: format!(
                    "rebuild changed the key set: {} keys in, {} out. The claims are all still in \
                     the CAR -- this refuses the write rather than committing a tree that cannot \
                     return them. See kan#204.",
                    pairs.len(),
                    rebuilt.len()
                ),
            });
        }
        if let Some((i, key)) = rebuilt
            .iter()
            .enumerate()
            .find(|(i, k)| pairs.get(*i).is_none_or(|(p, _)| p != *k))
        {
            return Err(Error::StructureViolation {
                reason: format!("rebuild reordered the key set at index {i} ({key})"),
            });
        }

        self.root = Some(new_root);
        Ok(new_root)
    }

    /// Keys of a tree, in the order an in-order walk yields them.
    async fn collect_keys(&self, root: &CidCore) -> Result<Vec<String>, Error> {
        let mut out = Vec::new();
        self.collect_keys_from(root, &mut out).await?;
        Ok(out)
    }

    async fn collect_keys_from(&self, cid: &CidCore, out: &mut Vec<String>) -> Result<(), Error> {
        let node = self.load_node(cid).await?;
        if let Some(ref left) = node.left {
            Box::pin(self.collect_keys_from(left, out)).await?;
        }
        let mut prev = String::new();
        for entry in &node.entries {
            let key = entry.reconstruct_key(&prev)?;
            out.push(key.clone());
            if let Some(ref tree) = entry.tree {
                Box::pin(self.collect_keys_from(tree, out)).await?;
            }
            prev = key;
        }
        Ok(())
    }

    /// Build the canonical MST for a sorted key set and return its root.
    ///
    /// Layers decrement STRICTLY: a layer holding no keys of its own still gets
    /// a node containing only a left pointer. Skipping empty layers produces a
    /// different root CID -- verified against `@atproto/repo` 0.10.10, which is
    /// the arbiter here.
    async fn build_canonical(&mut self, pairs: &[(String, Cid)]) -> Result<Option<CidCore>, Error> {
        let Some(top) = pairs.iter().map(|(k, _)| key_height(k)).max() else {
            return Ok(None);
        };
        self.build_layer(pairs, i64::from(top)).await
    }

    async fn build_layer(
        &mut self,
        pairs: &[(String, Cid)],
        layer: i64,
    ) -> Result<Option<CidCore>, Error> {
        if pairs.is_empty() || layer < 0 {
            return Ok(None);
        }

        let at: Vec<usize> = pairs
            .iter()
            .enumerate()
            .filter(|(_, (k, _))| i64::from(key_height(k)) == layer)
            .map(|(i, _)| i)
            .collect();

        // No key belongs at this layer: the node still exists, holding only a
        // pointer to the layer below.
        if at.is_empty() {
            let left = Box::pin(self.build_layer(pairs, layer - 1))
                .await?
                .map(Cid::from);
            let node = MstNode {
                left,
                entries: Vec::new(),
            };
            return Ok(Some(self.store_node(&node).await?));
        }

        let left = Box::pin(self.build_layer(&pairs[..at[0]], layer - 1))
            .await?
            .map(Cid::from);

        let mut entries = Vec::with_capacity(at.len());
        let mut prev_key = String::new();
        for (n, &i) in at.iter().enumerate() {
            let (key, value) = &pairs[i];
            let end = at.get(n + 1).copied().unwrap_or(pairs.len());
            let tree = Box::pin(self.build_layer(&pairs[i + 1..end], layer - 1))
                .await?
                .map(Cid::from);

            let common = super::key::common_prefix_len(&prev_key, key);
            entries.push(TreeEntry {
                prefix_len: common as u32,
                key_suffix: key.as_bytes()[common..].to_vec(),
                value: value.clone(),
                tree,
            });
            prev_key = key.clone();
        }

        let node = MstNode { left, entries };
        Ok(Some(self.store_node(&node).await?))
    }

    /// Delete a key. Returns the new root CID (or None if tree is now empty).
    ///
    /// # Errors
    ///
    /// Returns `Error` if the key is invalid or storage fails.
    pub async fn delete(&mut self, key: &str) -> Result<Option<CidCore>, Error> {
        let root_cid = match &self.root {
            Some(cid) => *cid,
            None => return Ok(None),
        };

        let new_root = self.delete_recursive(&root_cid, key, 0).await?;

        // Check if root is now empty
        if let Some(ref cid) = new_root {
            let node = self.load_node(cid).await?;
            if node.is_empty() {
                self.root = None;
                return Ok(None);
            }
        }

        self.root = new_root;
        Ok(self.root)
    }

    async fn delete_recursive(
        &mut self,
        cid: &CidCore,
        key: &str,
        depth: usize,
    ) -> Result<Option<CidCore>, Error> {
        if depth > self.config.max_depth {
            return Err(Error::StructureViolation {
                reason: format!("max depth {} exceeded", self.config.max_depth),
            });
        }

        let node = self.load_node(cid).await?;
        let (delete_idx, exists) = node.find_insertion_point(key)?;

        if !exists {
            // Key not found, return unchanged
            return Ok(Some(*cid));
        }

        // Remove the entry
        let mut new_entries = node.entries.clone();
        new_entries.remove(delete_idx);

        // Fix prefix compression for the next entry
        if delete_idx < new_entries.len() && delete_idx > 0 {
            let mut prev_key = String::new();
            for (i, entry) in new_entries.iter().enumerate() {
                if i == delete_idx - 1 {
                    prev_key = entry.reconstruct_key(&prev_key)?;
                    break;
                }
                prev_key = entry.reconstruct_key(&prev_key)?;
            }

            let next_entry = &new_entries[delete_idx];
            // Reconstruct with old prefix logic then recompute
            let old_prev = if delete_idx > 0 {
                let mut k = String::new();
                for (i, entry) in node.entries.iter().enumerate() {
                    if i == delete_idx {
                        break;
                    }
                    k = entry.reconstruct_key(&k)?;
                }
                k
            } else {
                String::new()
            };

            let next_key = node.entries[delete_idx + 1].reconstruct_key(&old_prev)?;
            let new_prefix_len = super::key::common_prefix_len(&prev_key, &next_key) as u32;

            new_entries[delete_idx] = TreeEntry {
                prefix_len: new_prefix_len,
                key_suffix: next_key.as_bytes()[new_prefix_len as usize..].to_vec(),
                value: next_entry.value.clone(),
                tree: next_entry.tree.clone(),
            };
        } else if delete_idx == 0 && !new_entries.is_empty() {
            // First entry was deleted, next becomes first with no prefix
            let old_first_key = node.entries[0].reconstruct_key("")?;
            let next_key = node.entries[1].reconstruct_key(&old_first_key)?;
            let next_value = new_entries[0].value.clone();
            let next_tree = new_entries[0].tree.clone();

            new_entries[0] = TreeEntry::first(&next_key, next_value);
            new_entries[0].tree = next_tree;
        }

        if new_entries.is_empty() && node.left.is_none() {
            return Ok(None);
        }

        let new_node = MstNode {
            left: node.left.clone(),
            entries: new_entries,
        };

        let new_cid = self.store_node(&new_node).await?;
        Ok(Some(new_cid))
    }

    /// Keys that are present in the tree but that ordered descent cannot find.
    ///
    /// This is the read-side detector for kan#204's read-invisibility path: a
    /// key spliced in by a non-conformant writer is still *visited* by a full
    /// walk, but sits at a tree position inconsistent with key order, so `get`
    /// — and therefore the fold — cannot reach it. Such a claim is in the log
    /// and invisible, which is precisely the failure this crate exists to
    /// prevent.
    ///
    /// Cheap in the common case: a conformant tree's walk is strictly
    /// ascending, and that check is one comparison per adjacent pair over a
    /// walk the caller has usually just done. The O(n) `get` sweep runs only
    /// once disorder has already been seen.
    ///
    /// A write repairs this — `insert` sorts before rebuilding — so callers
    /// should report it and carry on rather than refusing to read.
    ///
    /// # Errors
    ///
    /// Returns `Error` if traversal fails.
    pub async fn unreachable_by_ordered_descent(&self) -> Result<Vec<String>, Error> {
        let walk = self.entries().await?;
        self.unreachable_among(&walk).await
    }

    /// As [`Self::unreachable_by_ordered_descent`], over a walk the caller
    /// already has.
    ///
    /// Callers on the read path have just walked the tree; re-walking to check
    /// an invariant that (see
    /// `tests/mst_conformance.rs::no_reachable_state_leaves_a_claim_invisible`)
    /// no released binary can violate would double the cost of every read to
    /// pay for a check that never fires.
    ///
    /// # Errors
    ///
    /// Returns `Error` if a lookup fails.
    pub async fn unreachable_among(&self, walk: &[(String, Cid)]) -> Result<Vec<String>, Error> {
        if walk.windows(2).all(|w| w[0].0 < w[1].0) {
            return Ok(Vec::new());
        }

        let mut lost = Vec::new();
        for (key, _) in walk {
            if self.get(key).await?.is_none() {
                lost.push(key.clone());
            }
        }
        Ok(lost)
    }

    /// Iterate over all key-value pairs in sorted order.
    ///
    /// Returns pairs as `(key, cid)`.
    ///
    /// # Errors
    ///
    /// Returns `Error` if traversal fails.
    pub async fn entries(&self) -> Result<Vec<(String, Cid)>, Error> {
        let mut results = Vec::new();

        if let Some(ref root_cid) = self.root {
            self.collect_entries(root_cid, &mut results, 0).await?;
        }

        Ok(results)
    }

    async fn collect_entries(
        &self,
        cid: &CidCore,
        results: &mut Vec<(String, Cid)>,
        depth: usize,
    ) -> Result<(), Error> {
        if depth > self.config.max_depth {
            return Err(Error::StructureViolation {
                reason: format!("max depth {} exceeded", self.config.max_depth),
            });
        }

        let node = self.load_node(cid).await?;

        // First, traverse left subtree
        if let Some(ref left_cid) = node.left {
            Box::pin(self.collect_entries(left_cid, results, depth + 1)).await?;
        }

        // Then collect entries from this node, traversing subtrees in order
        let mut prev_key = String::new();
        for entry in &node.entries {
            let key = entry.reconstruct_key(&prev_key)?;
            results.push((key.clone(), entry.value.clone()));

            if let Some(ref tree_cid) = entry.tree {
                Box::pin(self.collect_entries(tree_cid, results, depth + 1)).await?;
            }

            prev_key = key;
        }

        Ok(())
    }

    /// Get all entries in a collection (by NSID prefix).
    ///
    /// # Errors
    ///
    /// Returns `Error` if traversal fails.
    pub async fn list_collection(&self, collection: &str) -> Result<Vec<(String, Cid)>, Error> {
        let entries = self.entries().await?;
        let prefix = format!("{}/", collection);

        Ok(entries
            .into_iter()
            .filter(|(key, _)| key.starts_with(&prefix))
            .collect())
    }

    /// Replace the live key set with an explicitly supplied canonical set.
    /// Record blocks remain in storage; only the root and MST node blocks
    /// change. Used by collection migrations that must remove an entire old
    /// namespace without relying on a sequence of shape-sensitive deletes.
    pub(crate) async fn replace_entries(
        &mut self,
        mut pairs: Vec<(String, Cid)>,
    ) -> Result<Option<CidCore>, Error> {
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
        if let Some(window) = pairs.windows(2).find(|window| window[0].0 == window[1].0) {
            return Err(Error::StructureViolation {
                reason: format!("duplicate key {} in replacement set", window[0].0),
            });
        }
        let root = self.build_canonical(&pairs).await?;
        if let Some(root) = &root {
            let rebuilt = self.collect_keys(root).await?;
            let expected: Vec<&String> = pairs.iter().map(|(key, _)| key).collect();
            if rebuilt.iter().collect::<Vec<_>>() != expected {
                return Err(Error::StructureViolation {
                    reason: "canonical replacement changed the key set".into(),
                });
            }
        } else if !pairs.is_empty() {
            return Err(Error::StructureViolation {
                reason: "canonical replacement lost a non-empty key set".into(),
            });
        }
        self.root = root;
        Ok(root)
    }
}

/// Convenience type alias for in-memory MST.
pub type MemoryMst = Mst<MemoryStorage>;

impl MemoryMst {
    /// Create an empty in-memory MST.
    #[must_use]
    pub fn new_in_memory() -> Self {
        Self::new(MemoryStorage::new(), MstConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atproto_repo::compute_cid;

    fn test_cid(data: &[u8]) -> Cid {
        compute_cid(data).into()
    }

    #[tokio::test]
    async fn test_empty_tree() {
        let mst = MemoryMst::new_in_memory();
        assert!(mst.is_empty());
        assert!(mst.root().is_none());

        let result = mst.get("any/key").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_insert_and_get() {
        let mut mst = MemoryMst::new_in_memory();

        let cid = test_cid(b"value");
        mst.insert("app.bsky.feed.post/abc", cid.clone())
            .await
            .unwrap();

        assert!(!mst.is_empty());

        let result = mst.get("app.bsky.feed.post/abc").await.unwrap();
        assert_eq!(result, Some(cid));
    }

    #[tokio::test]
    async fn test_insert_multiple() {
        let mut mst = MemoryMst::new_in_memory();

        let cids: Vec<Cid> = (0..5)
            .map(|i| test_cid(format!("v{}", i).as_bytes()))
            .collect();

        for (i, cid) in cids.iter().enumerate() {
            let key = format!("app.bsky.feed.post/{}", i);
            mst.insert(&key, cid.clone()).await.unwrap();
        }

        // Verify all inserted
        for (i, cid) in cids.iter().enumerate() {
            let key = format!("app.bsky.feed.post/{}", i);
            let result = mst.get(&key).await.unwrap();
            assert_eq!(result, Some(cid.clone()));
        }
    }

    #[tokio::test]
    async fn test_update_existing() {
        let mut mst = MemoryMst::new_in_memory();

        let cid1 = test_cid(b"v1");
        let cid2 = test_cid(b"v2");

        mst.insert("app.bsky.feed.post/abc", cid1).await.unwrap();
        mst.insert("app.bsky.feed.post/abc", cid2.clone())
            .await
            .unwrap();

        let result = mst.get("app.bsky.feed.post/abc").await.unwrap();
        assert_eq!(result, Some(cid2));
    }

    #[tokio::test]
    async fn test_delete() {
        let mut mst = MemoryMst::new_in_memory();

        let cid = test_cid(b"value");
        mst.insert("app.bsky.feed.post/abc", cid).await.unwrap();

        let new_root = mst.delete("app.bsky.feed.post/abc").await.unwrap();
        assert!(new_root.is_none());
        assert!(mst.is_empty());
    }

    #[tokio::test]
    async fn test_delete_nonexistent() {
        let mut mst = MemoryMst::new_in_memory();

        let cid = test_cid(b"value");
        mst.insert("app.bsky.feed.post/abc", cid).await.unwrap();

        // Delete non-existent key
        mst.delete("app.bsky.feed.post/xyz").await.unwrap();

        // Original should still exist
        assert!(!mst.is_empty());
    }

    #[tokio::test]
    async fn test_entries() {
        let mut mst = MemoryMst::new_in_memory();

        let keys = vec![
            "app.bsky.feed.post/c",
            "app.bsky.feed.post/a",
            "app.bsky.feed.post/b",
        ];

        for key in &keys {
            let cid = test_cid(key.as_bytes());
            mst.insert(key, cid).await.unwrap();
        }

        let entries = mst.entries().await.unwrap();
        assert_eq!(entries.len(), 3);

        // Should be sorted
        let entry_keys: Vec<&str> = entries.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            entry_keys,
            vec![
                "app.bsky.feed.post/a",
                "app.bsky.feed.post/b",
                "app.bsky.feed.post/c"
            ]
        );
    }

    #[tokio::test]
    async fn test_list_collection() {
        let mut mst = MemoryMst::new_in_memory();

        mst.insert("app.bsky.feed.post/a", test_cid(b"1"))
            .await
            .unwrap();
        mst.insert("app.bsky.feed.post/b", test_cid(b"2"))
            .await
            .unwrap();
        mst.insert("app.bsky.graph.follow/c", test_cid(b"3"))
            .await
            .unwrap();

        let posts = mst.list_collection("app.bsky.feed.post").await.unwrap();
        assert_eq!(posts.len(), 2);

        let follows = mst.list_collection("app.bsky.graph.follow").await.unwrap();
        assert_eq!(follows.len(), 1);
    }
}

//! Content-addressed bounded-path map for serving metadata commitments.
//!
//! A root authenticates contents, NOT authority or freshness. The consuming
//! service must bind it to a validated checkpoint, archive and current custody.
//! This codec does not open a database, sign a checkpoint or admit evidence.
use sha2::{Digest as _, Sha256};

pub type Digest = [u8; 32];
pub const MAX_VALUE: usize = 4096;
pub const MAX_NODE: usize = 37 + MAX_VALUE;
pub const MAX_PATH: usize = 257;
const NODE_DOMAIN: &[u8] = b"tools.kan.serving-index.node.v1\0";
const KEY_DOMAIN: &[u8] = b"tools.kan.serving-index.key.v1\0";
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("serving index node unavailable")]
    Missing,
    #[error("serving index is corrupt")]
    Corrupt,
    #[error("serving index input exceeds its bound")]
    Limit,
    #[error("serving index store unavailable")]
    Store,
}
pub type Result<T> = std::result::Result<T, Error>;
/// The storage adapter owns transactions and persistence capabilities. It must
/// bound a read to MAX_NODE bytes before allocating an untrusted block.
pub trait Blocks {
    fn read(&mut self, id: &Digest) -> Result<Option<Vec<u8>>>;
    /// Store immutable bytes at their digest; an existing different value fails.
    fn write(&mut self, id: Digest, bytes: &[u8]) -> Result<()>;
}
pub fn key(namespace: &[u8], opaque: &[u8]) -> Result<Digest> {
    if namespace.is_empty() || namespace.len() > 64 || opaque.len() > 4096 {
        return Err(Error::Limit);
    }
    let mut hash = Sha256::new();
    hash.update(KEY_DOMAIN);
    hash.update((namespace.len() as u16).to_be_bytes());
    hash.update(namespace);
    hash.update((opaque.len() as u32).to_be_bytes());
    hash.update(opaque);
    Ok(hash.finalize().into())
}
pub fn node_digest(bytes: &[u8]) -> Result<Digest> {
    if bytes.len() > MAX_NODE {
        return Err(Error::Limit);
    }
    let mut hash = Sha256::new();
    hash.update(NODE_DOMAIN);
    hash.update(bytes);
    Ok(hash.finalize().into())
}
fn bit(key: &Digest, at: u16) -> bool {
    key[usize::from(at) / 8] & (0x80 >> (at % 8)) != 0
}
fn prefix(key: &Digest, bits: u16) -> Digest {
    let mut out = *key;
    for n in bits..256 {
        out[usize::from(n) / 8] &= !(0x80 >> (n % 8));
    }
    out
}
fn difference(a: &Digest, b: &Digest) -> u16 {
    for (n, (a, b)) in a.iter().zip(b).enumerate() {
        let xor = a ^ b;
        if xor != 0 {
            return n as u16 * 8 + xor.leading_zeros() as u16;
        }
    }
    256
}
#[derive(Clone)]
struct Branch {
    at: u16,
    prefix: Digest,
    left: Digest,
    right: Digest,
}
enum Node {
    Leaf { key: Digest, value: Vec<u8> },
    Branch(Branch),
}
impl Node {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        match self {
            Self::Leaf { key, value } => {
                bytes.push(0);
                bytes.extend(key);
                bytes.extend((value.len() as u32).to_be_bytes());
                bytes.extend(value);
            }
            Self::Branch(b) => {
                bytes.push(1);
                bytes.extend(b.at.to_be_bytes());
                bytes.extend(b.prefix);
                bytes.extend(b.left);
                bytes.extend(b.right);
            }
        }
        bytes
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_NODE {
            return Err(Error::Limit);
        }
        match bytes.first() {
            Some(0) if bytes.len() >= 37 => {
                let key = bytes[1..33].try_into().map_err(|_| Error::Corrupt)?;
                let length =
                    u32::from_be_bytes(bytes[33..37].try_into().map_err(|_| Error::Corrupt)?)
                        as usize;
                if length > MAX_VALUE || length != bytes.len() - 37 {
                    return Err(Error::Corrupt);
                }
                Ok(Self::Leaf {
                    key,
                    value: bytes[37..].to_vec(),
                })
            }
            Some(1) if bytes.len() == 99 => {
                let b = Branch {
                    at: u16::from_be_bytes(bytes[1..3].try_into().map_err(|_| Error::Corrupt)?),
                    prefix: bytes[3..35].try_into().map_err(|_| Error::Corrupt)?,
                    left: bytes[35..67].try_into().map_err(|_| Error::Corrupt)?,
                    right: bytes[67..99].try_into().map_err(|_| Error::Corrupt)?,
                };
                if b.at >= 256 || prefix(&b.prefix, b.at) != b.prefix || b.left == b.right {
                    return Err(Error::Corrupt);
                }
                Ok(Self::Branch(b))
            }
            _ => Err(Error::Corrupt),
        }
    }
    fn position(&self) -> (u16, &Digest) {
        match self {
            Self::Leaf { key, .. } => (256, key),
            Self::Branch(b) => (b.at, &b.prefix),
        }
    }
    fn child_of(&self, parent: &Branch, right: bool) -> Result<()> {
        let (at, key) = self.position();
        if at <= parent.at
            || prefix(key, parent.at) != parent.prefix
            || bit(key, parent.at) != right
        {
            return Err(Error::Corrupt);
        }
        Ok(())
    }
}
fn read(blocks: &mut impl Blocks, id: &Digest, parent: Option<(&Branch, bool)>) -> Result<Node> {
    let bytes = blocks.read(id)?.ok_or(Error::Missing)?;
    if node_digest(&bytes)? != *id {
        return Err(Error::Corrupt);
    }
    let node = Node::decode(&bytes)?;
    if let Some((parent, right)) = parent {
        node.child_of(parent, right)?;
    }
    Ok(node)
}
fn write(blocks: &mut impl Blocks, node: Node) -> Result<Digest> {
    let bytes = node.encode();
    let id = node_digest(&bytes)?;
    blocks.write(id, &bytes)?;
    Ok(id)
}
/// Immutable roots can be read concurrently through independent store handles.
/// A failed insert retains this handle's old root; callers publish the new root
/// only in their archive/checkpoint transaction after success.
pub struct Map<S> {
    blocks: S,
    root: Option<Digest>,
}
impl<S: Blocks> Map<S> {
    pub fn new(blocks: S, root: Option<Digest>) -> Self {
        Self { blocks, root }
    }
    pub fn root(&self) -> Option<Digest> {
        self.root
    }
    pub fn into_blocks(self) -> S {
        self.blocks
    }
    pub fn get(&mut self, key: &Digest) -> Result<Option<Vec<u8>>> {
        let Some(mut id) = self.root else {
            return Ok(None);
        };
        let mut parent: Option<(Branch, bool)> = None;
        for _ in 0..MAX_PATH {
            let node = read(&mut self.blocks, &id, parent.as_ref().map(|(b, r)| (b, *r)))?;
            match node {
                Node::Leaf { key: actual, value } => return Ok((actual == *key).then_some(value)),
                Node::Branch(b) => {
                    if prefix(key, b.at) != b.prefix {
                        return Ok(None);
                    }
                    let right = bit(key, b.at);
                    id = if right { b.right } else { b.left };
                    parent = Some((b, right));
                }
            }
        }
        Err(Error::Corrupt)
    }
    pub fn insert(&mut self, key: Digest, value: &[u8]) -> Result<Digest> {
        if value.len() > MAX_VALUE {
            return Err(Error::Limit);
        }
        let leaf = Node::Leaf {
            key,
            value: value.to_vec(),
        };
        let Some(mut id) = self.root else {
            let root = write(&mut self.blocks, leaf)?;
            self.root = Some(root);
            return Ok(root);
        };
        let mut path: Vec<(Branch, bool)> = Vec::new();
        let mut root = loop {
            if path.len() >= MAX_PATH {
                return Err(Error::Corrupt);
            }
            let node = read(&mut self.blocks, &id, path.last().map(|(b, r)| (b, *r)))?;
            let (at, existing) = node.position();
            let split = difference(&key, existing);
            if split < at {
                let new = write(&mut self.blocks, leaf)?;
                let (left, right) = if bit(&key, split) {
                    (id, new)
                } else {
                    (new, id)
                };
                break write(
                    &mut self.blocks,
                    Node::Branch(Branch {
                        at: split,
                        prefix: prefix(&key, split),
                        left,
                        right,
                    }),
                )?;
            }
            match node {
                Node::Leaf { .. } => break write(&mut self.blocks, leaf)?,
                Node::Branch(b) => {
                    let right = bit(&key, b.at);
                    id = if right { b.right } else { b.left };
                    path.push((b, right));
                }
            }
        };
        for (mut parent, right) in path.into_iter().rev() {
            if right {
                parent.right = root;
            } else {
                parent.left = root;
            }
            root = write(&mut self.blocks, Node::Branch(parent))?;
        }
        self.root = Some(root);
        Ok(root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    #[derive(Clone, Default)]
    struct Memory {
        blocks: BTreeMap<Digest, Vec<u8>>,
        reads: usize,
        writes: usize,
        fail_after: Option<usize>,
    }
    impl Blocks for Memory {
        fn read(&mut self, id: &Digest) -> Result<Option<Vec<u8>>> {
            self.reads += 1;
            Ok(self.blocks.get(id).cloned())
        }
        fn write(&mut self, id: Digest, bytes: &[u8]) -> Result<()> {
            if self.fail_after == Some(self.writes) {
                return Err(Error::Store);
            }
            self.writes += 1;
            if self.blocks.get(&id).is_some_and(|old| old != bytes) {
                return Err(Error::Corrupt);
            }
            self.blocks.insert(id, bytes.to_vec());
            Ok(())
        }
    }
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    fn unhex(value: &str) -> Vec<u8> {
        (0..value.len())
            .step_by(2)
            .map(|n| u8::from_str_radix(&value[n..n + 2], 16).unwrap())
            .collect()
    }
    fn digest(value: &str) -> Digest {
        unhex(value).try_into().unwrap()
    }
    #[test]
    fn incremental_roots_and_blocks_match_independent_full_set_vectors_in_both_orders() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/serving-index-v1.json")).unwrap();
        let v = &vectors["derived_key"];
        assert_eq!(
            hex(&key(
                &unhex(v["namespace"].as_str().unwrap()),
                &unhex(v["opaque"].as_str().unwrap())
            )
            .unwrap()),
            v["key"]
        );
        let mut map = Map::new(Memory::default(), None);
        assert!(map.root().is_none());
        assert_eq!(map.get(&[0; 32]).unwrap(), None);
        assert_eq!(map.blocks.reads, 0);
        for step in vectors["steps"].as_array().unwrap() {
            let root = map
                .insert(
                    digest(step["key"].as_str().unwrap()),
                    &unhex(step["value"].as_str().unwrap()),
                )
                .unwrap();
            assert_eq!(hex(&root), step["root"]);
            for (id, body) in step["blocks"].as_object().unwrap() {
                assert_eq!(
                    hex(map.blocks.blocks.get(&digest(id)).unwrap()),
                    body.as_str().unwrap()
                );
            }
            for (key, value) in step["entries"].as_object().unwrap() {
                assert_eq!(
                    map.get(&digest(key)).unwrap(),
                    Some(unhex(value.as_str().unwrap()))
                );
            }
            let mut reversed = Map::new(Memory::default(), None);
            for (key, value) in step["entries"].as_object().unwrap().iter().rev() {
                reversed
                    .insert(digest(key), &unhex(value.as_str().unwrap()))
                    .unwrap();
            }
            assert_eq!(reversed.root(), Some(root));
        }
    }
    #[test]
    fn deepest_valid_path_has_fixed_work_and_old_roots_survive_updates() {
        let mut map = Map::new(Memory::default(), None);
        map.insert([0; 32], b"original").unwrap();
        for at in 0..256 {
            let mut key = [0; 32];
            key[at / 8] = 0x80 >> (at % 8);
            map.insert(key, b"sibling").unwrap();
        }
        map.blocks.reads = 0;
        assert_eq!(map.get(&[0; 32]).unwrap(), Some(b"original".to_vec()));
        assert_eq!(map.blocks.reads, MAX_PATH);
        let old = map.root();
        map.blocks.reads = 0;
        map.blocks.writes = 0;
        map.insert([0; 32], b"changed").unwrap();
        assert_eq!(map.blocks.reads, MAX_PATH);
        assert_eq!(map.blocks.writes, MAX_PATH);
        let mut original = Map::new(map.blocks.clone(), old);
        assert_eq!(original.get(&[0; 32]).unwrap(), Some(b"original".to_vec()));
        assert_eq!(map.get(&[0; 32]).unwrap(), Some(b"changed".to_vec()));
        let root = map.root();
        assert_eq!(
            map.insert([1; 32], &vec![0; MAX_VALUE + 1]),
            Err(Error::Limit)
        );
        assert_eq!(map.root(), root);
    }
    #[test]
    fn missing_or_substituted_nodes_never_become_absence() {
        let mut map = Map::new(Memory::default(), None);
        map.insert([0; 32], b"first").unwrap();
        map.insert([128; 32], b"second").unwrap();
        let root = map.root().unwrap();
        let mut missing = map.blocks.clone();
        missing.blocks.remove(&root);
        assert_eq!(
            Map::new(missing, Some(root)).get(&[0; 32]),
            Err(Error::Missing)
        );
        let mut bad = map.blocks.clone();
        bad.blocks.get_mut(&root).unwrap()[0] ^= 1;
        assert_eq!(Map::new(bad, Some(root)).get(&[0; 32]), Err(Error::Corrupt));
        // A valid hash is not enough: child prefixes must agree with the path.
        let mut blocks = Memory::default();
        let left = write(
            &mut blocks,
            Node::Leaf {
                key: [128; 32],
                value: vec![1],
            },
        )
        .unwrap();
        let right = write(
            &mut blocks,
            Node::Leaf {
                key: [129; 32],
                value: vec![2],
            },
        )
        .unwrap();
        let root = write(
            &mut blocks,
            Node::Branch(Branch {
                at: 0,
                prefix: [0; 32],
                left,
                right,
            }),
        )
        .unwrap();
        assert_eq!(
            Map::new(blocks, Some(root)).get(&[0; 32]),
            Err(Error::Corrupt)
        );
        let mut bytes = Node::Branch(Branch {
            at: 0,
            prefix: [1; 32],
            left,
            right,
        })
        .encode();
        assert!(Node::decode(&bytes).is_err());
        bytes[1..3].copy_from_slice(&256u16.to_be_bytes());
        assert!(Node::decode(&bytes).is_err());
    }
    #[test]
    fn interrupted_path_write_preserves_accepted_root_and_can_retry() {
        let mut original = Map::new(Memory::default(), None);
        original.insert([0; 32], b"zero").unwrap();
        original.insert([128; 32], b"high").unwrap();
        let old = original.root();
        for fail in 0..3 {
            let mut blocks = original.blocks.clone();
            blocks.writes = 0;
            blocks.fail_after = Some(fail);
            let mut map = Map::new(blocks, old);
            assert_eq!(map.insert([1; 32], b"new"), Err(Error::Store));
            assert_eq!(map.root(), old);
            assert_eq!(map.get(&[0; 32]).unwrap(), Some(b"zero".to_vec()));
            assert_eq!(map.get(&[1; 32]).unwrap(), None);
            map.blocks.fail_after = None;
            map.insert([1; 32], b"new").unwrap();
            assert_eq!(map.get(&[1; 32]).unwrap(), Some(b"new".to_vec()));
        }
    }
}

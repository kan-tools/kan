//! Content addressing for `ClaimContent` (`docs/SPEC.md` §3): canonical
//! DAG-CBOR of the content, hashed with the same recipe `atrium-repo`'s own
//! blockstores use (SHA2-256, DAG-CBOR codec `0x71`) — so a claim's
//! `content_cid` is byte-for-byte the CID that would result from writing
//! those same bytes into the log's blockstore.

use ipld_core::cid::{multihash::Multihash, Cid};
use serde::Serialize;
use sha2::Digest;

const DAG_CBOR: u64 = 0x71;
const SHA2_256: u64 = 0x12;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("DAG-CBOR encoding failed: {0}")]
    Encode(#[from] serde_ipld_dagcbor::EncodeError<std::collections::TryReserveError>),
}

/// Canonical DAG-CBOR bytes of `content`. Excludes any signature — callers
/// sign the *CID* of these bytes, not the bytes themselves (§3).
pub fn canonical_bytes<T: Serialize>(content: &T) -> Result<Vec<u8>, Error> {
    Ok(serde_ipld_dagcbor::to_vec(content)?)
}

/// The content-addressed identity of `content` — what other claims cite, and
/// what a claim's signature signs.
pub fn content_cid<T: Serialize>(content: &T) -> Result<Cid, Error> {
    let bytes = canonical_bytes(content)?;
    let digest = sha2::Sha256::digest(&bytes);
    let hash = Multihash::wrap(SHA2_256, digest.as_slice()).expect("sha2-256 digest is 32 bytes");
    Ok(Cid::new_v1(DAG_CBOR, hash))
}

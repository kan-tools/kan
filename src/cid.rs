//! Content addressing for `ClaimContent` (`docs/SPEC.md` §3): canonical
//! DAG-CBOR of the content, hashed as CIDv1/DAG-CBOR/SHA2-256 — the exact
//! recipe `atproto_repo::compute_cid_for` implements, "the blessed CID
//! format used by AT Protocol." A claim's `content_cid` is byte-for-byte
//! the CID that would result from writing those same bytes into the log's
//! blockstore (ADR-12).

use atproto_dasl::Cid;
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("DAG-CBOR encoding failed: {0}")]
    Encode(#[from] atproto_dasl::EncodeError),
}

/// Canonical DAG-CBOR bytes of `content`. Excludes any signature — callers
/// sign the *CID* of these bytes, not the bytes themselves (§3).
pub fn canonical_bytes<T: Serialize>(content: &T) -> Result<Vec<u8>, Error> {
    Ok(atproto_dasl::to_vec(content)?)
}

/// The content-addressed identity of `content` — what other claims cite, and
/// what a claim's signature signs.
pub fn content_cid<T: Serialize>(content: &T) -> Result<Cid, Error> {
    Ok(Cid::from(atproto_dasl::compute_cid_for(content)?))
}

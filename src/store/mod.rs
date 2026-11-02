pub mod index;
pub mod log;
mod tid;
// Shared canonical revision encoding for v1-compatible record envelopes.
#[cfg(feature = "v2-crypto")]
pub(crate) use tid::encode as encode_tid;

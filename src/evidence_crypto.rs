//! Bounded recipient-only HPKE chunks. Keys and plaintext lifetime belong to callers.
use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem, OpModeR,
    OpModeS, Serializable,
};
use sha2::{Digest, Sha256};
type K = X25519HkdfSha256;
const PREFIX: &[u8] = b"KANE\x01\x00\x20\x00\x01\x00\x03";
pub const HEADER: usize = 11 + 32 + 32 + 4;
pub const MAX_PLAINTEXT: usize = crate::evidence_service::MAX_PAYLOAD - HEADER - 16;
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("invalid encrypted chunk framing or size")]
    Invalid,
    #[error("recipient encryption failed")]
    Seal,
    #[error("encrypted chunk authentication failed")]
    Authentication,
}
fn info(scope: &[u8; 32]) -> Vec<u8> {
    let mut info = b"tools.kan.archive.hpke.v1\0".to_vec();
    info.extend_from_slice(scope);
    info
}
/// A fresh HPKE context and encapsulated key for each chunk. No private recipient key.
/// The HPKE library panics if operating-system randomness is unavailable.
pub fn seal(recipient: &[u8; 32], scope: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    if plaintext.len() > MAX_PLAINTEXT {
        return Err(Error::Invalid);
    }
    let recipient_key = <K as Kem>::PublicKey::from_bytes(recipient).map_err(|_| Error::Seal)?;
    let (enc, mut context) = hpke::setup_sender::<ChaCha20Poly1305, HkdfSha256, K>(
        &OpModeS::Base,
        &recipient_key,
        &info(scope),
    )
    .map_err(|_| Error::Seal)?;
    let mut frame = Vec::with_capacity(HEADER + plaintext.len() + 16);
    frame.extend_from_slice(PREFIX);
    frame.extend_from_slice(&Sha256::digest(recipient));
    frame.extend_from_slice(&enc.to_bytes());
    frame.extend_from_slice(&((plaintext.len() + 16) as u32).to_be_bytes());
    let ciphertext = context.seal(plaintext, &frame).map_err(|_| Error::Seal)?;
    frame.extend_from_slice(&ciphertext);
    Ok(frame)
}
/// Returns plaintext only after header, recipient, scope and AEAD authentication.
pub fn open(private: &[u8; 32], scope: &[u8; 32], frame: &[u8]) -> Result<Vec<u8>, Error> {
    if frame.len() < HEADER + 16
        || frame.len() > crate::evidence_service::MAX_PAYLOAD
        || !frame.starts_with(PREFIX)
    {
        return Err(Error::Invalid);
    }
    let length = u32::from_be_bytes(
        frame[HEADER - 4..HEADER]
            .try_into()
            .map_err(|_| Error::Invalid)?,
    ) as usize;
    if length != frame.len() - HEADER {
        return Err(Error::Invalid);
    }
    let key = <K as Kem>::PrivateKey::from_bytes(private).map_err(|_| Error::Authentication)?;
    let public = K::sk_to_pk(&key).to_bytes();
    if Sha256::digest(public).as_slice() != &frame[11..43] {
        return Err(Error::Authentication);
    }
    let enc =
        <K as Kem>::EncappedKey::from_bytes(&frame[43..75]).map_err(|_| Error::Authentication)?;
    let mut context = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, K>(
        &OpModeR::Base,
        &key,
        &enc,
        &info(scope),
    )
    .map_err(|_| Error::Authentication)?;
    context
        .open(&frame[HEADER..], &frame[..HEADER])
        .map_err(|_| Error::Authentication)
}
/// Derive public recipient bytes for a caller-supplied key; no key persistence.
pub fn public_key(private: &[u8; 32]) -> Result<[u8; 32], Error> {
    let key = <K as Kem>::PrivateKey::from_bytes(private).map_err(|_| Error::Invalid)?;
    K::sk_to_pk(&key)
        .to_bytes()
        .as_slice()
        .try_into()
        .map_err(|_| Error::Invalid)
}

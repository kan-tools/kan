//! Crate spike for `hkdf` and `x25519-dalek`, run **before** building the
//! seed root on them — `CLAUDE.md`'s rule after ADR-11/12, where a storage
//! crate's documented behaviour and its actual behaviour differed in a way
//! that destroyed data, and the lesson recorded was to verify first rather
//! than after.
//!
//! These assert the properties `.design/v0.9-milestone.md` REQ-4/REQ-5
//! actually depend on, not that the crates work in general.

use hkdf::Hkdf;
use sha2::Sha256;

/// Derive `N` bytes from a seed under a labelled context.
fn derive<const N: usize>(seed: &[u8], info: &str) -> [u8; N] {
    let hk = Hkdf::<Sha256>::new(None, seed);
    let mut out = [0u8; N];
    hk.expand(info.as_bytes(), &mut out)
        .expect("HKDF expand length is within the SHA-256 limit");
    out
}

/// The property every other one rests on: same seed and label, same bytes,
/// on any machine and any run. A recovery phrase that reproduced a *nearly*
/// identical key would be worse than one that failed outright.
#[test]
fn derivation_is_deterministic() {
    let seed = [7u8; 32];
    assert_eq!(
        derive::<32>(&seed, "kan/v1/sign"),
        derive::<32>(&seed, "kan/v1/sign")
    );
    assert_eq!(
        derive::<32>(&seed, "kan/v1/encrypt"),
        derive::<32>(&seed, "kan/v1/encrypt")
    );
}

/// REQ-5's core claim: the signing and encryption keys are **independently
/// derived**, not one converted from the other.
///
/// This is the Ed25519→X25519 conversion footgun avoided by construction —
/// the labels separate the two key spaces, so compromise of one does not
/// hand over the other, and neither is a function of the other.
#[test]
fn the_two_key_slots_are_independent() {
    let seed = [7u8; 32];
    let signing = derive::<32>(&seed, "kan/v1/sign");
    let encryption = derive::<32>(&seed, "kan/v1/encrypt");
    assert_ne!(
        signing, encryption,
        "two labels produced identical key material -- the labels are not separating anything"
    );

    // And a different seed moves both, so neither is a constant that only
    // looks derived.
    let other = derive::<32>(&[8u8; 32], "kan/v1/sign");
    assert_ne!(signing, other);
}

/// A one-bit change in the seed changes the derived key completely, so a
/// corrupted seed file fails loudly at the DID rather than producing a
/// plausible neighbouring key.
#[test]
fn a_changed_seed_changes_the_key() {
    let mut seed = [7u8; 32];
    let before = derive::<32>(&seed, "kan/v1/sign");
    seed[0] ^= 1;
    let after = derive::<32>(&seed, "kan/v1/sign");
    let shared = before
        .iter()
        .zip(after.iter())
        .filter(|(a, b)| a == b)
        .count();
    assert!(
        shared < 8,
        "flipping one seed bit left {shared}/32 bytes identical -- that is not a KDF"
    );
}

/// `x25519_dalek::StaticSecret` accepts arbitrary 32 bytes and clamps them
/// internally, so HKDF output can be used directly without kan doing its own
/// bit-twiddling — the part most likely to be got subtly wrong by hand.
#[test]
fn x25519_accepts_derived_bytes_and_produces_a_stable_public_key() {
    let seed = [7u8; 32];
    let bytes = derive::<32>(&seed, "kan/v1/encrypt");

    let secret = x25519_dalek::StaticSecret::from(bytes);
    let public = x25519_dalek::PublicKey::from(&secret);

    // Deriving twice gives the same public key: the recipient identifier is
    // reproducible from the phrase, which is what makes an encrypted backup
    // recoverable at all.
    let again = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(bytes));
    assert_eq!(public.as_bytes(), again.as_bytes());

    // And it is a real key exchange, not just bytes: two parties agree.
    let theirs = x25519_dalek::StaticSecret::from(derive::<32>(&[9u8; 32], "kan/v1/encrypt"));
    let their_public = x25519_dalek::PublicKey::from(&theirs);
    assert_eq!(
        secret.diffie_hellman(&their_public).as_bytes(),
        theirs.diffie_hellman(&public).as_bytes(),
        "the two sides did not agree on a shared secret"
    );
}

/// The one real hazard in deriving a **P-256** signing key from arbitrary
/// bytes: a valid scalar must lie in `[1, n-1]`, and 32 random bytes can
/// land outside that range.
///
/// The probability is negligible (~2^-32) but not zero, and "negligible"
/// is not a property a recovery path may rest on — a user whose phrase
/// happened to derive an out-of-range scalar would have an unrecoverable
/// identity. This asserts the failure is *detectable* (import returns an
/// error rather than silently producing a different key), which is what
/// makes a retry-with-counter derivation safe.
#[test]
fn an_invalid_p256_scalar_is_rejected_rather_than_coerced() {
    use atrium_crypto::keypair::P256Keypair;

    // All-zero is not a valid scalar.
    assert!(
        P256Keypair::import(&[0u8; 32]).is_err(),
        "a zero scalar was accepted -- an out-of-range derivation would pass silently"
    );
    // All-ones exceeds the curve order.
    assert!(
        P256Keypair::import(&[0xffu8; 32]).is_err(),
        "an over-order scalar was accepted -- the retry guard would never fire"
    );
    // A derived key in range imports fine.
    assert!(P256Keypair::import(&derive::<32>(&[7u8; 32], "kan/v1/sign")).is_ok());
}

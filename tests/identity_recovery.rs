//! Recovery phrase — the durability story for the signing key.
//!
//! This matters more than it looks. Making the key encrypted at rest means
//! deleting the plaintext copy once the keychain holds it, so `.kan/` is now
//! the only place the key lives on disk. Losing that directory takes the
//! identity with it — and because `TrustBase::Solo` trusts exactly one
//! `AuthorId`, an identity you cannot recover means every claim you ever
//! wrote drops out of every read, unretractable, under a DID that is no
//! longer yours.
//!
//! The phrase is what makes that decision safe rather than reckless.

use bip39::Language;
use kan::sign::{from_recovery_phrase, recovery_phrase, Identity};

const FIXED_PHRASE: &str = "huge similar size foam escape any exhibit forward color bounce horror \
    convince deny olympic grain garment ill embark strike during father mix brown solid";

fn with_first_word(word: &str) -> String {
    let mut words: Vec<&str> = FIXED_PHRASE.split_whitespace().collect();
    words[0] = word;
    words.join(" ")
}

#[test]
fn a_phrase_round_trips_to_the_same_identity() {
    let identity = Identity::generate();
    let phrase = recovery_phrase(&identity).unwrap();

    assert_eq!(
        phrase.split_whitespace().count(),
        24,
        "a P-256 key is 32 bytes, which is BIP-39's 256-bit entropy size -- 24 words"
    );

    let restored = from_recovery_phrase(&phrase).unwrap();
    assert_eq!(
        restored.did(),
        identity.did(),
        "the phrase must reproduce the identity exactly, not merely a valid one"
    );
}

/// Signatures made by the restored key must verify against the original DID —
/// a phrase that gives you a same-looking identity you cannot sign with would
/// be worse than none.
#[test]
fn the_restored_key_can_still_sign_as_the_original() {
    let identity = Identity::generate();
    let phrase = recovery_phrase(&identity).unwrap();
    let restored = from_recovery_phrase(&phrase).unwrap();

    let msg = b"a claim cid";
    let sig = restored.sign(msg).unwrap();
    assert!(
        kan::sign::verify(&identity.did(), msg, &sig),
        "the restored key must sign as the identity it restores"
    );
}

/// A known checksum-invalid substitution must be rejected with an actionable
/// error. The fixed vector matters: a random valid-word substitution in a
/// 24-word BIP-39 phrase has about a 1-in-256 chance of retaining a valid
/// checksum, so randomness made the former version of this test flaky.
#[test]
fn a_known_checksum_invalid_word_substitution_is_rejected() {
    let err = from_recovery_phrase(&with_first_word("abandon"))
        .err()
        .expect("this fixed substitution must fail its checksum");
    let msg = err.to_string();
    assert!(
        msg.contains("word order") || msg.contains("checksum"),
        "the error should tell a human what to check: {msg}"
    );
}

/// BIP-39 checksums detect most, not all, valid-word substitutions. An
/// accidentally checksum-valid typo must restore a *different* identity; it
/// must never be mistaken for the original.
#[test]
fn a_checksum_valid_word_substitution_restores_a_different_identity() {
    let original = from_recovery_phrase(FIXED_PHRASE).unwrap();
    let changed = from_recovery_phrase(&with_first_word("alley")).unwrap();
    assert_ne!(changed.did(), original.did());
}

/// Exhaust the English word list at one position. This pins the finite corpus
/// rather than drawing random samples and turning BIP-39's checksum probability
/// into a flaky CI assertion.
#[test]
fn one_word_substitution_checksum_behavior_is_exhaustively_characterized() {
    let accepted: Vec<&str> = Language::English
        .word_list()
        .iter()
        .copied()
        .filter(|word| *word != "huge")
        .filter(|word| from_recovery_phrase(&with_first_word(word)).is_ok())
        .collect();

    assert_eq!(
        accepted,
        ["alley", "ankle", "birth", "demand", "exotic", "peanut", "perfect", "pull", "spread",]
    );
}

/// Word order matters, and reversing it must not quietly yield a key.
///
/// **A fixed phrase, not a generated one, and that is a bug fix.** This
/// generated a fresh identity each run and reversed its words. BIP-39's
/// checksum is 8 bits over a 24-word phrase, so a reversal it happens not to
/// catch is a 1-in-256 event — the test failed roughly every 256 runs, on a
/// property that was never in doubt. Found when it fired in a full-suite run
/// during v0.11.
///
/// The phrase below is a real one whose reversal is *verified* to fail its
/// checksum, so this tests the mechanism deterministically. What it cannot
/// test is the 255/256 — that is a property of BIP-39, not of kan, and a
/// randomised test asserting it as if it were certain is how you get a suite
/// that cries wolf.
#[test]
fn a_reordered_phrase_is_rejected() {
    let phrase = FIXED_PHRASE;
    // The fixture has to be a phrase that restores, or the assertion below
    // would pass for the wrong reason.
    assert!(
        from_recovery_phrase(phrase).is_ok(),
        "the fixture phrase should itself be valid"
    );

    let mut words: Vec<&str> = phrase.split_whitespace().collect();
    words.reverse();
    assert!(
        from_recovery_phrase(&words.join(" ")).is_err(),
        "a reordered phrase must not restore -- silently returning a different \
         identity is the failure that costs someone their whole log"
    );
}

/// Surrounding whitespace and casing are ordinary transcription artifacts of
/// reading words off paper; they must not cost someone their identity.
#[test]
fn transcription_whitespace_is_tolerated() {
    let identity = Identity::generate();
    let phrase = recovery_phrase(&identity).unwrap();
    let messy = format!("  {}  \n", phrase);
    assert_eq!(from_recovery_phrase(&messy).unwrap().did(), identity.did());
}

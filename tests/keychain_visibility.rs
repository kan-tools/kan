//! #90's fourth ask: a blocking keychain read says what it is waiting on.
//!
//! The hang itself is #96/#69 and is not fixed here — #30's per-agent
//! identity work is the real answer. What is fixed is that it stops being
//! *silent*, which is the property #90 singles out: "a hang, not a failure",
//! and a caller like `day` cannot tell one from a slow fold.
//!
//! This is not a hypothetical. Building v0.9 hit it three times in one day —
//! dogfooding the durability column against kan's own repo, and twice more
//! from tests that exercised fresh-workspace creation. Each time the symptom
//! was a command that never returned and said nothing.

use kan::sign::SlowKeychainWarning;

/// The warning fires when the operation it wraps outlives the threshold.
///
/// Driven by holding the guard rather than by a real keychain: the point
/// under test is the watchdog, and a test that needed an actually-wedged
/// keychain could not run anywhere useful — least of all on the Linux CI
/// that has no keychain at all.
#[test]
fn a_slow_keychain_call_is_announced() {
    let fired = SlowKeychainWarning::fired_after(
        std::time::Duration::from_millis(40),
        std::time::Duration::from_millis(200),
    );
    assert!(
        fired,
        "an operation that outlived the threshold produced no warning -- the hang is silent \
         again, which is exactly #90's complaint"
    );
}

/// **The negative control**, and the half that decides whether this is
/// tolerable to ship: a prompt call says nothing at all.
///
/// A warning that fired on every keychain read would be noise on the common
/// path, and noise on the common path is how a warning stops being read —
/// the same failure the durability column and the migration matrix were each
/// shaped to avoid.
#[test]
fn a_prompt_keychain_call_stays_quiet() {
    let fired = SlowKeychainWarning::fired_after(
        std::time::Duration::from_millis(200),
        std::time::Duration::from_millis(10),
    );
    assert!(
        !fired,
        "a call that returned promptly still warned -- this would fire on every read and \
         teach people to ignore it"
    );
}

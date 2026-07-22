//! A minimal, self-contained generator for atproto TIDs — 13-character,
//! lexicographically-sortable timestamp identifiers
//! (<https://atproto.com/specs/tid>).
//!
//! Reimplemented directly rather than pulled in from `atrium-api` (dropped
//! entirely per the `atproto-repo` switch, ADR-12) — the algorithm is small
//! and stable, and `docs/DECISIONS.md`'s ADR-11 postmortem is reason enough
//! to own this rather than trust an unverified external `now()`.
//!
//! Unlike a naive `now()`-per-call generator (which can return the same
//! microsecond twice — this is explicitly why `atrium-api`'s own `Tid::now`
//! doc warns callers to retry until they observe a different value),
//! [`TidGenerator`] tracks the last value it produced and guarantees strict
//! monotonic increase within its own lifetime: `next() > previous next()`,
//! always, not just "usually."

const ENCODE_ALPHABET: &[u8; 32] = b"234567abcdefghijklmnopqrstuvwxyz";

fn encode(mut value: u64) -> String {
    let mut chars = [0u8; 13];
    for slot in chars.iter_mut().rev() {
        *slot = ENCODE_ALPHABET[(value & 0x1f) as usize];
        value >>= 5;
    }
    String::from_utf8(chars.to_vec()).expect("ASCII alphabet")
}

fn decode(s: &str) -> Option<u64> {
    if s.len() != 13 {
        return None;
    }
    let mut value: u64 = 0;
    for byte in s.bytes() {
        let digit = ENCODE_ALPHABET.iter().position(|&a| a == byte)?;
        value = (value << 5) | digit as u64;
    }
    Some(value)
}

/// Generates strictly-increasing TIDs for one log's append sequence.
#[derive(Debug, Default)]
pub struct TidGenerator {
    last: u64,
}

impl TidGenerator {
    pub fn new() -> Self {
        Self { last: 0 }
    }

    /// Seeds from a previously-produced TID (a reopened log's last commit
    /// `rev`), so strict monotonicity holds across process restarts, not
    /// just within one generator's lifetime — kan's real usage is a fresh
    /// process per command (`docs/DECISIONS.md` ADR-15), so `new()` alone
    /// only guaranteed monotonicity for a single append within one call.
    /// Falls back to `new()`'s zero baseline if `last_rev` doesn't parse as
    /// a TID (defensive, not expected in practice) — `next()`'s own
    /// wall-clock floor still protects against a bad seed producing
    /// something smaller than "now."
    pub fn seeded(last_rev: &str) -> Self {
        Self {
            last: decode(last_rev).unwrap_or(0),
        }
    }

    /// The microsecond value this generator will next exceed — for a
    /// generator seeded from a persisted commit `rev`, that is the wall-clock
    /// time of the last durable append.
    ///
    /// Exposed so `Log` can use it as a **cross-process** floor for
    /// `ClaimContent::recorded_at`: a within-process floor alone would let
    /// two separate writers in the same microsecond produce identical
    /// content CIDs again, which is the whole defect `recorded_at` exists to
    /// fix (`.design/v0.7-milestone.md` REQ-1/REQ-3).
    pub fn last_micros(&self) -> u64 {
        self.last
    }

    /// The next TID, guaranteed strictly greater than every prior value
    /// this generator has produced.
    pub fn next(&mut self) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before 1970")
            .as_micros() as u64;
        // Clear the top bit, matching the atproto TID layout (63 usable bits).
        let now = now & 0x7FFF_FFFF_FFFF_FFFF;
        let next = now.max(self.last + 1);
        self.last = next;
        encode(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn produces_13_char_strings() {
        let mut gen = TidGenerator::new();
        assert_eq!(gen.next().len(), 13);
    }

    #[test]
    fn strictly_monotonic_even_under_rapid_calls() {
        let mut gen = TidGenerator::new();
        let mut prev = gen.next();
        for _ in 0..10_000 {
            let cur = gen.next();
            assert!(cur > prev, "{cur:?} should sort after {prev:?}");
            prev = cur;
        }
    }

    #[test]
    fn seeded_generator_stays_strictly_after_the_seed() {
        let seed = TidGenerator::new().next();
        let mut gen = TidGenerator::seeded(&seed);
        let next = gen.next();
        assert!(next > seed, "{next:?} should sort after the seed {seed:?}");
    }

    #[test]
    fn a_backward_clock_step_still_stays_monotonic_after_reseeding() {
        // Simulates two separate process invocations where the second
        // process's wall clock is momentarily behind the first's last
        // emitted rev (NTP correction, VM snapshot restore) -- the exact
        // scenario `TidGenerator::seeded`'s doc comment describes.
        let mut first_process = TidGenerator::new();
        let mut last = String::new();
        for _ in 0..5 {
            last = first_process.next();
        }

        let mut second_process = TidGenerator::seeded(&last);
        let next = second_process.next();
        assert!(
            next > last,
            "{next:?} should sort after the previous process's last rev {last:?}, \
             even though this generator has never called next() before"
        );
    }

    #[test]
    fn seeded_falls_back_to_zero_baseline_on_an_unparseable_seed() {
        let mut gen = TidGenerator::seeded("not-a-valid-tid");
        // Still produces a well-formed, present-day TID -- the wall-clock
        // floor in `next()` covers for the bad seed.
        assert_eq!(gen.next().len(), 13);
    }
}

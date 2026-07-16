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

/// Generates strictly-increasing TIDs for one log's append sequence.
#[derive(Debug, Default)]
pub struct TidGenerator {
    last: u64,
}

impl TidGenerator {
    pub fn new() -> Self {
        Self { last: 0 }
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
}

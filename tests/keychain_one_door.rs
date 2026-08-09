//! Exactly one call to `keyring::Entry::new` exists in `src/`.
//!
//! Note the wording: it counts CALLS, and does not check that the one call is
//! inside `keychain_entry`. An earlier version computed that and used it only
//! in a failure message that cannot render while the count is 1 -- a cold
//! review moved the call out of the chokepoint and the test still passed.
//!
//! `KAN_NO_KEYCHAIN` is an OPT-OUT, and opt-outs fail open: each call site had
//! to independently remember `keychain_disabled()`, and the cost of forgetting
//! is landing in a developer's real login keychain. Four sites existed; the two
//! newest both forgot, and `kan identity protect --yes` with the flag set wrote
//! a real entry to the author's keychain.
//!
//! Auditing call sites is the curated fix and it has already failed once. This
//! is the cheaper one: instead of checking that every door is guarded, assert
//! there is only one door.
//!
//! **What it does NOT buy, because the first version of this note overclaimed
//! it.** It said "a fifth path cannot be added quietly". It is a substring
//! match on `keyring::Entry::new`, and a cold review defeated it in one line:
//!
//! ```ignore
//! use keyring::Entry;
//! let e = Entry::new(service, account);   // a second door, and this test passes
//! ```
//!
//! Catching that properly needs the token stream — a `syn` pass, or clippy's
//! `disallowed_methods`, which resolves paths rather than matching text. Either
//! is the right fix and neither is this file. What this buys today is the
//! *common* mistake: a new call written the way all four existing ones were,
//! which is how the two that forgot `keychain_disabled()` were written.
//!
//! Kept, narrowed, and the gap named — because a check whose docstring claims
//! more than it delivers is the failure this whole milestone keeps finding.
//!
//! Written after routing the four sites by hand MISSED ONE -- `cargo fmt` had
//! reflowed the line being matched, and only counting caught it. The test
//! earned its keep before it was committed.

/// Also excludes prose: a doc comment mentioning the constructor is fine, and
/// a line of code calling it is not.
fn is_code(line: &str) -> bool {
    let t = line.trim_start();
    !(t.starts_with("//") || t.starts_with("///") || t.starts_with("//!") || t.starts_with('*'))
}

#[test]
fn only_one_call_to_keyring_entry_new_exists_in_src() {
    let mut sites = Vec::new();
    for entry in walk("src") {
        let text = std::fs::read_to_string(&entry).unwrap();
        for (i, line) in text.lines().enumerate() {
            if line.contains("keyring::Entry::new") && is_code(line) {
                sites.push(format!("{}:{}", entry.display(), i + 1));
            }
        }
    }
    assert_eq!(
        sites.len(),
        1,
        "expected exactly ONE call to keyring::Entry::new in src/, found {}: {sites:?}\n\n\
         It must live in `sign::keychain_entry`, the single place that honours \
         KAN_NO_KEYCHAIN. A second door is a path that can touch a user's real login \
         keychain when kan was told no keychain exists -- which has happened three times \
         (#146, and twice during v0.12).",
        sites.len()
    );
}

fn walk(dir: &str) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![std::path::PathBuf::from(dir)];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    out
}

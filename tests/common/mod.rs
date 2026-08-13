//! Shared machinery for the golden-fixture tests.
//!
//! Extracted from `tests/golden_reads.rs` when `.design/v0.12-milestone.md`
//! added a second fixture. The normalizer is the part that must be shared
//! rather than copied: two goldens with two normalizers that drift is the
//! same failure as identity resolution having two implementations of one
//! question (`.design/identity-resolution.md` Consequence 3), and it would
//! show up as one fixture silently accepting a token the other rejects.
//!
//! That the extraction is behaviour-preserving is proved by
//! `tests/fixtures/golden/single-author-reads.txt` being unmodified across
//! it — the fixture was generated before this file existed.
//!
//! `dead_code` is allowed because Rust compiles this module separately into
//! *each* integration-test binary, so anything one golden does not call warns
//! there while being load-bearing in the other.

#![allow(dead_code)]

use std::path::Path;
use std::process::Command;

/// Run the real binary as a subprocess, which is the only way the properties
/// `day` needs are actually checked: day executes `kan` and parses `--json`
/// (ADR-42), so a library-level capture would validate kan against kan's own
/// idea of its CLI.
///
/// `key` sets `KAN_IDENTITY_FILE`; `None` removes it, so a test cannot
/// inherit one from the ambient environment and silently capture a different
/// identity's view.
pub fn kan_as(dir: &Path, key: Option<&Path>, args: &[&str]) -> (String, String, bool) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kan"));
    cmd.args(args).current_dir(dir).env("KAN_NO_KEYCHAIN", "1");
    match key {
        Some(k) => {
            cmd.env("KAN_IDENTITY_FILE", k);
        }
        None => {
            cmd.env_remove("KAN_IDENTITY_FILE");
        }
    }
    let output = cmd.output().expect("failed to run kan binary");
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.success(),
    )
}

/// The workspace's own identity — no `KAN_IDENTITY_FILE`.
pub fn kan(dir: &Path, args: &[&str]) -> (String, String, bool) {
    kan_as(dir, None, args)
}

pub fn git_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let status = Command::new("git")
            .args(args)
            .current_dir(dir.path())
            .status()
            .expect("failed to run git");
        assert!(status.success(), "git {args:?} failed");
    };
    run(&["init", "-q"]);
    run(&[
        "-c",
        "user.email=kan-test@example.com",
        "-c",
        "user.name=kan-test",
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        "init",
    ]);
    dir
}

/// Render one command into the golden document: the invocation, its exit
/// disposition, and both streams.
///
/// stderr is captured deliberately. Several of this project's defects were
/// visible only there — a substitution that warned and continued, a keychain
/// fallback — and a fixture that captured stdout alone would have frozen the
/// wrong half.
pub fn capture(dir: &Path, key: Option<&Path>, args: &[&str], doc: &mut String) {
    let (stdout, stderr, ok) = kan_as(dir, key, args);
    doc.push_str(&format!("$ kan {}\n", args.join(" ")));
    doc.push_str(&format!("exit: {}\n", if ok { "ok" } else { "FAILED" }));
    doc.push_str("--- stdout ---\n");
    doc.push_str(&stdout);
    if !stdout.ends_with('\n') {
        doc.push('\n');
    }
    doc.push_str("--- stderr ---\n");
    doc.push_str(&stderr);
    if !stderr.is_empty() && !stderr.ends_with('\n') {
        doc.push('\n');
    }
    doc.push_str("=====================================================\n");
}

/// Replace the tokens that legitimately differ per run with stable
/// placeholders, so the document is reproducible without being vacuous.
///
/// Everything here is volatile *by construction*: a freshly minted DID, CIDs
/// over wall-clock-stamped content, the temp repo's genesis hash. Nothing
/// semantic is normalized away — the only exception is `trust.base`, which
/// `tests/trust_surface.rs` pins by value instead.
pub fn normalize(raw: &str, root: &Path) -> String {
    // Path first: a temp directory name could otherwise be eaten by one of
    // the token rules below.
    let mut s = raw.replace(&root.to_string_lossy().to_string(), "<WORKSPACE>");
    // macOS hands out `/var/folders/...` paths that resolve to `/private/var`.
    if let Ok(canonical) = root.canonicalize() {
        s = s.replace(&canonical.to_string_lossy().to_string(), "<WORKSPACE>");
    }
    s = s.replace("\"base\": \"Solo\"", "\"base\": \"<BASE>\"");
    s = s.replace("\"base\": \"Local\"", "\"base\": \"<BASE>\"");
    s = normalize_token_counts(&s);

    let bytes: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut cids: Vec<String> = Vec::new();
    let mut dids: Vec<String> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if let Some(len) = match_did(&bytes[i..]) {
            let tok: String = bytes[i..i + len].iter().collect();
            out.push_str(&placeholder("DID", &tok, &mut dids));
            i += len;
        } else if let Some(len) = match_did_leaf(&bytes[i..]) {
            let leaf: String = bytes[i..i + len].iter().collect();
            let tok = format!("did:key:{leaf}");
            out.push_str(&placeholder("DID", &tok, &mut dids));
            i += len;
        } else if let Some(len) = match_cid(&bytes[i..]) {
            let tok: String = bytes[i..i + len].iter().collect();
            out.push_str(&placeholder("CID", &tok, &mut cids));
            i += len;
        } else if let Some(len) = match_rfc3339(&bytes[i..]) {
            out.push_str("<TIME>");
            i += len;
        } else if let Some(len) = match_hex40(&bytes, i) {
            out.push_str("<GENESIS>");
            i += len;
        } else if let Some(len) = match_micros(&bytes, i) {
            out.push_str("<MICROS>");
            i += len;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out
}

/// The one *measured* value that is genuinely volatile: `context`'s token
/// estimate counts the rendered claim text, and that text carries content
/// CIDs, which differ per workspace. `~178/400` and `~180/400` are the same
/// behaviour over different bytes.
///
/// Only the estimate is blurred. The claim count beside it, the budget, the
/// omission counts and — most importantly — *which* claims were selected and
/// in what order all stay exact.
fn normalize_token_counts(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        // Human: `~178/400 tokens`
        let human = chars[i] == '~' && i + 1 < chars.len() && chars[i + 1].is_ascii_digit();
        // JSON: `"tokens": 178`
        let json = chars[i..].starts_with(&"\"tokens\": ".chars().collect::<Vec<_>>()[..]);
        if human || json {
            let prefix = if human { 1 } else { "\"tokens\": ".len() };
            let mut len = prefix;
            while i + len < chars.len() && chars[i + len].is_ascii_digit() {
                len += 1;
            }
            if len > prefix {
                out.extend(&chars[i..i + prefix]);
                out.push_str("<TOKENS>");
                i += len;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// `<KIND-n>`, numbered by first appearance so a token that moves within the
/// document is still a difference.
fn placeholder(kind: &str, token: &str, seen: &mut Vec<String>) -> String {
    let idx = match seen.iter().position(|t| t == token) {
        Some(idx) => idx,
        None => {
            seen.push(token.to_string());
            seen.len() - 1
        }
    };
    format!("<{kind}-{idx}>")
}

fn match_did(s: &[char]) -> Option<usize> {
    let prefix = "did:key:";
    if !s.starts_with(&prefix.chars().collect::<Vec<_>>()[..]) {
        return None;
    }
    let mut len = prefix.len();
    while len < s.len() && s[len].is_ascii_alphanumeric() {
        len += 1;
    }
    (len > prefix.len() + 8).then_some(len)
}

/// A `did:key` without its prefix, as used by v3's per-author filename.
fn match_did_leaf(s: &[char]) -> Option<usize> {
    let prefix = "zDna";
    if !s.starts_with(&prefix.chars().collect::<Vec<_>>()[..]) {
        return None;
    }
    let mut len = prefix.len();
    while len < s.len() && s[len].is_ascii_alphanumeric() {
        len += 1;
    }
    (len > prefix.len() + 8).then_some(len)
}

/// A CIDv1 dag-cbor CID in base32: `bafyrei` plus 52 more base32 characters.
fn match_cid(s: &[char]) -> Option<usize> {
    let prefix = "bafyrei";
    if !s.starts_with(&prefix.chars().collect::<Vec<_>>()[..]) {
        return None;
    }
    let mut len = prefix.len();
    while len < s.len() && (s[len].is_ascii_lowercase() || ('2'..='7').contains(&s[len])) {
        len += 1;
    }
    (len == 59).then_some(len)
}

/// `2026-08-03T16:36:03Z`
fn match_rfc3339(s: &[char]) -> Option<usize> {
    const SHAPE: &str = "dddd-dd-ddTdd:dd:ddZ";
    if s.len() < SHAPE.len() {
        return None;
    }
    for (i, expect) in SHAPE.chars().enumerate() {
        let ok = match expect {
            'd' => s[i].is_ascii_digit(),
            c => s[i] == c,
        };
        if !ok {
            return None;
        }
    }
    Some(SHAPE.len())
}

/// A 40-character lowercase hex run — a git object id — at a word boundary.
fn match_hex40(s: &[char], i: usize) -> Option<usize> {
    if i > 0 && (s[i - 1].is_ascii_alphanumeric() || s[i - 1] == '<') {
        return None;
    }
    let mut len = 0;
    while i + len < s.len() && s[i + len].is_ascii_hexdigit() && !s[i + len].is_ascii_uppercase() {
        len += 1;
    }
    (len == 40).then_some(len)
}

/// A 16-or-more-digit run — a microsecond timestamp — at a word boundary.
fn match_micros(s: &[char], i: usize) -> Option<usize> {
    if i > 0 && (s[i - 1].is_ascii_alphanumeric() || s[i - 1] == '-') {
        return None;
    }
    let mut len = 0;
    while i + len < s.len() && s[i + len].is_ascii_digit() {
        len += 1;
    }
    (len >= 16).then_some(len)
}

/// Compare against the committed fixture, or rewrite it under
/// `UPDATE_GOLDEN=1`.
///
/// `why` is the argument the failure message makes for why a diff matters,
/// since the two fixtures make *different* arguments: one says nothing should
/// change, the other says every change must be accepted deliberately.
pub fn compare_or_update(golden_rel: &str, doc: &str, why: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(golden_rel);
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, doc).unwrap();
        return;
    }

    let expected = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "{golden_rel} is missing ({e}). Regenerate it with \
             `UPDATE_GOLDEN=1 cargo test` -- but only against a binary whose output you \
             intend to freeze."
        )
    });

    if doc != expected {
        panic!(
            "{golden_rel} does not match.\n\n{why}\n\n--- first difference ---\n{}\n",
            first_difference(&expected, doc)
        );
    }
}

/// Golden diffs are long; point at the line that actually moved.
pub fn first_difference(expected: &str, actual: &str) -> String {
    let mut e = expected.lines();
    let mut a = actual.lines();
    let mut line = 0;
    loop {
        line += 1;
        match (e.next(), a.next()) {
            (None, None) => return "documents are equal line-by-line".to_string(),
            (Some(x), Some(y)) if x == y => continue,
            (x, y) => {
                return format!(
                    "line {line}\n  golden: {}\n  actual: {}",
                    x.unwrap_or("<end of golden>"),
                    y.unwrap_or("<end of actual>")
                )
            }
        }
    }
}

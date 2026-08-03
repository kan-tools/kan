//! AC-1 of `.design/identity-surface.md`: a single-author workspace produces
//! **byte-identical** `show`, `status`, `issues` and `context` output before
//! and after the default trust base becomes `Local`, on both the human and
//! `--json` surfaces, with `trust.base` the one sanctioned exception.
//!
//! **Why a golden file rather than assertions.** Hand-written assertions test
//! what the author thought to check, and the claim here is the opposite shape
//! — that *nothing at all* changed. Several defects in this project were
//! tests that could not fail (`docs/DECISIONS.md` ADR-48, ADR-82); an
//! assertion list over read output is that shape by construction, because
//! every field nobody thought to assert is a field the change may silently
//! move. A whole-document comparison inverts the default: a difference has to
//! be *accepted* into the fixture rather than merely not noticed.
//!
//! **The fixture is generated against the pre-change binary and committed
//! first.** That ordering is the whole point. A golden regenerated in the
//! same commit as the behaviour change proves nothing.
//!
//! Volatile tokens — the minted DID, content CIDs, wall-clock timestamps, the
//! repo's genesis hash, the temp path — are normalized to stable placeholders
//! (see [`normalize`]), which is what makes the document reproducible without
//! making it vacuous: a CID becomes `<CID-3>` by *first appearance*, so a
//! claim that moves, vanishes, or arrives still shifts the document.
//!
//! Regenerate deliberately, never reflexively:
//!
//! ```text
//! UPDATE_GOLDEN=1 cargo test --test golden_reads
//! ```

use std::path::Path;
use std::process::Command;

const GOLDEN: &str = "tests/fixtures/golden/single-author-reads.txt";

fn kan(dir: &Path, args: &[&str]) -> (String, String, bool) {
    let output = Command::new(env!("CARGO_BIN_EXE_kan"))
        .args(args)
        .current_dir(dir)
        .env("KAN_NO_KEYCHAIN", "1")
        .output()
        .expect("failed to run kan binary");
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.success(),
    )
}

fn git_repo() -> tempfile::TempDir {
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

/// The writes that build the fixture workspace.
///
/// Deliberately covers more than one subject, a status transition, a relation,
/// a retraction and a publication, because the golden is only as good as the
/// shapes it contains: a document with one observation in it would stay
/// byte-identical under almost any change to the fold.
fn build_workspace(dir: &Path) {
    let writes: &[&[&str]] = &[
        &[
            "observe",
            "the fold reads morphisms and never mutates objects",
            "--subject",
            "alpha",
            "--title",
            "Alpha, the first subject",
            "--kind",
            "issue",
        ],
        &["plan", "add a golden fixture first", "--subject", "alpha"],
        &["block", "alpha", "waiting on the fixture to exist"],
        &[
            "observe",
            "beta was noticed in passing",
            "--subject",
            "beta",
        ],
        &["relate", "beta", "blocks", "alpha"],
        &[
            "observe",
            "this observation is a mistake",
            "--subject",
            "beta",
        ],
        &["resolve", "beta", "beta turned out to be nothing"],
        &["mark", "alpha", "open"],
        &["publish", "alpha"],
    ];
    for args in writes {
        let (_, stderr, ok) = kan(dir, args);
        assert!(ok, "setup write {args:?} failed: {stderr}");
    }

    // Retract the mistaken observation by CID, so the golden contains a
    // superseded claim rather than only live ones.
    let (stdout, stderr, ok) = kan(dir, &["show", "beta", "--json"]);
    assert!(ok, "reading beta failed: {stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let mistake = v["claims"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["text"].as_str() == Some("this observation is a mistake"))
        .expect("the mistaken observation should be live before it is retracted")["cid"]
        .as_str()
        .unwrap()
        .to_string();
    let (_, stderr, ok) = kan(dir, &["retract", &mistake]);
    assert!(ok, "retract failed: {stderr}");
}

/// Every read surface AC-1 names, in a fixed order.
const READS: &[&[&str]] = &[
    &["show", "alpha"],
    &["show", "beta"],
    &["show", "alpha", "--json"],
    &["show", "--all", "--json"],
    &["status"],
    &["status", "alpha"],
    &["status", "--json"],
    &["issues"],
    &["issues", "--json"],
    &["context", "--budget", "400"],
    &["context", "--budget", "400", "--json"],
];

fn capture_reads(dir: &Path) -> String {
    let mut doc = String::new();
    for args in READS {
        let (stdout, stderr, ok) = kan(dir, args);
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
    doc
}

/// Replace the tokens that legitimately differ per run with stable
/// placeholders, so the document is reproducible without being vacuous.
///
/// Everything here is volatile *by construction*: a freshly minted DID, CIDs
/// over wall-clock-stamped content, the temp repo's genesis hash. Nothing
/// semantic is normalized away — the only exception is `trust.base`, which is
/// the single field AC-1 sanctions changing, and which `tests/trust_surface.rs`
/// pins by value instead (AC-8).
fn normalize(raw: &str, root: &Path) -> String {
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
/// in what order all stay exact, which is what a change to the default trust
/// base would actually move.
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

#[test]
fn single_author_reads_match_the_golden() {
    let dir = git_repo();
    build_workspace(dir.path());
    let doc = normalize(&capture_reads(dir.path()), dir.path());

    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(GOLDEN);
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &doc).unwrap();
        return;
    }

    let expected = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "{GOLDEN} is missing ({e}). Regenerate it with \
             `UPDATE_GOLDEN=1 cargo test --test golden_reads` -- but only against a binary \
             whose read output you intend to freeze."
        )
    });

    if doc != expected {
        panic!(
            "single-author read output changed.\n\n\
             AC-1 of `.design/identity-surface.md` says this document is byte-identical \
             before and after the default trust base becomes `Local`, since `Solo` and \
             `Local` coincide when one author has written. A diff here is either a real \
             regression or a change that has to be argued for and then accepted with \
             `UPDATE_GOLDEN=1`.\n\n\
             --- first difference ---\n{}\n",
            first_difference(&expected, &doc)
        );
    }
}

/// Golden diffs are long; point at the line that actually moved.
fn first_difference(expected: &str, actual: &str) -> String {
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

/// The normalizer has to be reproducible itself, or the fixture is measuring
/// its own noise. Two independently built workspaces — different temp dirs,
/// different genesis hashes, different DIDs, different wall-clock — must
/// normalize to the same document.
#[test]
fn normalization_is_reproducible_across_workspaces() {
    let a = git_repo();
    build_workspace(a.path());
    let doc_a = normalize(&capture_reads(a.path()), a.path());

    let b = git_repo();
    build_workspace(b.path());
    let doc_b = normalize(&capture_reads(b.path()), b.path());

    assert_eq!(
        doc_a,
        doc_b,
        "two identically-built workspaces normalized differently, so the golden fixture \
         would be testing run-to-run noise rather than behaviour.\n\n\
         --- first difference ---\n{}\n",
        first_difference(&doc_a, &doc_b)
    );
}

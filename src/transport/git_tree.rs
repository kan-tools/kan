//! `GitTree` — the committed git tree as a sharing layer.
//!
//! Publishing a claim here is not rendering it. It is **moving the claim to
//! another sharing layer**, the same category of act as publishing to a
//! `HostedRelay` or an atproto PDS, with git as the substrate instead of a
//! server (`.design/git-tree-transport.md`). `docs/SPEC.md` §10's "local-only
//! and atproto-ready are the SAME on-disk artifact" extends to git cleanly:
//! the claim written here is byte-identical in identity to the one in the
//! local log — same content, same CID, same signature.
//!
//! That is what makes the format safe. A file in `.claims/` carries a
//! complete signed record, so it can be verified rather than trusted: its
//! content is re-hashed and compared to the CID it states, and the signature
//! is checked against the author's DID. A hand-edited file is *detected*,
//! not merely discouraged — which the "render a claim to Markdown" framing
//! this replaced had no answer to at all.
//!
//! Narrative text lives in the Markdown body, not the frontmatter,
//! deliberately: editing the prose a human actually reads changes the CID and
//! fails verification. A format where the visible text could drift from the
//! signed record would be worse than no format.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use atproto_dasl::Cid;
use tokio_stream::Stream;

use super::{ClaimStream, Transport};
use crate::{
    cid::content_cid,
    claim::{Claim, ClaimContent, Did},
    sign::{self, Identity},
    store::log::Log,
};

/// Directory holding published claims, tracked in git — deliberately *not*
/// under `.kan/`, which ADR-3 keeps gitignored in full. The two never
/// overlap: `.kan/` is this author's private store, `.claims/` is the shared
/// layer.
pub const CLAIMS_DIR: &str = ".claims";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error under {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("cid: {0}")]
    Cid(#[from] crate::cid::Error),
    #[error("log: {0}")]
    Log(#[from] crate::store::log::Error),
    #[error("{path}: malformed claim record: {detail}")]
    Malformed { path: String, detail: String },
    #[error(
        "{path}: claim {stated} does not match its own content (recomputed {actual}) — the \
         record has been altered since it was signed"
    )]
    CidMismatch {
        path: String,
        stated: String,
        actual: String,
    },
    #[error("{path}: signature on claim {cid} does not verify against author {did}")]
    BadSignature {
        path: String,
        cid: String,
        did: String,
    },
    #[error(
        "{path}: record header claims {field} is {stated:?} but the signed content says \
         {actual:?} — the human-readable header disagrees with the claim it describes"
    )]
    HeaderMismatch {
        path: String,
        field: &'static str,
        stated: String,
        actual: String,
    },
    #[error(
        "{path}: this file is named {found:?}, but the records in it belong in {expected:?} \
         — the filename does not describe its contents"
    )]
    FilenameMismatch {
        path: String,
        /// The filename these records should be in.
        expected: String,
        /// The filename they are actually in.
        found: String,
    },
    #[error(
        "{path}: this file already holds another subject's claims — publishing {subject} here \
         would overwrite them. The filename digest collided; publish was refused rather than \
         destroy the existing file (its claims are safe in the log and in git)"
    )]
    FilenameCollision {
        path: String,
        /// The subject whose publish was refused.
        subject: String,
    },
    #[error(
        "{path}: {found} of {declared} records are present — {missing} record(s) have been \
         removed from this file since it was published"
    )]
    RecordsMissing {
        path: String,
        found: usize,
        declared: usize,
        missing: usize,
    },
}

fn io(path: &Path) -> impl Fn(std::io::Error) -> Error + '_ {
    move |source| Error::Io {
        path: path.display().to_string(),
        source,
    }
}

// ------------------------------------------------------------ wire format

/// Marker separating one claim record from the next within a subject's file.
const RECORD_SEPARATOR: &str = "---8<---";

/// Serializes a claim as one frontmatter block plus its narrative body.
///
/// The frontmatter carries everything the CID is computed over *except* the
/// narrative text, which goes in the Markdown body. Reassembly puts them back
/// together before hashing, so the bytes a reader sees are the bytes that
/// were signed.
pub fn to_record(claim: &Claim) -> Result<String, Error> {
    to_record_with_rev(claim, None)
}

/// [`to_record`], carrying the claim's `rev` TID.
///
/// A TID is a 13-character, lexicographically-sortable atproto timestamp
/// identifier — real time, unlike a CID, which is a content hash and carries
/// none. kan generates one per append, but it lives on `StoredClaim`,
/// outside `ClaimContent` and therefore outside the CID and the signature.
///
/// Publishing without it left a clone able to verify and fold every claim
/// and unable to order any two of them by time (`.design/schema-evolution.md`
/// REQ-11). It rides in the envelope rather than the content, so it is
/// exactly as trustworthy here as in the log — no more, no less — and it is
/// not an input to the CID. Whether time should become *signed* content is
/// issue #67, deliberately unanswered.
pub fn to_record_with_rev(claim: &Claim, rev: Option<&str>) -> Result<String, Error> {
    to_record_at(claim, rev, None)
}

/// [`to_record_with_rev`], carrying this record's position in its file so a
/// later deletion is visible (REQ-10).
pub fn to_record_at(
    claim: &Claim,
    rev: Option<&str>,
    position: Option<(usize, usize)>,
) -> Result<String, Error> {
    let cid = content_cid(&claim.content)?;
    let mut content = claim.content.clone();
    let text = content.body.text().map(str::to_string);
    if text.is_some() {
        content.body = content.body.with_text(String::new());
    }

    let header = serde_json::to_string_pretty(&RecordHeader {
        v: FORMAT_VERSION,
        seq: position.map(|(i, _)| i),
        of: position.map(|(_, n)| n),
        text_len: text.as_ref().map(|t: &String| t.len()),
        cid: cid.to_string(),
        sig: hex_encode(&claim.sig),
        author: content.author.did.clone(),
        subject: format!("{:?}", content.subject),
        kind: format!("{:?}", content.body.kind()),
        cites: claim.content.cites.iter().map(|c| c.to_string()).collect(),
        rev: rev.map(str::to_string),
        content: hex_encode(
            &atproto_dasl::to_vec(&content).map_err(|e| Error::Malformed {
                path: String::new(),
                detail: e.to_string(),
            })?,
        ),
    })
    .map_err(|e| Error::Malformed {
        path: String::new(),
        detail: e.to_string(),
    })?;

    let mut out = String::from("---\n");
    out.push_str(&header);
    out.push_str("\n---\n");
    if let Some(text) = text {
        // Exactly one newline of separation, then the text verbatim, then
        // exactly one newline. The reader strips precisely this framing using
        // `text_len` rather than trimming, so the bytes in between survive
        // whatever they are -- trailing whitespace, CRLF, blank runs, or the
        // record separator itself.
        out.push('\n');
        out.push_str(&text);
        out.push('\n');
    }
    Ok(out)
}

/// A record's frontmatter.
///
/// `content` is the authoritative field: DAG-CBOR of the `ClaimContent`,
/// hex-encoded, with the narrative text blanked because the text lives in
/// the Markdown body. Everything above it — `author`, `subject`, `kind`,
/// `cites` — is **derived and ignored on read**, present only so a human
/// scanning a diff can see who said what about which subject without
/// decoding anything.
///
/// The design proposed a plain-JSON `ClaimContent` here instead. That does
/// not work: `Cid` serializes for DAG-CBOR, so through `serde_json` it
/// becomes `{"": [0, 1, 113, ...]}` — unreadable, and it does not
/// deserialize back. Annotating `Cid` fields to serialize as strings was
/// the obvious fix and is unacceptable: it would change how `ClaimContent`
/// encodes to DAG-CBOR, and therefore change every CID kan has ever
/// computed. Encoding the content exactly as the log encodes it, and
/// carrying legibility alongside rather than inside it, keeps the wire
/// format honest about what it is.
#[derive(serde::Serialize, serde::Deserialize)]
struct RecordHeader {
    /// Record-format version (`.design/git-tree-transport.md` REQ-4, never
    /// implemented until now). Absent means version 1, the shape shipped in
    /// v0.6.0-beta.1. A reader meeting a higher version says so, by version
    /// number, instead of failing somewhere deeper with a message about
    /// hex or CIDs that tells the operator nothing actionable.
    #[serde(default = "default_format_version")]
    v: u32,
    cid: String,
    sig: String,
    /// Derived, ignored on read.
    author: String,
    /// Derived, ignored on read.
    subject: String,
    /// Derived, ignored on read.
    kind: String,
    /// Derived, ignored on read.
    cites: Vec<String>,
    /// The claim's TID: envelope metadata, not an input to the CID, and
    /// the only time information a published claim carries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rev: Option<String>,
    /// This record's position in its file, and how many the file held when
    /// it was written.
    ///
    /// Deleting a whole record used to be **completely undetectable**: the
    /// remainder verified cleanly, because nothing linked a subject's records
    /// to each other. Anyone with repo write access could remove a shared
    /// claim and kan would never say so, and an out-of-date clone
    /// republishing did it accidentally via `write_subject`'s whole-file
    /// rewrite (`.design/v0.7-milestone.md` REQ-10).
    ///
    /// Honest about its limits: this is envelope metadata, not signed, so it
    /// detects deletion rather than *preventing* it — an editor who rewrites
    /// every remaining record's `seq`/`of` defeats it. Authenticated deletion
    /// detection needs the publisher to sign over the record set, which is a
    /// new claim shape and therefore its own design pass. Catching accidental
    /// loss and naive removal is worth having in the meantime; claiming more
    /// would be the kind of overstatement this release exists to remove.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    seq: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    of: Option<usize>,
    /// Byte length of the narrative body that follows the frontmatter.
    ///
    /// **This is what makes the framing safe.** Version 1 recovered the body
    /// by trimming everything between the fence and the next separator, which
    /// meant the writer's own output failed the reader: a trailing newline, a
    /// leading space, a tab, CRLF, a non-breaking space, or a run of blank
    /// lines all round-tripped to a different CID and were reported as
    /// "altered since it was signed" — against honest claims, unrecoverably,
    /// because the CID is frozen in the append-only log. It also meant the
    /// literal record separator appearing in prose split one claim into
    /// three phantom records.
    ///
    /// With an explicit length the reader takes exactly those bytes and never
    /// consults the content to decide where the record ends, so no narrative
    /// text can alter the framing (`.design/v0.7-milestone.md` REQ-7, REQ-8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    text_len: Option<usize>,
    /// Authoritative: hex DAG-CBOR of `ClaimContent`, text blanked.
    content: String,
}

/// The record format this build writes.
const FORMAT_VERSION: u32 = 2;

fn default_format_version() -> u32 {
    1
}

/// Parses one record and verifies it against itself.
///
/// Verification is the whole safety story: without it, `.claims/` would be an
/// unsigned artifact sitting next to a signed one, looking equally
/// authoritative. With it, the file is a claim carrier rather than a forgery
/// surface.
pub fn from_record(path: &str, record: &str) -> Result<(Cid, Claim), Error> {
    from_record_with_rev(path, record).map(|(cid, claim, _)| (cid, claim))
}

/// [`from_record`], also returning the claim's published TID if it carries
/// one. Older records have none; that is a gap, not a failure.
pub fn from_record_with_rev(
    path: &str,
    record: &str,
) -> Result<(Cid, Claim, Option<String>), Error> {
    let malformed = |detail: &str| Error::Malformed {
        path: path.to_string(),
        detail: detail.to_string(),
    };

    let rest = record
        .trim_start()
        .strip_prefix("---")
        .ok_or_else(|| malformed("record does not begin with a `---` frontmatter fence"))?;
    let end = rest
        .find("\n---")
        .ok_or_else(|| malformed("frontmatter fence is never closed"))?;
    let header: RecordHeader =
        serde_json::from_str(rest[..end].trim()).map_err(|e| malformed(&e.to_string()))?;

    if header.v > FORMAT_VERSION {
        return Err(malformed(&format!(
            "record format version {} is newer than this build understands (max {}). \
             Upgrade kan to read it; the record is not damaged.",
            header.v, FORMAT_VERSION
        )));
    }

    let after_fence = &rest[end + "\n---".len()..];
    let body = match header.text_len {
        // v2: exactly the declared bytes, after the single newline the
        // writer emits. Never trimmed, and the content is never consulted to
        // decide where the record ends.
        Some(len) => {
            let start = after_fence
                .strip_prefix('\n')
                .ok_or_else(|| malformed("frontmatter fence is not followed by a newline"))?
                .strip_prefix('\n')
                .ok_or_else(|| malformed("no blank line between frontmatter and body"))?;
            if start.len() < len {
                return Err(malformed(&format!(
                    "body is {} bytes but the record declares {len}",
                    start.len()
                )));
            }
            if !start.is_char_boundary(len) {
                return Err(malformed(
                    "declared body length does not fall on a character boundary",
                ));
            }
            &start[..len]
        }
        // v1: no declared length. Fall back to the original trimming
        // behaviour so records written before this change still read --
        // `docs/SPEC.md` §7.1's coexistence contract. Those records remain
        // vulnerable to the framing defects `text_len` fixes, which is why
        // republishing under v2 is worth doing, but a reader must never
        // refuse to read what an older kan legitimately wrote.
        None => after_fence.trim(),
    };

    let bytes = hex_decode(&header.content).ok_or_else(|| malformed("content is not valid hex"))?;
    let mut content: ClaimContent =
        atproto_dasl::from_reader(&bytes[..]).map_err(|e| malformed(&e.to_string()))?;
    if content.body.text().is_some() {
        content.body = content.body.with_text(body.to_string());
    }

    let actual = content_cid(&content)?;
    if actual.to_string() != header.cid {
        return Err(Error::CidMismatch {
            path: path.to_string(),
            stated: header.cid,
            actual: actual.to_string(),
        });
    }

    // REQ-9: authenticate the legibility fields against the claim they
    // describe.
    //
    // These were documented "derived, ignored on read" and never checked, so
    // each could be set to an arbitrary valid-looking lie that verified
    // clean: a reviewer reading a PR diff saw a `Decision` by a victim's DID
    // about a different subject citing a fabricated provenance edge, while
    // kan read an `Observation` by the real author citing nothing. The whole
    // reason this format exists is human review in a PR — so the fields a
    // human actually reads are exactly the ones that must not be able to lie.
    // `cites` being forgeable is a direct hit on CLAUDE.md's "provenance is
    // sacred: never fabricate or drop `cites` edges."
    let mismatch = |field: &'static str, stated: &str, actual: &str| Error::HeaderMismatch {
        path: path.to_string(),
        field,
        stated: stated.to_string(),
        actual: actual.to_string(),
    };
    if header.author != content.author.did {
        return Err(mismatch("author", &header.author, &content.author.did));
    }
    let subject = format!("{:?}", content.subject);
    if header.subject != subject {
        return Err(mismatch("subject", &header.subject, &subject));
    }
    let kind = format!("{:?}", content.body.kind());
    if header.kind != kind {
        return Err(mismatch("kind", &header.kind, &kind));
    }
    let cites: Vec<String> = content.cites.iter().map(|c| c.to_string()).collect();
    if header.cites != cites {
        return Err(mismatch("cites", &header.cites.join(","), &cites.join(",")));
    }

    let sig = hex_decode(&header.sig).ok_or_else(|| malformed("signature is not valid hex"))?;
    if !sign::verify(&content.author.did, &actual.to_bytes(), &sig) {
        return Err(Error::BadSignature {
            path: path.to_string(),
            cid: header.cid,
            did: content.author.did.clone(),
        });
    }

    Ok((actual, Claim { content, sig }, header.rev))
}

/// Splits a subject file into records, without letting any record's own
/// content decide where it ends.
///
/// Version 1 split the whole file on the separator string, so narrative prose
/// containing that string tore one claim into three: a tampering accusation,
/// a malformed record, and a phantom. Records that declare `text_len` are now
/// walked sequentially — header, then exactly the declared body — and the
/// separator is only ever *skipped over* between records, never searched for
/// inside one.
///
/// Records without `text_len` (version 1, written before this change) still
/// fall back to separator splitting, because that is how they were framed and
/// a reader must keep reading what an older kan legitimately wrote.
pub fn split_records(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = text;

    while let Some(open) = rest.find("---") {
        let record = &rest[open..];
        let Some(fence_rel) = record[3..].find("\n---").map(|i| i + 3) else {
            break;
        };
        let header: Option<RecordHeader> = serde_json::from_str(record[3..fence_rel].trim()).ok();
        let after_fence = fence_rel + "\n---".len();

        let end = match header.as_ref().and_then(|h| h.text_len) {
            // "\n" (closing the fence line) + "\n" + body + "\n"
            Some(len) => (after_fence + 2 + len + 1).min(record.len()),
            None => match record[after_fence..].find(RECORD_SEPARATOR) {
                Some(i) => after_fence + i,
                None => record.len(),
            },
        };

        // Deliberately *not* trimmed: the trailing newline is part of the
        // framing the reader strips using `text_len`, and trimming it would
        // eat one byte of a body that legitimately ends in whitespace —
        // which is the exact defect this change exists to fix.
        let slice = &record[..end];
        if !slice.trim().is_empty() {
            out.push(slice);
        }

        // Step over the separator explicitly rather than letting the next
        // `find("---")` land on it — `---8<---` contains `---`, so searching
        // blindly re-enters on the separator and tries to parse `8<` as a
        // header.
        let tail = record[end..].trim_start();
        rest = tail.strip_prefix(RECORD_SEPARATOR).unwrap_or(tail);
    }
    out
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

/// Filename for a subject's claims. Subject rkeys may contain `/` (day's
/// `telos/legible-process`, for instance), which would otherwise create
/// directories.
pub fn file_name(subject: &crate::claim::SubjectRef) -> String {
    let raw = match subject {
        crate::claim::SubjectRef::Local(rkey) => rkey.clone(),
        crate::claim::SubjectRef::Anchor(anchor) => format!("{anchor:?}"),
    };
    let safe: String = raw
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();

    // The readable part is lossy on purpose — it exists so a human scanning
    // `.claims/` can tell what a file is about. The suffix is what makes the
    // mapping injective (`.design/v0.7-milestone.md` REQ-13).
    //
    // Without it, every character that is not alphanumeric/`-`/`.` collapsed
    // to `_`, so `telos/legible-process` and `telos_legible-process` shared
    // one file and publishing the second silently destroyed the first's
    // record — and `telos/<slug>` is exactly `day`'s naming convention
    // (ADR-42). On a case-insensitive filesystem (APFS by default) `Bug42`
    // and `bug42` collided on top of that, which no amount of character
    // mapping fixes because the collision happens below kan entirely.
    //
    // The suffix is derived from the *exact* subject bytes, so any two
    // distinct subjects differ in it even when their readable parts are
    // identical, and it is lowercase hex so it cannot itself collide under
    // case folding.
    format!("{safe}.{}.md", subject_digest(&raw))
}

/// The filename v0.6.0-beta.1 wrote for this subject.
///
/// Kept so files already in a repo's `.claims/` keep verifying. They are not
/// wrong — kan wrote them, they are correctly signed, and the only thing that
/// changed is where kan would put them now. Rejecting them would report a
/// repo's own history as mismatched for the crime of predating a rename
/// (#107).
///
/// Lossy, which is exactly why it was replaced: `telos/x` and `telos_x` both
/// land here, and publishing the second destroyed the first. That is why it
/// is accepted on **read** and never written.
pub fn legacy_file_name(subject: &crate::claim::SubjectRef) -> String {
    let raw = match subject {
        crate::claim::SubjectRef::Local(rkey) => rkey.clone(),
        crate::claim::SubjectRef::Anchor(anchor) => format!("{anchor:?}"),
    };
    let safe: String = raw
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("{safe}.md")
}

/// Whether a subject file is missing records it declares it should have
/// (REQ-10).
///
/// Every record written since v0.7 carries how many records its file held at
/// write time. If fewer are present than the largest such count declares,
/// records have been removed — accidentally by an out-of-date clone
/// republishing, or deliberately by someone with repo write access. Either
/// way it is reported rather than passing silently, which is what used to
/// happen.
///
/// Returns `None` for files written before v0.7 (no record declares a count),
/// because nothing there is claimed and nothing can be checked. That is a gap
/// in what old records can tell us, not a failure to report.
fn missing_records(path: &str, records: &[&str]) -> Option<Error> {
    let declared = records
        .iter()
        .filter_map(|r| {
            let rest = r.trim_start().strip_prefix("---")?;
            let end = rest.find("\n---")?;
            let header: RecordHeader = serde_json::from_str(rest[..end].trim()).ok()?;
            header.of
        })
        .max()?;

    if records.len() < declared {
        return Some(Error::RecordsMissing {
            path: path.to_string(),
            found: records.len(),
            declared,
            missing: declared - records.len(),
        });
    }
    None
}

/// Short, stable, case-insensitive-safe digest of a subject's exact bytes.
fn subject_digest(raw: &str) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(raw.as_bytes());
    digest[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// Writes every live claim of `subject` into its file under `root`,
/// replacing it.
///
/// A free function rather than a method: `kan publish` already holds an open
/// `Log` through its `Workspace`, and constructing a `GitTree` just to write
/// a file would mean a second `Log` handle over the same files.
///
/// Rewriting rather than appending keeps the file a faithful projection of
/// the claims being published; because claims are immutable and
/// content-addressed, rewriting cannot lose one that is still live.
pub fn write_subject(
    root: &Path,
    subject: &crate::claim::SubjectRef,
    claims: &[(Claim, Option<String>)],
) -> Result<Written, Error> {
    let dir = root.join(CLAIMS_DIR);
    std::fs::create_dir_all(&dir).map_err(io(&dir))?;
    let path = dir.join(file_name(subject));

    // #111: the primary write trusts `file_name(subject)` — a sanitized
    // prefix plus a 32-bit digest — as a unique key and overwrites
    // unconditionally, the last instance of ADR-52's class (a lossy derived
    // value trusted as a unique key for a destructive operation) still on a
    // write path. Two subjects colliding in the sanitized prefix *and* the
    // 4-byte digest would silently overwrite each other's file. Before
    // overwriting an existing file, confirm it is entirely this subject's —
    // exactly the check `retirable` makes below, keyed on the records'
    // content, not on the filename. A normal re-publish of this subject's own
    // file passes (every record is this subject); only a genuine collision, or
    // a file no longer parseable as this subject's, is refused rather than
    // clobbered. The claims are safe in the log and git either way, so refusing
    // loses nothing but the overwrite.
    if path.exists() && !retirable(&path, subject) {
        return Err(Error::FilenameCollision {
            path: path.display().to_string(),
            subject: format!("{subject:?}"),
        });
    }

    let mut out = String::new();
    for (i, (claim, rev)) in claims.iter().enumerate() {
        if !out.is_empty() {
            out.push_str(RECORD_SEPARATOR);
            out.push('\n');
        }
        out.push_str(&to_record_at(
            claim,
            rev.as_deref(),
            Some((i, claims.len())),
        )?);
    }
    std::fs::write(&path, out).map_err(io(&path))?;

    // Retire the v0.6-named file for this subject, now that its claims have
    // been rewritten under the current name (#107).
    //
    // Leaving it produced two files per subject, one of which never updated
    // again and diverged silently — and once a reader ships, a wall of
    // errors about files kan wrote itself.
    //
    // **The legacy name is lossy** (`legacy_file_name`'s own doc: `telos/x`
    // and `telos_x` both land there). A `.design/`-era version keyed the
    // deletion on it directly, and an adversarial review proved that let
    // publishing `telos/x` delete a *different* subject `telos_x`'s file —
    // a write path destroying another subject's data, keyed on a value that
    // is not unique (#107 round two). So the file is only retired after
    // reading it and confirming **every** record in it is about this exact
    // subject. A file that belongs to a colliding neighbour, or holds
    // anything unverifiable, is left untouched.
    let legacy = dir.join(legacy_file_name(subject));
    let retired = if legacy != path && retirable(&legacy, subject) {
        std::fs::remove_file(&legacy).map_err(io(&legacy))?;
        Some(legacy)
    } else {
        None
    };
    Ok(Written { path, retired })
}

/// Whether `filename` is the v0.6 legacy name of a *uniform* file — every
/// record about one subject, and that subject's legacy name is `filename`.
///
/// This is the only shape a genuine v0.6 file has (v0.6 wrote subject-exact
/// files), and requiring it stops the lossy legacy name from authenticating a
/// mixed-subject file (review D-C). An unparseable record makes the file
/// non-uniform, which is the safe direction: it falls back to strict
/// current-name checking rather than being waved through under a legacy name.
fn file_is_uniform_legacy(records: &[&str], filename: &str) -> bool {
    let mut subject: Option<crate::claim::SubjectRef> = None;
    for record in records {
        let Ok((_, claim)) = from_record(filename, record) else {
            return false;
        };
        match &subject {
            None => subject = Some(claim.content.subject.clone()),
            Some(s) if s != &claim.content.subject => return false,
            _ => {}
        }
    }
    subject.is_some_and(|s| legacy_file_name(&s) == filename)
}

/// Whether a legacy file may be deleted as this subject's superseded copy.
///
/// True only if it exists, parses, and **every** record in it is about
/// exactly `subject`. The lossy legacy name is never trusted as the sole
/// key: a file that a colliding neighbour wrote, an empty file, or one
/// holding anything that does not verify or belongs to another subject is
/// left in place. Deleting the wrong file here destroys another subject's
/// published claims, which is the invariant this guards.
fn retirable(legacy: &Path, subject: &crate::claim::SubjectRef) -> bool {
    let Ok(text) = std::fs::read_to_string(legacy) else {
        return false;
    };
    let records = split_records(&text);
    if records.is_empty() {
        return false;
    }
    let shown = legacy.display().to_string();
    records.iter().all(|record| {
        matches!(from_record(&shown, record), Ok((_, claim)) if &claim.content.subject == subject)
    })
}

/// What `write_subject` did, so the caller can say so rather than removing a
/// tracked file silently.
#[derive(Debug)]
pub struct Written {
    pub path: PathBuf,
    /// The v0.6-named file this replaced, if there was one.
    pub retired: Option<PathBuf>,
}

// -------------------------------------------------------------- transport

/// The committed git tree as a transport.
///
/// kan runs **no git commands**. It writes files into the working tree and
/// reads them back; staging, committing, and merging stay the user's, which
/// keeps kan git's sibling rather than its driver.
pub struct GitTree {
    log: Log,
    root: PathBuf,
}

impl GitTree {
    pub fn new(log: Log, root: impl Into<PathBuf>) -> Self {
        Self {
            log,
            root: root.into(),
        }
    }

    fn claims_dir(&self) -> PathBuf {
        self.root.join(CLAIMS_DIR)
    }

    /// Every claim in the tree, verified. An unverifiable record yields an
    /// `Err` in place rather than being skipped: silently dropping a claim
    /// that fails verification would hide exactly the tampering the
    /// verification exists to catch.
    pub fn read_all(&self) -> Vec<Result<(Cid, Claim), Error>> {
        let dir = self.claims_dir();
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return Vec::new();
        };

        // Sorted so a fold over the tree is reproducible; ordering carries
        // no meaning, but determinism makes divergence between two clones
        // visible rather than incidental.
        let mut files: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "md"))
            .collect();
        files.sort();

        let mut out = Vec::new();
        for file in files {
            let shown = file.display().to_string();
            match std::fs::read_to_string(&file) {
                Ok(text) => {
                    let records = split_records(&text);
                    if let Some(missing) = missing_records(&shown, &records) {
                        out.push(Err(missing));
                    }

                    // A legacy (`.md`, no-digest) name is accepted only for a
                    // file that is *uniform* — every record about one subject
                    // whose legacy name is this filename. That is what a
                    // genuine v0.6 file is (v0.6 wrote subject-exact files),
                    // and it is the check that keeps the lossy legacy name
                    // from authenticating a whole equivalence class: without
                    // it, a `foo_bar.md` holding a mix of `foo/bar` and
                    // `foo:bar` records passed, because each record's own
                    // legacy name equals the filename (review D-C). Current
                    // digest names stay per-record injective and need no such
                    // allowance.
                    let actual = file.file_name().and_then(|n| n.to_str());
                    let legacy_ok = actual.is_some_and(|a| file_is_uniform_legacy(&records, a));

                    for record in records {
                        let parsed = from_record(&shown, record);
                        // REQ-13's second half: the filename is authenticated
                        // against the records inside it. Without it the name
                        // was decorative — a `.claims/x.md` full of subject-`y`
                        // claims folded as `y` and nothing said so.
                        if let Ok((_, claim)) = &parsed {
                            let current = file_name(&claim.content.subject);
                            if let Some(actual) = actual {
                                let accepted = actual == current
                                    || (legacy_ok
                                        && actual == legacy_file_name(&claim.content.subject));
                                if !accepted {
                                    out.push(Err(Error::FilenameMismatch {
                                        path: shown.clone(),
                                        expected: current,
                                        found: actual.to_string(),
                                    }));
                                    continue;
                                }
                            }
                        }
                        out.push(parsed);
                    }
                }
                Err(source) => out.push(Err(Error::Io {
                    path: shown,
                    source,
                })),
            }
        }
        out
    }
}

impl Transport for GitTree {
    /// Appends to this author's own log first, then publishes the resulting
    /// claim verbatim — same content, same CID, same signature. Publishing
    /// copies a claim to another layer; it never creates an altered one.
    async fn publish(
        &mut self,
        content: ClaimContent,
        identity: &Identity,
    ) -> Result<Cid, super::Error> {
        let subject = content.subject.clone();
        let cid = self.log.append(content, identity).await?;

        let live: Vec<(Claim, Option<String>)> = self
            .log
            .iter_all()
            .await?
            .into_iter()
            .map(|(_, stored)| (stored.claim, Some(stored.rev)))
            .filter(|(claim, _)| claim.content.subject == subject)
            .collect();

        write_subject(&self.root, &subject, &live)
            .map_err(|e| super::Error::GitTree(Box::new(e)))?;
        Ok(cid)
    }

    /// Claims other actors published into the tree, as they arrive by an
    /// ordinary `git pull`. kan performs no network I/O and runs no git
    /// commands to fetch — the tree is simply read.
    async fn subscribe(&self, dids: &[Did]) -> Result<ClaimStream, super::Error> {
        let wanted: Vec<Did> = dids.to_vec();
        let claims: Vec<Result<Claim, super::Error>> = self
            .read_all()
            .into_iter()
            .filter(|result| match result {
                Ok((_, claim)) => wanted.is_empty() || wanted.contains(&claim.content.author.did),
                Err(_) => true,
            })
            .map(|result| {
                result
                    .map(|(_, claim)| claim)
                    .map_err(|e| super::Error::GitTree(Box::new(e)))
            })
            .collect();

        let stream: Pin<Box<dyn Stream<Item = Result<Claim, super::Error>> + Send>> =
            Box::pin(tokio_stream::iter(claims));
        Ok(stream)
    }
}

/// Deliberately empty: kan ships **no** merge-driver guidance for
/// `.claims/`.
///
/// ADR-43 originally shipped `.claims/*.md merge=union`, reasoning that
/// records are additive and immutable, so keeping both sides is the correct
/// resolution. The reasoning about *claims* is right; the conclusion about
/// *files* was wrong, and an adversarial review proved it destroys data.
///
/// `merge=union` is **line**-based. Every record here begins with the same
/// boilerplate lines (`---`, `{`, `"cid": …`), so git aligns the two sides'
/// record boundaries against each other and unions *inside* a record,
/// welding two claims into one malformed record with duplicate `cid`/`sig`
/// keys. The merge exits 0 reporting insertions, and both concurrent claims
/// are lost. Without the driver, the same merge raises an ordinary conflict
/// — visible, and recoverable by hand.
///
/// Union merge could only be safe if a record were one line, or if record
/// boundaries were unique enough that git could never align across them.
/// Neither is true today, so the honest shipped answer is no guidance at
/// all rather than guidance that loses claims.
pub const GITATTRIBUTES_LINE: &str = "";

/// What `.gitignore` must *not* do. ADR-3 keeps `.kan/` ignored in full;
/// this feature deliberately inverts that for a separate directory, so the
/// two never overlap and the inversion stays explicit.
pub fn gitignore_guidance() -> String {
    format!(
        "`.kan/` stays gitignored in full (ADR-3). `{CLAIMS_DIR}/` is tracked — it is a \
         sharing layer, not a store.\nDo not set a merge driver for `{CLAIMS_DIR}/`: a \
         merge conflict there is informative, and `merge=union` silently destroys both \
         sides' claims.\n"
    )
}

/// Subjects that have been published, from the fold's live claims.
pub fn published_subjects(claims: &[(Cid, Claim)]) -> BTreeMap<String, crate::claim::SubjectRef> {
    let mut out = BTreeMap::new();
    for (_, claim) in claims {
        if matches!(
            claim.content.body,
            crate::claim::ClaimBody::Publication { .. }
        ) {
            out.insert(
                format!("{:?}", claim.content.subject),
                claim.content.subject.clone(),
            );
        }
    }
    out
}

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

/// One record read out of the tree: its content CID, the claim, and the
/// published `rev` when the record carries one.
pub type ReadRecord = Result<(Cid, Claim, Option<String>), Error>;

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

impl Error {
    /// Stable category for the structured read-error surface. This is owned
    /// by kan rather than derived from the Rust variant's `Debug` spelling.
    pub fn diagnostic_kind(&self) -> &'static str {
        match self {
            Self::Io { .. } => "io",
            Self::Cid(_) => "cid",
            Self::Log(_) => "log",
            Self::Malformed { .. } => "malformed_record",
            Self::CidMismatch { .. } => "cid_mismatch",
            Self::BadSignature { .. } => "bad_signature",
            Self::HeaderMismatch { .. } => "header_mismatch",
            Self::FilenameMismatch { .. } => "filename_mismatch",
            Self::FilenameCollision { .. } => "filename_collision",
            Self::RecordsMissing { .. } => "records_missing",
        }
    }

    /// Source path carried by errors that can arise while reading GitTree.
    pub fn diagnostic_path(&self) -> Option<&str> {
        match self {
            Self::Io { path, .. }
            | Self::Malformed { path, .. }
            | Self::CidMismatch { path, .. }
            | Self::BadSignature { path, .. }
            | Self::HeaderMismatch { path, .. }
            | Self::FilenameMismatch { path, .. }
            | Self::FilenameCollision { path, .. }
            | Self::RecordsMissing { path, .. } => Some(path),
            Self::Cid(_) | Self::Log(_) => None,
        }
    }
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

/// v3's separator. Same scissors, no `---` run.
///
/// The v1/v2 separator contains `---`, so a scan for the frontmatter fence
/// re-enters on it and tries to parse `8<` as a header — the reader has to
/// step over it explicitly to stay correct, and kan#195 noted a separator that
/// could not collide was free at design time. It is nearly free now, and v3 is
/// the version that takes it.
const RECORD_SEPARATOR_V3: &str = "***8<***";

/// Both separators, longest first so a prefix match cannot shadow a longer
/// one. A file may mix versions when an opaque future claim needs v2's
/// `Unknown` header beside v3 records, and splitting happens *before* any
/// header is parsed, so the split cannot ask what version it is reading.
const RECORD_SEPARATORS: [&str; 2] = [RECORD_SEPARATOR, RECORD_SEPARATOR_V3];

/// Where the next record starts after `text`, if a separator follows.
fn strip_separator(text: &str) -> &str {
    for sep in RECORD_SEPARATORS {
        if let Some(rest) = text.strip_prefix(sep) {
            return rest;
        }
    }
    text
}

/// The earliest separator in `text`, of either kind.
fn find_separator(text: &str) -> Option<usize> {
    RECORD_SEPARATORS.iter().filter_map(|s| text.find(s)).min()
}

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
    to_record_at_version(claim, rev, position, FORMAT_VERSION)
}

/// [`to_record_at`], emitting a chosen record-format version.
///
/// The writer emits `FORMAT_VERSION` and nothing else; this exists so the v3
/// reader can be shipped and exercised *before* anything publishes v3.
/// Reader-before-writer is not fastidiousness here: a tree published in a
/// format no released kan can read is unreadable by every clone that has not
/// upgraded, and `.claims/` is the layer whose whole purpose is other people.
pub fn to_record_at_version(
    claim: &Claim,
    rev: Option<&str>,
    position: Option<(usize, usize)>,
    version: u32,
) -> Result<String, Error> {
    let cid = content_cid(&claim.content)?;
    let mut content = claim.content.clone();
    let text = content.body.text().map(str::to_string);
    if text.is_some() {
        content.body = content.body.with_text(String::new());
    }

    let encoded = atproto_dasl::to_vec(&content).map_err(|e| Error::Malformed {
        path: String::new(),
        detail: e.to_string(),
    })?;
    let kind = content.body.kind();
    let header = serde_json::to_string_pretty(&RecordHeader {
        v: version,
        seq: position.map(|(i, _)| i),
        of: position.map(|(_, n)| n),
        text_len: text.as_ref().map(|t: &String| t.len()),
        cid: cid.to_string(),
        sig: hex_encode(&claim.sig),
        author: content.author.did.clone(),
        subject: if version >= FORMAT_VERSION_WIRE_FIELDS {
            serde_json::to_value(WireSubject::of(&content.subject)).map_err(|e| {
                Error::Malformed {
                    path: String::new(),
                    detail: e.to_string(),
                }
            })?
        } else {
            serde_json::Value::String(format!("{:?}", content.subject))
        },
        kind: if version >= FORMAT_VERSION_WIRE_FIELDS {
            wire_kind(kind)
                .ok_or_else(|| Error::Malformed {
                    path: String::new(),
                    // Reached only by publishing a claim this build could not
                    // identify, which `.claims/` has no way to describe
                    // honestly -- see `wire_kind`.
                    detail: "cannot publish a claim of an unrecognised kind".to_string(),
                })?
                .to_string()
        } else {
            format!("{kind:?}")
        },
        cites: claim.content.cites.iter().map(|c| c.to_string()).collect(),
        rev: rev.map(str::to_string),
        content: if version >= FORMAT_VERSION_WIRE_FIELDS {
            base64_encode(&encoded)
        } else {
            hex_encode(&encoded)
        },
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
    /// Authenticated on read, not merely derived — see the block above
    /// `mismatch` in `from_record_with_rev`.
    ///
    /// These four said "Derived, ignored on read" until
    /// `.design/git-tree-transport.md` REQ-9 made them checked, and the
    /// comment outlived the change by two releases. A field that says it is
    /// ignored while being a hard error on mismatch is the shape of kan#177.
    author: String,
    /// Authenticated. A JSON string in v1/v2 (`Debug`), a [`WireSubject`] in
    /// v3; the header's own `v` decides which, never the shape on disk.
    subject: serde_json::Value,
    /// Authenticated. The `Debug` name in v1/v2, [`wire_kind`]'s name in v3.
    kind: String,
    /// Authenticated. CID strings in every version — already stable, and
    /// already what `Cid::to_string` produces.
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
/// What the writer emits.
///
/// Now 3. It lagged `MAX_READABLE_VERSION` deliberately through v0.12.0-beta.5,
/// which shipped the reader alone -- so a released kan understands v3 before
/// anything writes it, and a tree in the new shape is readable by a clone that
/// upgraded one release ago rather than by nothing at all.
const FORMAT_VERSION: u32 = 3;

/// What the reader understands. `FORMAT_VERSION` may lag this and never leads
/// it — the gap between the two *is* reader-before-writer, expressed as a
/// number rather than as a promise.
const MAX_READABLE_VERSION: u32 = 3;

/// The version from which `subject`, `kind` and `content` carry declared wire
/// shapes instead of `Debug` output and hex.
const FORMAT_VERSION_WIRE_FIELDS: u32 = 3;

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

    if header.v > MAX_READABLE_VERSION {
        return Err(malformed(&format!(
            "record format version {} is newer than this build understands (max {}). \
             Upgrade kan to read it; the record is not damaged.",
            header.v, MAX_READABLE_VERSION
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

    // Selected by the header's own `v`, never by sniffing the payload. A
    // decoder that tried both would turn a corrupted v3 record into a
    // different *valid* v2 one, and the CID check downstream would then report
    // a legitimate claim as altered since it was signed.
    let bytes = if header.v >= FORMAT_VERSION_WIRE_FIELDS {
        base64_decode(&header.content).ok_or_else(|| malformed("content is not valid base64"))?
    } else {
        hex_decode(&header.content).ok_or_else(|| malformed("content is not valid hex"))?
    };
    let mut content: ClaimContent =
        atproto_dasl::from_reader(&bytes[..]).map_err(|e| malformed(&e.to_string()))?;
    if content.body.text().is_some() {
        content.body = content.body.with_text(body.to_string());
    }

    let actual = content_cid(&content).map_err(|e| malformed(&e.to_string()))?;
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
    // The comparison is by VALUE in v3 and by formatted string in v1/v2. That
    // is the whole of `review/f4-debug-wire-contract`: authenticating these
    // fields is right, and authenticating them against `format!("{:?}")` made
    // `std`'s formatting a contract, so a rename or an escaping change would
    // have invalidated every file ever published.
    let kind = content.body.kind();
    if header.v >= FORMAT_VERSION_WIRE_FIELDS {
        let actual_subject = WireSubject::of(&content.subject);
        let stated: WireSubject = serde_json::from_value(header.subject.clone())
            .map_err(|e| malformed(&format!("subject is not a v3 wire subject: {e}")))?;
        if stated != actual_subject {
            return Err(mismatch(
                "subject",
                &header.subject.to_string(),
                &serde_json::to_string(&actual_subject).unwrap_or_default(),
            ));
        }
        // An unrecognised kind cannot be published (`wire_kind`), so it cannot
        // authenticate either: `None` here means the record claims a kind this
        // build has no name for, and saying so beats comparing two blanks.
        let actual = wire_kind(kind)
            .ok_or_else(|| malformed("record kind is not one this build can authenticate"))?;
        if header.kind != actual {
            return Err(mismatch("kind", &header.kind, actual));
        }
    } else {
        let subject = format!("{:?}", content.subject);
        let stated = header
            .subject
            .as_str()
            .ok_or_else(|| malformed("subject is not a string, as v1 and v2 require"))?;
        if stated != subject {
            return Err(mismatch("subject", stated, &subject));
        }
        let kind = format!("{kind:?}");
        if header.kind != kind {
            return Err(mismatch("kind", &header.kind, &kind));
        }
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

        // `text_len` is untrusted bytes from a tracked file, and this
        // arithmetic and the slice below run on every command, before any
        // signature is checked. A declared length near usize::MAX overflowed
        // the sum, and one landing inside a multibyte UTF-8 character
        // panicked the slice — either way a single committed record aborted
        // every kan command in every clone (review/full-pass-v0.12 F3). A
        // length that cannot frame this record is treated exactly like a
        // record that never declared one: separator framing, the pre-v2
        // fallback, which never trusts record content for its endpoint.
        let framed_end = header.as_ref().and_then(|h| h.text_len).and_then(|len| {
            // "\n" (closing the fence line) + "\n" + body + "\n"
            let end = after_fence
                .checked_add(2)?
                .checked_add(len)?
                .checked_add(1)?
                .min(record.len());
            record.is_char_boundary(end).then_some(end)
        });
        let end = match framed_end {
            Some(end) => end,
            None => match find_separator(&record[after_fence..]) {
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
        rest = strip_separator(tail);
    }
    out
}

/// Where a subject's records live under `.claims/` in the nested layout:
/// the subject's own name, with its `/` separators kept as real directories.
///
/// `telos/legible-process` becomes `telos/legible-process`, not
/// `telos_legible-process.6b2c1a90`. The flat name sanitizes every character
/// outside `[alnum].-` to `_` and then appends a digest to restore the
/// injectivity that sanitizing destroyed — and the collision it was restoring
/// is exactly the one `/` produced, against `telos/<slug>`, which is day's
/// naming convention (ADR-42). Keep the separator and the collision cannot
/// occur, so the digest has no job left.
///
/// Returns `None` for a subject that cannot be a safe relative path. **This
/// is a containment check, not tidiness**: a subject named `../../etc/x` maps
/// to a path outside `.claims/`, and a component of `.` or `..` or an
/// absolute-looking root would let a subject name decide where a write lands.
/// The writer does not use this yet — the reader ships first — but the guard
/// belongs here rather than at the call site that eventually needs it.
pub fn subject_path(subject: &crate::claim::SubjectRef) -> Option<PathBuf> {
    use crate::claim::SubjectRef;
    let raw = match subject {
        SubjectRef::Local(rkey) => rkey.clone(),
        // Anchors get a declared prefix rather than `format!("{anchor:?}")`,
        // which is the same `Debug`-as-contract defect one layer over: a path
        // derived from Debug output silently orphans every published file
        // when a variant is renamed.
        SubjectRef::Anchor(anchor) => match WireSubject::of(&SubjectRef::Anchor(anchor.clone())) {
            WireSubject::Workspace(id) => format!("anchor/workspace/{id}"),
            WireSubject::Commit(sha) => format!("anchor/commit/{sha}"),
            WireSubject::Blob(cid) => format!("anchor/blob/{cid}"),
            WireSubject::FileAt { path, sha } => format!("anchor/file-at/{sha}/{path}"),
            WireSubject::LineRangeAt {
                path,
                sha,
                start,
                end,
            } => format!("anchor/line-range-at/{sha}/{start}-{end}/{path}"),
            WireSubject::Local(_) => return None,
        },
    };

    if raw.is_empty() || raw.starts_with('/') || raw.contains('\\') || raw.contains('\0') {
        return None;
    }
    let mut out = PathBuf::new();
    for component in raw.split('/') {
        // An empty component is `a//b`, which the filesystem would silently
        // collapse to `a/b` — two distinct subjects, one path.
        if component.is_empty() || component == "." || component == ".." {
            return None;
        }
        out.push(component);
    }
    Some(out)
}

/// Every `.md` under `.claims/`, at any depth.
///
/// Flat files sit directly under the directory; nested ones sit under
/// directories that spell out the subject. A read must find both, because an
/// author cannot rewrite a peer's file — so the flat layout is a contract to
/// keep reading, not a deprecation window.
fn collect_claim_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for path in entries.flatten().map(|e| e.path()) {
        if path.is_dir() {
            collect_claim_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "md") {
            out.push(path);
        }
    }
}

/// One nested file: `.claims/<subject>/<author>.md`.
///
/// REQ-14. The flat reader already authenticates a record's FILENAME against
/// its contents, because a name that describes nothing is a name that can
/// lie. The nested path carries one thing more — the author — so both are
/// checked here. Without the author half, a file bearing one author's name
/// could hold another's records, and the directory listing that is supposed
/// to say who published what would be decorative.
fn read_nested_file(file: &Path, relative: &Path) -> Vec<ReadRecord> {
    let shown = file.display().to_string();
    let mut out = Vec::new();

    let text = match std::fs::read_to_string(file) {
        Ok(text) => text,
        Err(source) => {
            return vec![Err(Error::Io {
                path: shown,
                source,
            })];
        }
    };

    let stated_author = file
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    let stated_subject = relative.parent().and_then(subject_from_path);

    let records = split_records(&text);
    if let Some(missing) = missing_records(&shown, &records) {
        out.push(Err(missing));
    }

    for record in records {
        let parsed = from_record_with_rev(&shown, record);
        if let Ok((_, claim, _)) = &parsed {
            // The path states a subject and an author; the record is signed
            // over its own. Comparing the two is the whole of REQ-14.
            let expected_path = subject_path(&claim.content.subject);
            let path_matches = match (&stated_subject, &expected_path) {
                (Some(stated), Some(expected)) => {
                    Path::new(stated) == expected.as_path()
                        || subject_from_path(expected).as_deref() == Some(stated.as_str())
                }
                _ => false,
            };
            if !path_matches {
                out.push(Err(Error::FilenameMismatch {
                    path: shown.clone(),
                    expected: expected_path
                        .and_then(|p| subject_from_path(&p))
                        .unwrap_or_else(|| "<unrepresentable subject>".to_string()),
                    found: stated_subject.clone().unwrap_or_default(),
                }));
                continue;
            }

            let did = claim.content.author.did.strip_prefix("did:key:").unwrap_or(
                // A DID that is not `did:key:` cannot name a leaf under this
                // scheme; say so rather than matching on the whole string and
                // appearing to have checked something.
                &claim.content.author.did,
            );
            if stated_author != did {
                out.push(Err(Error::FilenameMismatch {
                    path: shown.clone(),
                    expected: did.to_string(),
                    found: stated_author.to_string(),
                }));
                continue;
            }
        }
        out.push(parsed);
    }
    out
}

/// The subject a nested path is claiming to hold, recovered from the path.
///
/// The inverse of [`subject_path`] for `Local` subjects, which is what the
/// reader needs in order to authenticate a file against the records inside
/// it. Anchor paths are not inverted: they are prefixed `anchor/` and are
/// checked by comparing against [`subject_path`] of the record's own subject
/// instead, which needs no inverse.
fn subject_from_path(relative: &Path) -> Option<String> {
    let mut parts = Vec::new();
    for component in relative.components() {
        let std::path::Component::Normal(part) = component else {
            return None;
        };
        parts.push(part.to_str()?.to_string());
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

/// The v3 wire shape of a subject.
///
/// v1 and v2 wrote `format!("{:?}", subject)` here — `Local("work")` — and
/// then *strictly compared* it on read, which made `std`'s `Debug` output a
/// wire contract nobody declared: an enum rename, a variant reorder, or a
/// change in how `std` escapes a string invalidates every previously published
/// file (`review/f4-debug-wire-contract`). This is that contract stated on
/// purpose, so the thing that may not drift is a declared shape rather than a
/// formatting implementation.
///
/// `SubjectRef`'s own derived `serde` impl is deliberately not reused.
/// `Anchor::Blob` holds a `Cid`, which through `serde_json` becomes
/// `{"": [0, 1, 113, …]}` and does not deserialize back (ADR-44 measurement
/// 1). Every field below is a string or a number by construction.
#[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum WireSubject {
    Local(String),
    Workspace(String),
    Commit(String),
    Blob(String),
    FileAt {
        path: String,
        sha: String,
    },
    LineRangeAt {
        path: String,
        sha: String,
        start: u32,
        end: u32,
    },
}

impl WireSubject {
    fn of(subject: &crate::claim::SubjectRef) -> Self {
        use crate::claim::{Anchor, SubjectRef};
        // `to_string_lossy` is safe here in the sense that matters: this value
        // is compared against the same projection of the same claim, never
        // used to reconstruct the path. A non-UTF-8 path yields a stable
        // rendering on both sides.
        match subject {
            SubjectRef::Local(rkey) => Self::Local(rkey.clone()),
            SubjectRef::Anchor(Anchor::Workspace(cid)) => Self::Workspace(cid.clone()),
            SubjectRef::Anchor(Anchor::Commit(sha)) => Self::Commit(sha.clone()),
            SubjectRef::Anchor(Anchor::Blob(cid)) => Self::Blob(cid.to_string()),
            SubjectRef::Anchor(Anchor::FileAt(path, sha)) => Self::FileAt {
                path: path.to_string_lossy().into_owned(),
                sha: sha.clone(),
            },
            SubjectRef::Anchor(Anchor::LineRangeAt(path, sha, span)) => Self::LineRangeAt {
                path: path.to_string_lossy().into_owned(),
                sha: sha.clone(),
                start: span.start,
                end: span.end,
            },
        }
    }
}

/// The v3 wire name of a claim kind.
///
/// Same problem as [`WireSubject`], smaller: v1/v2 wrote the `Debug` name and
/// compared it exactly. The wire name is lower-case and explicit, so renaming
/// a Rust variant is a code change rather than a break in every published file.
///
/// `ClaimKind::Unknown` is the kind a build gives a claim it does not
/// recognise (ADR-44). It is deliberately *not* representable here: a record
/// whose header says `unknown` would be asserting that the publisher could not
/// identify their own claim, and on read the comparison would pass for any
/// unrecognised kind at all, which is the opposite of authenticating it.
fn wire_kind(kind: crate::claim::ClaimKind) -> Option<&'static str> {
    use crate::claim::ClaimKind as K;
    Some(match kind {
        K::Subject => "subject",
        K::Observation => "observation",
        K::Plan => "plan",
        K::Decision => "decision",
        K::Blocker => "blocker",
        K::Resolution => "resolution",
        K::Result => "result",
        K::Status => "status",
        K::Relation => "relation",
        K::Retraction => "retraction",
        K::Rejects => "rejects",
        K::Publication => "publication",
        K::RoleDeclaration => "role_declaration",
        K::Unknown => return None,
    })
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding, hand-rolled for the same reason `hex_encode`
/// is: this file already owns its encodings, and a dependency added for forty
/// lines on the verification path is a dependency whose correctness we would
/// have to check anyway (ADR-90).
///
/// v3 records encode `content` this way. Hex doubles a ~1.5 KB payload per
/// record for nothing (kan#195); base64 rather than the base32 the CIDs beside
/// it use, so the two are visually distinguishable rather than confusable.
fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        out.push(B64[(n >> 18 & 63) as usize] as char);
        out.push(B64[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            B64[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Strict: rejects anything outside the alphabet, wrong-length input, and
/// misplaced padding, rather than skipping unknown bytes.
///
/// Lenient decoders are how a corrupted payload becomes a *different* valid
/// payload instead of an error — and everything downstream of this is a CID
/// check that would then report a legitimate claim as altered since signing.
/// Same discipline as `hex_decode`: ASCII-only, no slicing of untrusted text
/// at non-boundaries (review/full-pass-v0.12 F3).
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !text.is_ascii() || !bytes.len().is_multiple_of(4) || bytes.is_empty() {
        return (bytes.is_empty() && text.is_empty()).then(Vec::new);
    }
    let value = |c: u8| -> Option<u32> {
        B64.iter()
            .position(|&x| x == c)
            .map(|i| u32::try_from(i).expect("base64 alphabet index fits in u32"))
    };

    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for (i, quad) in bytes.chunks(4).enumerate() {
        let last = i == bytes.len() / 4 - 1;
        let pad = if last {
            usize::from(quad[3] == b'=') + usize::from(quad[2] == b'=')
        } else {
            0
        };
        // Padding is only ever the final one or two characters of the final
        // quad. `A=B=` and `AB=C` are rejected rather than interpreted.
        if !last && quad.contains(&b'=') {
            return None;
        }
        if pad == 2 && quad[2] != b'=' {
            return None;
        }
        let mut n = 0u32;
        for (j, &c) in quad.iter().enumerate() {
            let six = if j >= 4 - pad {
                if c != b'=' {
                    return None;
                }
                0
            } else {
                value(c)?
            };
            n = n << 6 | six;
        }
        out.push((n >> 16 & 0xff) as u8);
        if pad < 2 {
            out.push((n >> 8 & 0xff) as u8);
        }
        if pad < 1 {
            out.push((n & 0xff) as u8);
        }
    }
    Some(out)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    // The parity check counts bytes, but the slice below indexes byte
    // positions of what is untrusted text from a tracked file — non-ASCII
    // input put a slice boundary inside a multibyte character and aborted
    // the process before any verification ran (review/full-pass-v0.12 F3).
    // Hex is ASCII by definition; anything else is a malformed field.
    if !text.is_ascii() || !text.len().is_multiple_of(2) {
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

    // The subject's own name as a path, `/` and all. `None` means the subject
    // cannot be a safe relative path -- `..`, an empty component, an absolute
    // root -- and a subject name must never decide where a write lands.
    let rel = subject_path(subject).ok_or_else(|| Error::Malformed {
        path: dir.display().to_string(),
        detail: format!("subject {subject:?} cannot be expressed as a path under {CLAIMS_DIR}"),
    })?;
    let subject_dir = dir.join(&rel);

    // A subject path is only contained if the filesystem resolves it the way
    // its components spell it. `.claims/` is shared through git, so an
    // existing component may be a committed symlink; following one here
    // would let `publish` write outside the tracked projection even though
    // `subject_path` rejected every lexical traversal shape.
    refuse_symlinked_components(&dir, &rel)?;

    // GROUPED BY AUTHOR, because a workspace can sign with several identities.
    // Role keys all append to one log, so `publish` hands us every live claim
    // on the subject regardless of who signed it. The flat layout put them in
    // one file; here they belong in one file each, and a caller that assumed
    // otherwise would have one author's records silently overwrite another's
    // -- the very failure this layout removes for peers (kan#131).
    let mut by_author: BTreeMap<&str, Vec<(&Claim, Option<&str>)>> = BTreeMap::new();
    for (claim, rev) in claims {
        by_author
            .entry(claim.content.author.did.as_str())
            .or_default()
            .push((claim, rev.as_deref()));
    }

    std::fs::create_dir_all(&subject_dir).map_err(io(&subject_dir))?;

    let mut paths = Vec::new();
    for (did, group) in &by_author {
        let leaf = did.strip_prefix("did:key:").unwrap_or(did);
        let path = subject_dir.join(format!("{leaf}.md"));

        // The kan#111 guard, still keyed on the records' content rather than
        // on the filename. Under this layout a collision needs a case-folding
        // filesystem AND two subjects differing only in case, which is the one
        // hazard preserving `/` does not remove -- so the check stays, and a
        // genuine collision is refused rather than clobbered. The claims are
        // safe in the log and in git either way.
        if path.exists() && !retirable(&path, subject) {
            return Err(Error::FilenameCollision {
                path: path.display().to_string(),
                subject: format!("{subject:?}"),
            });
        }

        let mut out = String::new();
        for (i, (claim, rev)) in group.iter().enumerate() {
            if !out.is_empty() {
                out.push_str(RECORD_SEPARATOR_V3);
                out.push('\n');
            }
            let version = if wire_kind(claim.content.body.kind()).is_some() {
                FORMAT_VERSION
            } else {
                // Unknown bodies are preserved opaque claims from a newer
                // schema. v3 cannot name their kind honestly, but v2 can and
                // released readers accept mixed-version files. Falling back
                // per record keeps one future claim from making the whole
                // subject unpublishable without dropping or rewriting it.
                FORMAT_VERSION_WIRE_FIELDS - 1
            };
            out.push_str(&to_record_at_version(
                claim,
                *rev,
                Some((i, group.len())),
                version,
            )?);
        }
        std::fs::write(&path, out).map_err(io(&path))?;
        paths.push(path);
    }

    // RETIRING THE FLAT FILE IS THE DANGEROUS PART, and it is why this is
    // conditional rather than automatic.
    //
    // Under the flat layout a subject had ONE file, and `publish` rewrote it
    // whole -- so a peer's records could be sitting in it right now. That is
    // not hypothetical: it is what the multi-actor probe measured, a second
    // author's publish silently replacing the first author's records. Deleting
    // that file while migrating would destroy claims this author never wrote
    // and cannot re-create, which is exactly the act the non-negotiable
    // invariant forbids.
    //
    // So it is retired only when every record in it is BOTH this subject's and
    // by an author we just rewrote. Anything else -- a peer's records, a
    // record that will not parse -- and the file is left alone, where the
    // reader still understands it.
    let current_flat = dir.join(file_name(subject));
    let legacy_flat = dir.join(legacy_file_name(subject));
    let flat = if current_flat.exists() {
        current_flat
    } else {
        legacy_flat
    };
    let authors: Vec<&str> = by_author.keys().copied().collect();
    let retired = if flat.exists() && retirable_by(&flat, subject, &authors) {
        std::fs::remove_file(&flat).map_err(io(&flat))?;
        Some(flat)
    } else {
        None
    };

    Ok(Written { paths, retired })
}

fn refuse_symlinked_components(dir: &Path, rel: &Path) -> Result<(), Error> {
    let mut path = dir.to_path_buf();
    for component in std::iter::once(None).chain(rel.components().map(Some)) {
        if let Some(component) = component {
            path.push(component.as_os_str());
        }
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(Error::Malformed {
                    path: path.display().to_string(),
                    detail: format!(
                        "publishing through a symlink under {CLAIMS_DIR} is refused because it may escape the tracked projection"
                    ),
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(source) => {
                return Err(Error::Io {
                    path: path.display().to_string(),
                    source,
                });
            }
        }
    }
    Ok(())
}

/// Every record in `path` is about `subject` AND signed by one of `authors`.
///
/// The subject half is [`retirable`]'s check. The author half is what keeps a
/// migration from deleting a peer's published claims out of a shared flat file.
fn retirable_by(path: &Path, subject: &crate::claim::SubjectRef, authors: &[&str]) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    let records = split_records(&text);
    if records.is_empty() {
        return false;
    }
    records.iter().all(|record| {
        match from_record(&path.display().to_string(), record) {
            Ok((_, claim)) => {
                &claim.content.subject == subject
                    && authors.contains(&claim.content.author.did.as_str())
            }
            // Unparseable means unknown, and unknown is never safe to delete.
            Err(_) => false,
        }
    })
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
    /// Every file this write produced, one per publishing author.
    ///
    /// A `Vec` rather than a path because a workspace can sign with several
    /// identities — role keys all append to one log (`.kan/roles.d/`) — and
    /// under the per-author layout their records go to different files. The
    /// flat layout hid that by putting them all in one.
    pub paths: Vec<PathBuf>,
    /// A previous-layout file this write superseded, if there was one and if
    /// retiring it was safe.
    pub retired: Option<PathBuf>,
}

impl Written {
    /// The first file written, for callers that report a single path.
    pub fn path(&self) -> &Path {
        self.paths
            .first()
            .map(PathBuf::as_path)
            .unwrap_or(Path::new(""))
    }
}

// -------------------------------------------------------------- transport

/// The committed git tree as a transport.
///
/// kan runs **no git commands**. It writes files into the working tree and
/// reads them back; staging, committing, and merging stay the user's, which
/// keeps kan git's sibling rather than its driver.
pub struct GitTree {
    /// `None` for a reader built by [`GitTree::new_reader`].
    log: Option<Log>,
    root: PathBuf,
}

impl GitTree {
    pub fn new(log: Log, root: impl Into<PathBuf>) -> Self {
        Self {
            log: Some(log),
            root: root.into(),
        }
    }

    /// A `GitTree` for reading only, with no log behind it.
    ///
    /// `Transport::publish` needs a `Log` to append to first; the read half
    /// (`read_all`, `read_all_with_rev`) touches nothing but the tree, and
    /// `Workspace::open` has no log to lend it at the point it needs to read
    /// — the overlay it is filling *is* the destination. Rather than
    /// contrive one, this constructs the reader alone.
    ///
    /// `publish` on a reader panics rather than silently writing to a log
    /// that was never supplied. Nothing constructs one and then publishes;
    /// the type-level version of this (splitting the trait in two) is a
    /// bigger change than the reader wiring warrants, and is worth doing
    /// when `HostedRelay` gives a second implementation to design against.
    pub fn new_reader(root: impl Into<PathBuf>) -> Self {
        Self {
            log: None,
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
    /// [`Self::read_all`], keeping each record's published `rev`.
    ///
    /// The reader needs it and the plain `read_all` drops it: a `StoredClaim`
    /// carries the log-revision TID that orders the fold, so ingesting
    /// without it would reorder another actor's claims relative to how they
    /// were written. Records published before v0.7.0-beta.1 carry none —
    /// `Option`, because that is a gap in old data, not a failure.
    pub fn read_all_with_rev(&self) -> Vec<ReadRecord> {
        self.read_records()
    }

    pub fn read_all(&self) -> Vec<Result<(Cid, Claim), Error>> {
        self.read_records()
            .into_iter()
            .map(|r| r.map(|(cid, claim, _)| (cid, claim)))
            .collect()
    }

    fn read_records(&self) -> Vec<ReadRecord> {
        let dir = self.claims_dir();

        // Sorted so a fold over the tree is reproducible; ordering carries
        // no meaning, but determinism makes divergence between two clones
        // visible rather than incidental.
        let mut files = Vec::new();
        collect_claim_files(&dir, &mut files);
        files.sort();

        let mut out = Vec::new();
        for file in files {
            // A file directly under `.claims/` is the flat layout every
            // release through v0.12.x wrote. Anything deeper is the nested
            // layout, whose directories ARE the subject — so the depth is
            // what selects which authentication applies, rather than a guess
            // about the filename's shape.
            let relative = file.strip_prefix(&dir).unwrap_or(&file).to_path_buf();
            let nested = relative.components().count() > 1;
            if nested {
                out.extend(read_nested_file(&file, &relative));
                continue;
            }
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
                        let parsed = from_record_with_rev(&shown, record);
                        // REQ-13's second half: the filename is authenticated
                        // against the records inside it. Without it the name
                        // was decorative — a `.claims/x.md` full of subject-`y`
                        // claims folded as `y` and nothing said so.
                        if let Ok((_, claim, _)) = &parsed {
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
        let log = self
            .log
            .as_mut()
            .expect("publish on a GitTree reader -- new_reader has no log to append to");
        let cid = log.append(content, identity).await?;

        let live: Vec<(Claim, Option<String>)> = log
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

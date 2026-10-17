//! Read-only v1 evidence preflight. Never opens the legacy all-memory log.
//! Its reports explicitly do not certify claim validity or migration completion.

use atproto_dasl::{drisl, Ipld};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{self, Read, Seek},
    path::{Path, PathBuf},
};

const MAX_FILES: usize = 16_384;
const MAX_DEPTH: usize = 128;
const BUFFER: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NoticeKind {
    Excluded,
    Unavailable,
    Unsupported,
    Changed,
    Limit,
}
#[derive(Debug, Serialize)]
pub struct Notice {
    pub kind: NoticeKind,
    pub path: PathBuf,
    pub reason: String,
}
#[derive(Debug, Default, Serialize)]
pub struct Discovery {
    pub roots: Vec<PathBuf>,
    pub notices: Vec<Notice>,
}

pub fn discover(roots: &[PathBuf]) -> Discovery {
    let mut output = Discovery::default();
    let mut pending: Vec<_> = roots.iter().cloned().map(|p| (p, 0)).collect();
    let mut visited = std::collections::BTreeSet::new();
    'walk: while let Some((path, depth)) = pending.pop() {
        if pending.len() + visited.len() + output.notices.len() > 65_536 {
            output.notices.push(Notice {
                kind: NoticeKind::Limit,
                path,
                reason: "traversal inventory limit; discovery incomplete".into(),
            });
            break;
        }
        let metadata = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) => {
                output.notices.push(Notice {
                    kind: NoticeKind::Unavailable,
                    path,
                    reason: e.to_string(),
                });
                continue;
            }
        };
        if metadata.file_type().is_symlink() {
            output.notices.push(Notice {
                kind: NoticeKind::Unsupported,
                path,
                reason: "symlink not followed".into(),
            });
            continue;
        }
        if !metadata.is_dir() {
            output.notices.push(Notice {
                kind: NoticeKind::Unsupported,
                path,
                reason: "search root is not a directory".into(),
            });
            continue;
        }
        if depth > MAX_DEPTH {
            output.notices.push(Notice {
                kind: NoticeKind::Limit,
                path,
                reason: "directory depth limit; discovery incomplete".into(),
            });
            continue;
        }
        let canonical = match path.canonicalize() {
            Ok(p) => p,
            Err(e) => {
                output.notices.push(Notice {
                    kind: NoticeKind::Unavailable,
                    path,
                    reason: e.to_string(),
                });
                continue;
            }
        };
        if !visited.insert(canonical.clone()) {
            continue;
        }
        let mut found = false;
        for marker in [".kan", ".claims"] {
            match fs::symlink_metadata(path.join(marker)) {
                Ok(m) if m.is_dir() && !m.file_type().is_symlink() => found = true,
                Ok(_) => output.notices.push(Notice {
                    kind: NoticeKind::Unsupported,
                    path: path.join(marker),
                    reason: "workspace marker is not a real directory".into(),
                }),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => output.notices.push(Notice {
                    kind: NoticeKind::Unavailable,
                    path: path.join(marker),
                    reason: e.to_string(),
                }),
            }
        }
        if found {
            output.roots.push(canonical);
        }
        let children = match fs::read_dir(&path) {
            Ok(d) => d,
            Err(e) => {
                output.notices.push(Notice {
                    kind: NoticeKind::Unavailable,
                    path,
                    reason: e.to_string(),
                });
                continue;
            }
        };
        for child in children {
            if pending.len() + visited.len() + output.notices.len() > 65_536 {
                output.notices.push(Notice {
                    kind: NoticeKind::Limit,
                    path: path.clone(),
                    reason: "traversal inventory limit; discovery incomplete".into(),
                });
                break 'walk;
            }
            match child {
                Err(e) => output.notices.push(Notice {
                    kind: NoticeKind::Unavailable,
                    path: path.clone(),
                    reason: e.to_string(),
                }),
                Ok(child) => {
                    let p = child.path();
                    let name = child.file_name();
                    if [".git", ".kan", "node_modules", "target"]
                        .iter()
                        .any(|s| name == *s)
                    {
                        output.notices.push(Notice {
                            kind: NoticeKind::Excluded,
                            path: p,
                            reason: "excluded traversal directory".into(),
                        });
                    } else {
                        match child.file_type() {
                            Ok(t) if t.is_dir() || t.is_symlink() => pending.push((p, depth + 1)),
                            Ok(_) => {}
                            Err(e) => output.notices.push(Notice {
                                kind: NoticeKind::Unavailable,
                                path: p,
                                reason: e.to_string(),
                            }),
                        }
                    }
                }
            }
        }
    }
    output.roots.sort();
    output.notices.sort_by(|a, b| a.path.cmp(&b.path));
    output
}

#[derive(Debug, Serialize)]
pub struct CarScan {
    pub roots: Vec<String>,
    pub verified_blocks: u64,
    pub unsupported_blocks: u64,
    pub error: Option<String>,
}

fn varint(reader: &mut impl Read) -> io::Result<Option<u64>> {
    let mut value = 0u64;
    for i in 0..10 {
        let mut byte = [0];
        match reader.read_exact(&mut byte) {
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof && i == 0 => return Ok(None),
            other => other?,
        }
        if i == 9 && byte[0] > 1 {
            return Err(io::Error::other("overflowing varint"));
        }
        value |= u64::from(byte[0] & 127) << (i * 7);
        if byte[0] & 128 == 0 {
            if i > 0 && byte[0] == 0 {
                return Err(io::Error::other("nonminimal varint"));
            }
            return Ok(Some(value));
        }
    }
    Err(io::Error::other("unterminated varint"))
}
fn required_varint(reader: &mut impl Read) -> io::Result<u64> {
    varint(reader)?.ok_or_else(|| io::Error::other("missing varint"))
}

/// Streaming CAR v1 framing/hash inspection, not graph or signature validation.
pub fn scan_car(file: &mut File) -> CarScan {
    let mut result = CarScan {
        roots: vec![],
        verified_blocks: 0,
        unsupported_blocks: 0,
        error: None,
    };
    if let Err(error) = scan_car_inner(file, &mut result) {
        result.error = Some(error.to_string());
    }
    result
}
fn scan_car_inner(file: &mut File, result: &mut CarScan) -> io::Result<()> {
    file.rewind()?;
    let total = file.metadata()?.len();
    let header_length = required_varint(file)?;
    if header_length == 0 || header_length > BUFFER as u64 {
        return Err(io::Error::other("CAR header length"));
    }
    let mut header = vec![0; header_length as usize];
    file.read_exact(&mut header)?;
    let value: Ipld = drisl::from_slice_with_config(
        &header,
        drisl::DecodeConfig {
            max_depth: 32,
            max_alloc: BUFFER,
            max_array_elements: BUFFER,
            max_map_entries: BUFFER,
            ..Default::default()
        },
    )
    .map_err(io::Error::other)?;
    let Ipld::Map(header) = value else {
        return Err(io::Error::other("CAR header not map"));
    };
    if header.get("version") != Some(&Ipld::Integer(1)) {
        return Err(io::Error::other("unsupported CAR version"));
    }
    let Some(Ipld::List(roots)) = header.get("roots") else {
        return Err(io::Error::other("missing CAR roots"));
    };
    for root in roots {
        let Ipld::Link(cid) = root else {
            return Err(io::Error::other("non-CID CAR root"));
        };
        result.roots.push(cid.to_string());
    }
    let mut buffer = [0u8; BUFFER];
    while let Some(frame_length) = varint(file)? {
        if frame_length == 0 || frame_length > total.saturating_sub(file.stream_position()?) {
            return Err(io::Error::other("truncated or zero CAR frame"));
        }
        let mut frame = (&mut *file).take(frame_length);
        let version = required_varint(&mut frame)?;
        if version != 1 {
            return Err(io::Error::other(
                "unsupported CID version; raw file retained",
            ));
        }
        let codec = required_varint(&mut frame)?;
        let hash_code = required_varint(&mut frame)?;
        let digest_length = required_varint(&mut frame)?;
        if digest_length == 0 || digest_length > 128 || digest_length > frame.limit() {
            return Err(io::Error::other("CID digest length"));
        }
        let mut expected = vec![0; digest_length as usize];
        frame.read_exact(&mut expected)?;
        let mut digest = Sha256::new();
        loop {
            let n = frame.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            digest.update(&buffer[..n]);
        }
        if frame.limit() != 0 {
            return Err(io::Error::other("truncated CAR body"));
        }
        if hash_code == 0x12 && digest_length == 32 && [0x55, 0x71].contains(&codec) {
            if digest.finalize().as_slice() != expected {
                return Err(io::Error::other("CAR block digest mismatch"));
            }
            result.verified_blocks += 1;
        } else {
            result.unsupported_blocks += 1;
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct SourceFile {
    pub path: PathBuf,
    pub medium: &'static str,
    pub length: u64,
    pub sha256: String,
    pub car: Option<CarScan>,
}
#[derive(Debug, Serialize)]
pub struct Preview {
    pub selection: &'static str,
    pub selected_inventory_complete: bool,
    pub public_identity_history: &'static str,
    pub root: PathBuf,
    pub files: Vec<SourceFile>,
    pub notices: Vec<Notice>,
    pub observed_bytes: u64,
    pub claim_signatures: &'static str,
    pub graph_reachability: &'static str,
    pub git_history: &'static str,
    pub snapshot: &'static str,
    pub ready_for_cutover: bool,
}

fn unchanged(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    let stable = before.len() == after.len() && before.modified().ok() == after.modified().ok();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        stable
            && before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        stable
    }
}
fn inspect(root: &Path, path: &Path, medium: &'static str, car: bool) -> io::Result<SourceFile> {
    let relative = path.strip_prefix(root).map_err(io::Error::other)?;
    let mut parent = root.to_path_buf();
    if let Some(components) = relative.parent() {
        for component in components.components() {
            parent.push(component);
            let meta = fs::symlink_metadata(&parent)?;
            if !meta.is_dir() || meta.file_type().is_symlink() {
                return Err(io::Error::other(
                    "evidence ancestor is not a real directory",
                ));
            }
        }
    }
    let before = fs::symlink_metadata(path)?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err(io::Error::other("not a regular evidence file"));
    }
    let mut file = File::open(path)?;
    if !unchanged(&before, &file.metadata()?) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "source changed or replaced before read",
        ));
    }
    let mut digest = Sha256::new();
    let mut buffer = [0; BUFFER];
    let mut length = 0;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
        length += n as u64;
    }
    let scan = if car { Some(scan_car(&mut file)) } else { None };
    if length != before.len()
        || !unchanged(&before, &file.metadata()?)
        || !unchanged(&before, &fs::symlink_metadata(path)?)
    {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "source changed during inspection",
        ));
    }
    Ok(SourceFile {
        path: path.strip_prefix(root).map_err(io::Error::other)?.into(),
        medium,
        length,
        sha256: format!("{:x}", digest.finalize()),
        car: scan,
    })
}

pub fn preview(root: &Path) -> io::Result<Preview> {
    if fs::symlink_metadata(root)?.file_type().is_symlink() {
        return Err(io::Error::other("workspace root is a symlink"));
    }
    let root = root.canonicalize()?;
    let mut found = false;
    for marker in [".kan", ".claims"] {
        match fs::symlink_metadata(root.join(marker)) {
            Ok(m) if m.is_dir() && !m.file_type().is_symlink() => found = true,
            Ok(_) => return Err(io::Error::other("workspace marker is not a real directory")),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    if !found {
        return Err(io::Error::other("no workspace evidence marker"));
    }
    let mut output = empty_preview(root.clone(), "workspace");
    let mut selected = Vec::new();
    for (name, medium) in [("log", "primary-log"), ("overlay", "derived-recovery")] {
        let dir = root.join(".kan").join(name);
        match fs::symlink_metadata(&dir) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => {
                output.notices.push(Notice {
                    kind: NoticeKind::Unavailable,
                    path: dir,
                    reason: e.to_string(),
                });
                continue;
            }
            Ok(m) if !m.is_dir() || m.file_type().is_symlink() => {
                output.notices.push(Notice {
                    kind: NoticeKind::Unsupported,
                    path: dir,
                    reason: "evidence directory is not a real directory".into(),
                });
                continue;
            }
            Ok(_) => {}
        }
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == "repo.car" || name.starts_with("repo.car.damaged-") || name == "HEAD" {
                selected.push((entry.path(), medium, name != "HEAD"));
            } else {
                output.notices.push(Notice {
                    kind: NoticeKind::Excluded,
                    path: entry.path(),
                    reason: "unselected log artifact (including coordination files)".into(),
                });
            }
            if selected.len() + output.notices.len() > MAX_FILES {
                return Err(io::Error::other("file inventory limit; preview incomplete"));
            }
        }
    }
    let scope_dir = root.join(".kan/scope");
    match fs::symlink_metadata(&scope_dir) {
        Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {
            let scope = scope_dir.join("inception.cbor");
            match fs::symlink_metadata(&scope) {
                Ok(_) => selected.push((scope, "public-scope", false)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => output.notices.push(Notice {
                    kind: NoticeKind::Unavailable,
                    path: scope,
                    reason: e.to_string(),
                }),
            }
        }
        Ok(_) => output.notices.push(Notice {
            kind: NoticeKind::Unsupported,
            path: scope_dir,
            reason: "scope directory is not a real directory".into(),
        }),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => output.notices.push(Notice {
            kind: NoticeKind::Unavailable,
            path: scope_dir,
            reason: e.to_string(),
        }),
    }
    let claims = root.join(".claims");
    let mut pending = match fs::symlink_metadata(&claims) {
        Ok(_) => vec![(claims, 0)],
        Err(e) if e.kind() == io::ErrorKind::NotFound => vec![],
        Err(e) => return Err(e),
    };
    while let Some((path, depth)) = pending.pop() {
        let meta = fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() {
            output.notices.push(Notice {
                kind: NoticeKind::Unsupported,
                path,
                reason: "publication symlink not followed".into(),
            });
            continue;
        }
        if depth > MAX_DEPTH {
            return Err(io::Error::other(
                "publication depth limit; preview incomplete",
            ));
        }
        if meta.is_dir() {
            for entry in fs::read_dir(path)? {
                pending.push((entry?.path(), depth + 1));
                if selected.len() + pending.len() + output.notices.len() > MAX_FILES {
                    return Err(io::Error::other("file inventory limit; preview incomplete"));
                }
            }
        } else if meta.is_file() && path.extension().is_some_and(|v| v == "md") {
            selected.push((path, "publication-working-tree", false));
        } else {
            output.notices.push(Notice {
                kind: NoticeKind::Excluded,
                path,
                reason: "unselected publication artifact".into(),
            });
        }
        if selected.len() + pending.len() > MAX_FILES {
            return Err(io::Error::other("file inventory limit; preview incomplete"));
        }
    }
    if selected.len() > MAX_FILES {
        return Err(io::Error::other("file inventory limit; preview incomplete"));
    }
    selected.sort_by(|a, b| a.0.cmp(&b.0));
    for (path, medium, car) in selected {
        match inspect(&root, &path, medium, car) {
            Ok(file) => {
                record_file(&mut output, file);
            }
            Err(e) => output.notices.push(Notice {
                kind: inspection_kind(&e),
                path,
                reason: e.to_string(),
            }),
        }
    }
    output.notices.push(Notice {
        kind: NoticeKind::Excluded,
        path: root.join(".kan"),
        reason: "private credentials, identity keys, indexes and unselected configuration excluded from evidence preview".into(),
    });
    finish_inventory(&mut output);
    Ok(output)
}

fn empty_preview(root: PathBuf, selection: &'static str) -> Preview {
    Preview {
        selection,
        selected_inventory_complete: false,
        public_identity_history: "not-inventoried",
        root,
        files: vec![],
        notices: vec![],
        observed_bytes: 0,
        claim_signatures: "not-verified",
        graph_reachability: "not-verified",
        git_history: "not-inventoried",
        snapshot: "file-level-observation-not-atomic",
        ready_for_cutover: false,
    }
}

fn finish_inventory(output: &mut Preview) {
    output.selected_inventory_complete = output
        .notices
        .iter()
        .all(|n| n.kind == NoticeKind::Excluded)
        && output.files.iter().all(|f| {
            f.car
                .as_ref()
                .is_none_or(|c| c.error.is_none() && c.unsupported_blocks == 0)
        });
}

/// Explicit selection only. No global configuration lookup or credential reads.
pub fn preview_identity(root: &Path) -> io::Result<Preview> {
    preview_selected(root, "public-identity-history", "identity/ledger/events")
}

/// Inspect a caller-selected raw log directory without opening the legacy log.
pub fn preview_store(root: &Path) -> io::Result<Preview> {
    preview_selected(root, "log-directory", "")
}

fn preview_selected(root: &Path, selection: &'static str, relative: &str) -> io::Result<Preview> {
    if fs::symlink_metadata(root)?.file_type().is_symlink() {
        return Err(io::Error::other("source root is a symlink"));
    }
    let root = root.canonicalize()?;
    let mut output = empty_preview(root.clone(), selection);
    let mut directory = root.clone();
    for part in Path::new(relative).components() {
        directory.push(part);
        match fs::symlink_metadata(&directory) {
            Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {}
            other => {
                output.notices.push(Notice {
                    kind: NoticeKind::Unavailable,
                    path: directory,
                    reason: format!("selected evidence directory unavailable: {other:?}"),
                });
                return Ok(output);
            }
        }
    }
    let mut selected = Vec::new();
    for entry in fs::read_dir(&directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let log = name == "repo.car"
            || name == "HEAD"
            || name
                .to_str()
                .is_some_and(|n| n.starts_with("repo.car.damaged-"));
        let public = selection == "public-identity-history"
            && entry.path().extension().is_some_and(|e| e == "cbor");
        if public || (selection == "log-directory" && log) {
            selected.push(entry.path());
        } else {
            output.notices.push(Notice {
                kind: NoticeKind::Excluded,
                path: entry.path(),
                reason: "outside selected evidence allowlist".into(),
            });
        }
        if selected.len() + output.notices.len() > MAX_FILES {
            return Err(io::Error::other("file inventory limit; preview incomplete"));
        }
    }
    selected.sort();
    for path in selected {
        let car = selection == "log-directory" && path.file_name().is_some_and(|n| n != "HEAD");
        match inspect(&root, &path, selection, car) {
            Ok(file) => {
                record_file(&mut output, file);
            }
            Err(e) => output.notices.push(Notice {
                kind: inspection_kind(&e),
                path,
                reason: e.to_string(),
            }),
        }
    }
    if selection == "public-identity-history" {
        output.public_identity_history = "selected-public-files-not-verified";
    }
    finish_inventory(&mut output);
    Ok(output)
}

fn inspection_kind(error: &io::Error) -> NoticeKind {
    if error.kind() == io::ErrorKind::Interrupted {
        NoticeKind::Changed
    } else {
        NoticeKind::Unavailable
    }
}

fn record_file(output: &mut Preview, file: SourceFile) {
    if let Some(scan) = &file.car {
        if scan.error.is_some() || scan.unsupported_blocks > 0 {
            output.notices.push(Notice {
                kind: NoticeKind::Unsupported,
                path: file.path.clone(),
                reason: format!(
                    "CAR inspection incomplete: error={:?}, unsupported_blocks={}",
                    scan.error, scan.unsupported_blocks
                ),
            });
        }
    }
    output.observed_bytes += file.length;
    output.files.push(file);
}

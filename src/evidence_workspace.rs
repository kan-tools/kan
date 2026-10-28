//! Encrypted reader workspace. Cached interpretations are disposable; saved view
//! declarations are owner-authored records. Neither grants access to evidence.
use crate::{
    evidence_crypto as crypto,
    evidence_service::{self, Failure},
    sign::{self, Identity},
};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    sync::{Arc, Mutex},
};
pub(crate) mod annotations;
pub mod erasure;
pub mod publication;

type Result<T> = std::result::Result<T, Failure>;
const MAX: usize = 12 * 1024 * 1024;
const SCHEMA: &str = "PRAGMA application_id=1264014129; PRAGMA user_version=1;
CREATE TABLE entries(kind TEXT NOT NULL, id TEXT NOT NULL, body BLOB NOT NULL, PRIMARY KEY(kind,id));";
const DOMAIN: &[u8] = b"tools.kan.reader.workspace.v1\0";
// A scheduler owns this lease independently of database/maintenance locks.
// Explicit unlock prevents fork-inherited descriptors delaying a clean restart.
// This lease is deliberately not clonable; maintenance leases below share an
// owned guard to extend their lifetime through recovery cleanup.
pub(crate) struct AnalysisLease(std::fs::File);
impl Drop for AnalysisLease {
    fn drop(&mut self) {
        let _ = fs4::FileExt::unlock(&self.0);
    }
}
// Recovery must retain exclusion after closing the recovered SQLite connection.
// Share the guard, not duplicated file handles: only the last deliberate owner
// unlocks, even if an unrelated fork still holds an inherited descriptor.
struct MaintenanceLease(Arc<MaintenanceLock>);
struct MaintenanceLock {
    file: std::fs::File,
}
impl Drop for MaintenanceLock {
    fn drop(&mut self) {
        let _ = fs4::FileExt::unlock(&self.file);
    }
}
impl MaintenanceLease {
    fn acquire(path: &Path, exclusive: bool) -> Result<Self> {
        lease(path, ".maintenance-lock", exclusive)
            .map(|file| Self(Arc::new(MaintenanceLock { file })))
    }
    fn retain(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}
pub struct Workspace {
    conn: Mutex<Connection>,
    // Field order matters: close SQLite before releasing maintenance exclusion.
    _maintenance: MaintenanceLease,
    erasure_maintenance: bool,
    erasure_histories: Vec<crate::evidence_erasure_history::Access>,
    erasure_audit: Mutex<Option<(i64, Vec<String>)>>,
    annotation_lookup: Mutex<Option<annotations::Lookup>>,
    path: std::path::PathBuf,
    signer: Identity,
    private: [u8; 32],
    scope: [u8; 32],
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    version: u8,
    kind: String,
    id: String,
    author: String,
    value: Value,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Signed {
    body: Body,
    signature: String,
}
fn invalid<T>(_: T) -> Failure {
    Failure::Corrupt
}
fn private(path: &Path, directory: bool) -> Result<()> {
    let m = std::fs::symlink_metadata(path).map_err(invalid)?;
    if m.file_type().is_symlink() || (directory && !m.is_dir()) || (!directory && !m.is_file()) {
        return Err(Failure::Invalid);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if m.permissions().mode() & 0o077 != 0 || (!directory && m.nlink() != 1) {
            return Err(Failure::Invalid);
        }
    }
    Ok(())
}
fn sidecar(path: &Path, suffix: &str) -> std::path::PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    name.into()
}
// Use a separate inode: flock and SQLite locks interact on macOS.
fn lease(path: &Path, suffix: &str, exclusive: bool) -> Result<std::fs::File> {
    let lock = sidecar(path, suffix);
    match std::fs::symlink_metadata(&lock) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // surface-write: evidence-workspace:database-lock
            match crate::persistence::write_new_owner_only(
                crate::persistence::SurfaceWrite::EvidenceWorkspace,
                &lock,
                &[],
            ) {
                Ok(()) => (),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(e) => return Err(invalid(e)),
            }
        }
        Err(e) => return Err(invalid(e)),
        Ok(_) => (),
    }
    private(&lock, false)?;
    let file = std::fs::File::open(&lock).map_err(invalid)?;
    if file.metadata().map_err(invalid)?.len() != 0 {
        return Err(Failure::Invalid);
    }
    if exclusive {
        fs4::FileExt::try_lock(&file)
    } else {
        fs4::FileExt::try_lock_shared(&file)
    }
    .map_err(|_| Failure::Unavailable)?;
    Ok(file)
}
impl Workspace {
    /// Caller selects a private directory and dedicated recipient key. No source
    /// archive, repo checkout, or browser storage is used as the workspace.
    pub fn open(path: &Path, signer: Identity, private_key: [u8; 32]) -> Result<Self> {
        private(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .ok_or(Failure::Invalid)?,
            true,
        )?;
        let maintenance = MaintenanceLease::acquire(path, false)?;
        Self::open_locked(path, signer, private_key, maintenance, false)
    }
    fn open_locked(
        path: &Path,
        signer: Identity,
        private_key: [u8; 32],
        maintenance: MaintenanceLease,
        recover_copy: bool,
    ) -> Result<Self> {
        for suffix in ["-journal", "-wal", "-shm"] {
            if suffix == "-journal" && recover_copy {
                continue;
            }
            let mut side = path.as_os_str().to_os_string();
            side.push(suffix);
            match std::fs::symlink_metadata(Path::new(&side)) {
                Ok(_) => return Err(Failure::Unavailable),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Err(_) => return Err(Failure::Unavailable),
            }
        }
        let fresh = match std::fs::symlink_metadata(path) {
            Ok(_) => {
                private(path, false)?;
                false
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
            Err(_) => return Err(Failure::Unavailable),
        };
        if fresh {
            // surface-write: evidence-workspace:database
            crate::persistence::write_new_owner_only(
                crate::persistence::SurfaceWrite::EvidenceWorkspace,
                path,
                &[],
            )
            .map_err(invalid)?;
        } else {
            let mut header = [0u8; 20];
            std::fs::File::open(path)
                .map_err(invalid)?
                .read_exact(&mut header)
                .map_err(invalid)?;
            if &header[..16] != b"SQLite format 3\0" || header[18..20] != [1, 1] {
                return Err(Failure::Corrupt);
            }
        }
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)
            .map_err(invalid)?;
        conn.busy_timeout(std::time::Duration::from_millis(100))
            .map_err(invalid)?;
        conn.set_limit(
            rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH,
            (MAX + 8192) as i32,
        )
        .map_err(invalid)?;
        conn.execute_batch("PRAGMA trusted_schema=OFF;")
            .map_err(invalid)?;
        if fresh {
            let tx = conn.unchecked_transaction().map_err(invalid)?;
            tx.execute_batch(SCHEMA).map_err(invalid)?;
            tx.commit().map_err(invalid)?;
        }
        let expected = Connection::open_in_memory().map_err(invalid)?;
        expected.execute_batch(SCHEMA).map_err(invalid)?;
        fn schema(c: &Connection) -> rusqlite::Result<Vec<(String, String)>> {
            c.prepare("SELECT name,coalesce(sql,'') FROM sqlite_schema ORDER BY name")?
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect()
        }
        if schema(&conn).map_err(invalid)? != schema(&expected).map_err(invalid)?
            || conn
                .query_row("PRAGMA application_id", [], |r| r.get::<_, u32>(0))
                .map_err(invalid)?
                != 1264014129
            || !matches!(
                conn.query_row("PRAGMA user_version", [], |r| r.get::<_, u32>(0))
                    .map_err(invalid)?,
                1 | 2
            )
        {
            return Err(Failure::Corrupt);
        }
        let profile: u32 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(invalid)?;
        let has_erasure: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM entries WHERE kind='erasure')",
                [],
                |r| r.get(0),
            )
            .map_err(invalid)?;
        if (profile == 2) != has_erasure {
            return Err(Failure::Corrupt);
        }
        conn.execute_batch(
            "PRAGMA synchronous=FULL; PRAGMA fullfsync=ON; PRAGMA max_page_count=4294967294;",
        )
        .map_err(invalid)?;
        let scope = Sha256::digest(
            [
                DOMAIN,
                signer.did().as_bytes(),
                &crypto::public_key(&private_key).map_err(invalid)?,
            ]
            .concat(),
        )
        .into();
        let workspace = Self {
            conn: Mutex::new(conn),
            _maintenance: maintenance,
            erasure_maintenance: false,
            erasure_histories: Vec::new(),
            erasure_audit: Mutex::new(None),
            annotation_lookup: Mutex::new(None),
            path: path.to_path_buf(),
            signer,
            private: private_key,
            scope,
        };
        let binding = serde_json::json!({"version":1,"author":workspace.author()});
        if fresh {
            workspace.put("binding", "binding", binding)?;
            std::fs::File::open(path.parent().ok_or(Failure::Invalid)?)
                .map_err(invalid)?
                .sync_all()
                .map_err(invalid)?;
        } else if workspace.get("binding", "binding")? != Some(binding) {
            return Err(Failure::Corrupt);
        }
        Ok(workspace)
    }
    /// Recover a stopped workspace on a new copy. The original database and
    /// rollback journal remain byte-for-byte intact, including on failure.
    /// Older processes without maintenance locking must be stopped by the owner.
    pub fn recover(
        source: &Path,
        destination: &Path,
        signer: Identity,
        private_key: [u8; 32],
    ) -> Result<Value> {
        for path in [source, destination] {
            private(
                path.parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .ok_or(Failure::Invalid)?,
                true,
            )?;
        }
        private(source, false)?;
        let _source_lease = MaintenanceLease::acquire(source, true)?;
        let target_lease = MaintenanceLease::acquire(destination, true)?;
        for suffix in ["", "-journal", "-wal", "-shm"] {
            match std::fs::symlink_metadata(sidecar(destination, suffix)) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                _ => return Err(Failure::Invalid),
            }
        }
        for suffix in ["-wal", "-shm"] {
            match std::fs::symlink_metadata(sidecar(source, suffix)) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                _ => return Err(Failure::Invalid),
            }
        }
        // Copy/hash fixed-size chunks. Recovery must not need the entire lifetime
        // workspace (or rollback journal) resident in memory.
        fn transfer(path: &Path, output: Option<&mut std::fs::File>) -> Result<String> {
            private(path, false)?;
            let mut source = std::fs::File::open(path).map_err(invalid)?;
            let mut output = output;
            let mut hash = Sha256::new();
            let mut chunk = [0u8; 65536];
            loop {
                let n = source.read(&mut chunk).map_err(invalid)?;
                if n == 0 {
                    break;
                }
                hash.update(&chunk[..n]);
                if let Some(writer) = &mut output {
                    writer.write_all(&chunk[..n]).map_err(invalid)?;
                }
            }
            Ok(evidence_service::hex(&hash.finalize()))
        }
        fn validate_copy(path: &Path, suffix: &str) -> Result<()> {
            private(path, false)?;
            let mut file = std::fs::File::open(path).map_err(invalid)?;
            let mut header = [0u8; 28];
            file.read_exact(&mut header).map_err(invalid)?;
            if suffix.is_empty() {
                if &header[..16] != b"SQLite format 3\0" || header[18..20] != [1, 1] {
                    return Err(Failure::Corrupt);
                }
            } else {
                // This application never ATTACHes databases. Refuse super-journal
                // pointers before SQLite can follow a path outside the new copy.
                const MAGIC: &[u8] = &[0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7];
                let mut tail = [0u8; 8];
                file.seek(SeekFrom::End(-8)).map_err(invalid)?;
                file.read_exact(&mut tail).map_err(invalid)?;
                if (header[..8] != *MAGIC && header[..8] != [0; 8]) || tail == *MAGIC {
                    return Err(Failure::Corrupt);
                }
            }
            Ok(())
        }
        let journal = sidecar(source, "-journal");
        let journal_present = match std::fs::symlink_metadata(&journal) {
            Ok(_) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(invalid(e)),
        };
        let mut hashes = Vec::new();
        for suffix in if journal_present {
            vec!["", "-journal"]
        } else {
            vec![""]
        } {
            let input = sidecar(source, suffix);
            validate_copy(&input, suffix)?;
            // surface-write: evidence-workspace-recovery:database,evidence-workspace-recovery:database-journal
            let mut output = crate::persistence::open_new_owner_only(
                crate::persistence::SurfaceWrite::EvidenceWorkspaceRecovery,
                &sidecar(destination, suffix),
            )
            .map_err(invalid)?;
            let digest = transfer(&input, Some(&mut output))?;
            output.sync_all().map_err(invalid)?;
            drop(output);
            // Revalidate the actual copied bytes before SQLite can interpret a
            // rollback journal. The source may have changed while being copied.
            validate_copy(&sidecar(destination, suffix), suffix)?;
            hashes.push((suffix, digest));
        }
        let recovered = Self::open_locked(destination, signer, private_key, target_lease, true)?;
        let mut counts = std::collections::BTreeMap::<String, u64>::new();
        {
            let conn = recovered.conn.lock().map_err(invalid)?;
            let integrity: String = conn
                .query_row("PRAGMA integrity_check", [], |r| r.get(0))
                .map_err(invalid)?;
            if integrity != "ok" {
                return Err(Failure::Corrupt);
            }
            let mut query = conn
                .prepare("SELECT kind,id,body FROM entries ORDER BY kind,id")
                .map_err(invalid)?;
            let mut rows = query.query([]).map_err(invalid)?;
            while let Some(row) = rows.next().map_err(invalid)? {
                let kind: String = row.get(0).map_err(invalid)?;
                let id: String = row.get(1).map_err(invalid)?;
                let body: Vec<u8> = row.get(2).map_err(invalid)?;
                if erasure::erased(&recovered, &conn, &kind, &id)? {
                    return Err(Failure::Corrupt);
                }
                recovered.unseal(&kind, &id, &body)?;
                *counts.entry(kind).or_default() += 1;
            }
        }
        // Every original input must still match the retained copy's source bytes.
        for (suffix, expected) in &hashes {
            if transfer(&sidecar(source, suffix), None)? != *expected {
                return Err(Failure::Unavailable);
            }
        }
        let author = recovered.author();
        let _cleanup_lease = recovered._maintenance.retain();
        drop(recovered);
        // SQLite can leave an ignored, non-hot journal. Only the verified new
        // copy's sidecar is removed; the original remains available for forensics.
        let output_journal = sidecar(destination, "-journal");
        if output_journal.exists() {
            // surface-write: evidence-workspace-recovery:database-journal
            crate::persistence::remove_file(
                crate::persistence::SurfaceWrite::EvidenceWorkspaceRecovery,
                &output_journal,
            )
            .map_err(invalid)?;
        }
        std::fs::File::open(destination)
            .map_err(invalid)?
            .sync_all()
            .map_err(invalid)?;
        std::fs::File::open(destination.parent().ok_or(Failure::Invalid)?)
            .map_err(invalid)?
            .sync_all()
            .map_err(invalid)?;
        Ok(
            serde_json::json!({"source":source,"destination":destination,"author":author,"authenticated_entries":counts,"source_hashes":hashes,"rollback_journal_present":journal_present,"originals":"retained","activation":"not-performed","independent_backup":false,"coverage":"Authenticated entries present after SQLite rollback recovery. Compare an independent checkpoint to detect missing history."}),
        )
    }
    /// Queue the immutable authored declaration, not a mutable browser draft.
    pub(crate) fn queue_import(
        &self,
        plan: &crate::evidence_import::Plan,
        expected: &str,
        spool: &mut crate::evidence_spool::Spool,
        limit: usize,
    ) -> std::result::Result<crate::evidence_import::Progress, crate::evidence_import::Error> {
        plan.enqueue(expected, spool, &self.signer, limit)
    }
    pub(crate) fn queue_annotation(
        &self,
        spool: &mut crate::evidence_spool::Spool,
        recipient: &[u8; 32],
        operation: &[u8; 16],
        id: &str,
    ) -> Result<()> {
        let _custody = self.publication_lease()?;
        let declaration = self.get("annotation", id)?.ok_or(Failure::AccessLimited)?;
        let bytes = serde_json::to_vec(
            &serde_json::json!({"format":"kan-annotation/1","declaration":declaration}),
        )
        .map_err(invalid)?;
        match crate::evidence_delivery::queue_bound(
            spool,
            &self.signer,
            recipient,
            operation,
            &bytes,
            |queued| {
                self.put(
                    "annotation-publication",
                    &queued.manifest,
                    serde_json::json!({
                        "version":1,"annotation":id,"manifest":queued.manifest,
                    }),
                )?;
                Ok(())
            },
        ) {
            Ok(_) => Ok(()),
            Err(crate::evidence_delivery::Error::ReusedOperation) => {
                let retained = spool
                    .operation(&evidence_service::hex(operation))
                    .map_err(invalid)?
                    .ok_or(Failure::AccessLimited)?;
                let binding = self
                    .get("annotation-publication", &retained.manifest)?
                    .ok_or(Failure::AccessLimited)?;
                if binding["version"] != 1
                    || binding["annotation"] != id
                    || binding["manifest"] != retained.manifest
                {
                    return Err(Failure::AccessLimited);
                }
                Ok(())
            }
            Err(_) => Err(Failure::Unavailable),
        }
    }
    /// A single analysis scheduler owns this workspace at a time. The advisory
    /// lifetime lock does not modify the database or replace SQLite transactions.
    pub(crate) fn analysis_lease(&self) -> Result<AnalysisLease> {
        lease(&self.path, ".scheduler-lock", true).map(AnalysisLease)
    }
    pub fn author(&self) -> String {
        self.signer.did().to_string()
    }
    fn id(kind: &str, key: &str) -> String {
        evidence_service::hex(&Sha256::digest(
            [DOMAIN, kind.as_bytes(), b"\0", key.as_bytes()].concat(),
        ))
    }
    fn seal(&self, kind: &str, id: &str, value: Value) -> Result<Vec<u8>> {
        let body = Body {
            version: 1,
            kind: kind.into(),
            id: id.into(),
            author: self.author(),
            value,
        };
        let bytes = serde_json::to_vec(&body).map_err(invalid)?;
        let signature = evidence_service::hex(
            &self
                .signer
                .sign(&[DOMAIN, &bytes].concat())
                .map_err(invalid)?,
        );
        let plain = serde_json::to_vec(&Signed { body, signature }).map_err(invalid)?;
        if plain.len() > MAX - 8192 {
            return Err(Failure::Invalid);
        }
        let public = crypto::public_key(&self.private).map_err(invalid)?;
        let mut out = Vec::new();
        for part in plain.chunks(crypto::MAX_PLAINTEXT) {
            let frame = crypto::seal(&public, &self.scope, part).map_err(invalid)?;
            out.extend_from_slice(&(frame.len() as u32).to_be_bytes());
            out.extend(frame);
        }
        Ok(out)
    }
    fn unseal(&self, kind: &str, id: &str, bytes: &[u8]) -> Result<Value> {
        if bytes.len() > MAX {
            return Err(Failure::Corrupt);
        }
        let mut rest = bytes;
        let mut plain = Vec::new();
        while !rest.is_empty() {
            let n = u32::from_be_bytes(
                rest.get(..4)
                    .ok_or(Failure::Corrupt)?
                    .try_into()
                    .map_err(invalid)?,
            ) as usize;
            let frame = rest
                .get(4..4usize.checked_add(n).ok_or(Failure::Corrupt)?)
                .ok_or(Failure::Corrupt)?;
            plain.extend(crypto::open(&self.private, &self.scope, frame).map_err(invalid)?);
            rest = &rest[4 + n..];
        }
        let signed: Signed = serde_json::from_slice(&plain).map_err(invalid)?;
        let b = &signed.body;
        if b.version != 1
            || b.kind != kind
            || b.id != id
            || b.author != self.author()
            || !sign::verify(
                &b.author,
                &[DOMAIN, &serde_json::to_vec(b).map_err(invalid)?].concat(),
                &evidence_service::unhex(&signed.signature, 64)?,
            )
        {
            return Err(Failure::Corrupt);
        }
        Ok(signed.body.value)
    }
    pub fn get(&self, kind: &str, key: &str) -> Result<Option<Value>> {
        let id = Self::id(kind, key);
        let conn = self.conn.lock().map_err(invalid)?;
        let tx = conn.unchecked_transaction().map_err(invalid)?;
        let _custody = self.check_erasure_histories(&tx)?;
        if erasure::erased(self, &tx, kind, &id)? {
            return Ok(None);
        }
        let bytes: Option<Vec<u8>> = tx
            .query_row(
                "SELECT body FROM entries WHERE kind=? AND id=?",
                params![kind, id],
                |r| r.get(0),
            )
            .optional()
            .map_err(invalid)?;
        bytes.map(|b| self.unseal(kind, &id, &b)).transpose()
    }
    pub(crate) fn backup_checkpoint(
        &self,
        statement: crate::evidence_backup::Statement,
    ) -> Result<crate::evidence_backup::Checkpoint> {
        crate::evidence_backup::Checkpoint::sign(statement, &self.signer)
    }
    /// Immutable, idempotent installation. A second value under an existing key
    /// is refused. SQLite commits the encrypted value and its identity together.
    pub fn put(&self, kind: &str, key: &str, value: Value) -> Result<()> {
        if !matches!(
            kind,
            "binding"
                | "search-page"
                | "view"
                | "annotation"
                | "annotation-publication"
                | "analysis-job"
                | "analysis-input"
                | "analysis-result"
                | "analysis-event"
                | "analysis-trigger"
                | "owner-job"
                | "owner-result"
        ) {
            return Err(Failure::Invalid);
        }
        if matches!(
            kind,
            "view"
                | "annotation"
                | "annotation-publication"
                | "analysis-job"
                | "analysis-event"
                | "analysis-trigger"
                | "owner-job"
                | "owner-result"
        ) && serde_json::to_vec(&value).map_err(invalid)?.len() > 262144
        {
            return Err(Failure::Invalid);
        }
        let id = Self::id(kind, key);
        let bytes = self.seal(kind, &id, value.clone())?;
        let mut conn = self.conn.lock().map_err(invalid)?;
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(invalid)?;
        let custody = self.check_erasure_histories(&tx)?;
        if erasure::erased(self, &tx, kind, &id)? {
            return Err(Failure::AccessLimited);
        }
        let prior: Option<Vec<u8>> = tx
            .query_row(
                "SELECT body FROM entries WHERE kind=? AND id=?",
                params![kind, id],
                |r| r.get(0),
            )
            .optional()
            .map_err(invalid)?;
        if let Some(prior) = prior {
            if self.unseal(kind, &id, &prior)? != value {
                return Err(Failure::Invalid);
            }
        } else {
            tx.execute(
                "INSERT INTO entries VALUES(?,?,?)",
                params![kind, id, bytes],
            )
            .map_err(invalid)?;
        }
        if kind == "annotation" {
            *self.annotation_lookup.lock().map_err(invalid)? = None;
        }
        // Local commits do not change this connection's data_version. Forget
        // its positive cache before validating prospective rows or committing.
        *self.erasure_audit.lock().map_err(invalid)? = None;
        self.audit_erasure_snapshots(&tx, &custody)?;
        tx.commit().map_err(invalid)
    }
    /// Replace only a disposable encrypted projection. Authored declarations
    /// continue to use immutable put(), and custody still fences erased inputs.
    pub(crate) fn replace_search_page(&self, key: &str, value: Value) -> Result<()> {
        let id = Self::id("search-page", key);
        let bytes = self.seal("search-page", &id, value)?;
        let mut conn = self.conn.lock().map_err(invalid)?;
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(invalid)?;
        let custody = self.check_erasure_histories(&tx)?;
        if erasure::erased(self, &tx, "search-page", &id)? {
            return Err(Failure::AccessLimited);
        }
        tx.execute("INSERT INTO entries VALUES('search-page',?,?) ON CONFLICT(kind,id) DO UPDATE SET body=excluded.body", params![id,bytes]).map_err(invalid)?;
        *self.erasure_audit.lock().map_err(invalid)? = None;
        self.audit_erasure_snapshots(&tx, &custody)?;
        tx.commit().map_err(invalid)
    }
    /// Explicit bounded cache maintenance. Freed pages are reusable by SQLite;
    /// no annotation, saved view, job, custody history or source archive is erased.
    pub(crate) fn prune_search_pages(&self) -> Result<Value> {
        let mut conn = self.conn.lock().map_err(invalid)?;
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(invalid)?;
        let _custody = self.check_erasure_histories(&tx)?;
        let removed = tx.execute("DELETE FROM entries WHERE kind='search-page' AND id IN (SELECT id FROM entries WHERE kind='search-page' ORDER BY id LIMIT 128)", []).map_err(invalid)?;
        let remaining: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM entries WHERE kind='search-page')",
                [],
                |r| r.get(0),
            )
            .map_err(invalid)?;
        *self.erasure_audit.lock().map_err(invalid)? = None;
        tx.commit().map_err(invalid)?;
        Ok(
            serde_json::json!({"removed":removed,"more":remaining,"scope":"disposable search index only; freed SQLite pages reusable; authored history retained"}),
        )
    }
    /// Bounded view declarations only; cache pages are addressed explicitly.
    pub fn views(&self) -> Result<Vec<Value>> {
        self.declarations("view", Some(200))
    }
    pub fn annotations(&self) -> Result<Vec<Value>> {
        self.declarations("annotation", None)
    }
    /// Keyset pagination over immutable encrypted journal identities. The cursor
    /// is opaque; concurrent inserts before it appear on a fresh traversal.
    pub(crate) fn owner_jobs_page(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<Value>, Option<String>)> {
        self.declarations_page("owner-job", after, limit)
    }
    /// Page saved views independently of the workspace's lifetime length.
    pub fn views_page(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<Value>, Option<String>)> {
        self.declarations_page("view", after, limit)
    }
    fn declarations_page(
        &self,
        kind: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<Value>, Option<String>)> {
        if limit == 0
            || limit > 1000
            || after.is_some_and(|id| id.len() != 64 || evidence_service::unhex(id, 32).is_err())
        {
            return Err(Failure::Invalid);
        }
        let conn = self.conn.lock().map_err(invalid)?;
        let tx = conn.unchecked_transaction().map_err(invalid)?;
        let _custody = self.check_erasure_histories(&tx)?;
        let mut q = tx
            .prepare("SELECT id,body FROM entries WHERE kind=? AND id>? ORDER BY id LIMIT ?")
            .map_err(invalid)?;
        let rows = q
            .query_map(
                params![kind, after.unwrap_or(""), (limit + 1) as i64],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)),
            )
            .map_err(invalid)?;
        let mut out = Vec::new();
        let mut last = None;
        let mut bytes = 0usize;
        for (n, row) in rows.enumerate() {
            let (id, body) = row.map_err(invalid)?;
            // Bound one response independently of the journal's lifetime length.
            if n == limit || (n > 0 && bytes + body.len() > 1024 * 1024) {
                return Ok((out, last));
            }
            bytes += body.len();
            if !erasure::erased(self, &tx, kind, &id)? {
                out.push(self.unseal(kind, &id, &body)?);
            }
            last = Some(id);
        }
        Ok((out, None))
    }
    pub(crate) fn analysis_jobs(&self) -> Result<Vec<Value>> {
        self.declarations("analysis-job", Some(1000))
    }
    fn declarations(&self, kind: &str, limit: Option<usize>) -> Result<Vec<Value>> {
        let conn = self.conn.lock().map_err(invalid)?;
        let tx = conn.unchecked_transaction().map_err(invalid)?;
        let _custody = self.check_erasure_histories(&tx)?;
        let mut q = tx
            .prepare("SELECT id,body FROM entries WHERE kind=? ORDER BY id LIMIT ?")
            .map_err(invalid)?;
        let rows = q
            .query_map(
                params![kind, limit.map(|n| (n + 1) as i64).unwrap_or(-1)],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)),
            )
            .map_err(invalid)?;
        let mut out = Vec::new();
        for row in rows {
            let (id, b) = row.map_err(invalid)?;
            if !erasure::erased(self, &tx, kind, &id)? {
                out.push(self.unseal(kind, &id, &b)?);
            }
        }
        if limit.is_some_and(|n| out.len() > n) {
            return Err(Failure::Invalid);
        }
        Ok(out)
    }
}

#[cfg(all(test, unix))]
mod lease_tests {
    use super::*;

    fn workspace_fixture() -> (tempfile::TempDir, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        // Synthetic fixture container, not a production workspace mutation.
        // surface-write: container:workspace
        crate::persistence::set_permissions(
            crate::persistence::SurfaceWrite::Container,
            directory.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let path = directory.path().join("workspace.sqlite");
        (directory, path)
    }

    fn signer() -> Identity {
        let mut seed = tempfile::NamedTempFile::new().unwrap();
        seed.write_all(&[6; 32]).unwrap();
        Identity::load_existing(seed.path()).unwrap()
    }

    #[test]
    fn workspace_maintenance_releases_inherited_descriptor_without_unlocking_other_users() {
        let (_directory, path) = workspace_fixture();
        let first = Workspace::open(&path, signer(), [8; 32]).unwrap();
        let second = Workspace::open(&path, signer(), [8; 32]).unwrap();
        let inherited = first._maintenance.0.file.try_clone().unwrap();
        assert!(Workspace::open_for_erasure(&path, signer(), [8; 32]).is_err());
        drop(first);
        assert!(Workspace::open_for_erasure(&path, signer(), [8; 32]).is_err());
        drop(second);
        // A close-only guard fails here while inherited remains alive.
        let maintenance = Workspace::open_for_erasure(&path, signer(), [8; 32]).unwrap();
        drop(inherited);
        assert!(Workspace::open(&path, signer(), [8; 32]).is_err());
        drop(maintenance);
        Workspace::open(&path, signer(), [8; 32]).unwrap();
    }

    #[test]
    fn recovery_cleanup_retains_exclusion_until_last_owned_lease_drops() {
        let (_directory, path) = workspace_fixture();
        let target = MaintenanceLease::acquire(&path, true).unwrap();
        let inherited = target.0.file.try_clone().unwrap();
        let recovered = Workspace::open_locked(&path, signer(), [8; 32], target, true).unwrap();
        let cleanup = recovered._maintenance.retain();
        drop(recovered);
        // Closing SQLite must not release the lease used by subsequent cleanup.
        assert!(Workspace::open(&path, signer(), [8; 32]).is_err());
        assert!(Workspace::open_for_erasure(&path, signer(), [8; 32]).is_err());
        drop(cleanup);
        let replacement = Workspace::open_for_erasure(&path, signer(), [8; 32]).unwrap();
        drop(inherited);
        assert!(Workspace::open(&path, signer(), [8; 32]).is_err());
        drop(replacement);
        Workspace::open(&path, signer(), [8; 32]).unwrap();
    }

    #[test]
    fn failed_workspace_open_preserves_retained_lease_and_releases_last_owner() {
        let (_directory, path) = workspace_fixture();
        let owner = MaintenanceLease::acquire(&path, true).unwrap();
        let inherited = owner.0.file.try_clone().unwrap();
        // Deliberately incomplete journal exercises refusal and lease cleanup.
        // surface-write: evidence-workspace:database-journal
        crate::persistence::write_new_owner_only(
            crate::persistence::SurfaceWrite::EvidenceWorkspace,
            &sidecar(&path, "-journal"),
            b"interrupted",
        )
        .unwrap();
        assert!(matches!(
            Workspace::open_locked(&path, signer(), [8; 32], owner.retain(), false),
            Err(Failure::Unavailable)
        ));
        assert!(MaintenanceLease::acquire(&path, false).is_err());
        drop(owner);
        let replacement = MaintenanceLease::acquire(&path, true).unwrap();
        drop(inherited);
        assert!(MaintenanceLease::acquire(&path, false).is_err());
        drop(replacement);
        MaintenanceLease::acquire(&path, false).unwrap();
    }

    #[test]
    fn scheduler_owner_unlocks_even_with_inherited_descriptor() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let owner = std::fs::File::open(file.path()).unwrap();
        fs4::FileExt::try_lock(&owner).unwrap();
        let owner = AnalysisLease(owner);
        let inherited = owner.0.try_clone().unwrap();
        let contender = std::fs::File::open(file.path()).unwrap();
        assert!(fs4::FileExt::try_lock(&contender).is_err());
        drop(owner);
        fs4::FileExt::try_lock(&contender).unwrap();
        // Dropping only the stale descriptor must not unlock the new owner.
        drop(inherited);
        let third = std::fs::File::open(file.path()).unwrap();
        assert!(fs4::FileExt::try_lock(&third).is_err());
        fs4::FileExt::unlock(&contender).unwrap();
        fs4::FileExt::try_lock(&third).unwrap();
    }
}

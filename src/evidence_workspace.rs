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
use std::{io::Read, path::Path, sync::Mutex};
type Result<T> = std::result::Result<T, Failure>;
const MAX: usize = 12 * 1024 * 1024;
const SCHEMA: &str = "PRAGMA application_id=1264014129; PRAGMA user_version=1;
CREATE TABLE entries(kind TEXT NOT NULL, id TEXT NOT NULL, body BLOB NOT NULL, PRIMARY KEY(kind,id));";
const DOMAIN: &[u8] = b"tools.kan.reader.workspace.v1\0";
pub struct Workspace {
    conn: Mutex<Connection>,
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
    if m.file_type().is_symlink()
        || (directory && !m.is_dir())
        || (!directory && (!m.is_file() || m.len() > 256 * 1024 * 1024))
    {
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
        for suffix in ["-journal", "-wal", "-shm"] {
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
        );
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
            || conn
                .query_row("PRAGMA user_version", [], |r| r.get::<_, u32>(0))
                .map_err(invalid)?
                != 1
        {
            return Err(Failure::Corrupt);
        }
        conn.execute_batch(
            "PRAGMA synchronous=FULL; PRAGMA fullfsync=ON; PRAGMA max_page_count=65536;",
        )
        .map_err(invalid)?;
        let scope = Sha256::digest(
            [
                DOMAIN,
                signer.did().as_str().as_bytes(),
                &crypto::public_key(&private_key).map_err(invalid)?,
            ]
            .concat(),
        )
        .into();
        let workspace = Self {
            conn: Mutex::new(conn),
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
        let declaration = self.get("annotation", id)?.ok_or(Failure::AccessLimited)?;
        let bytes = serde_json::to_vec(
            &serde_json::json!({"format":"kan-annotation/1","declaration":declaration}),
        )
        .map_err(invalid)?;
        match crate::evidence_delivery::queue(spool, &self.signer, recipient, operation, &bytes) {
            Ok(_) | Err(crate::evidence_delivery::Error::ReusedOperation) => Ok(()),
            Err(_) => Err(Failure::Unavailable),
        }
    }
    /// A single analysis scheduler owns this workspace at a time. The advisory
    /// lifetime lock does not modify the database or replace SQLite transactions.
    pub(crate) fn analysis_lease(&self) -> Result<std::fs::File> {
        private(&self.path, false)?;
        let file = std::fs::File::open(&self.path).map_err(invalid)?;
        fs4::FileExt::try_lock(&file).map_err(|_| Failure::Unavailable)?;
        Ok(file)
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
        let bytes: Option<Vec<u8>> = conn
            .query_row(
                "SELECT body FROM entries WHERE kind=? AND id=?",
                params![kind, id],
                |r| r.get(0),
            )
            .optional()
            .map_err(invalid)?;
        bytes.map(|b| self.unseal(kind, &id, &b)).transpose()
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
            if kind == "view"
                && tx
                    .query_row("SELECT count(*) FROM entries WHERE kind='view'", [], |r| {
                        r.get::<_, i64>(0)
                    })
                    .map_err(invalid)?
                    >= 200
            {
                return Err(Failure::Invalid);
            }
            if kind == "annotation"
                && tx
                    .query_row(
                        "SELECT count(*) FROM entries WHERE kind='annotation'",
                        [],
                        |r| r.get::<_, i64>(0),
                    )
                    .map_err(invalid)?
                    >= 1000
            {
                return Err(Failure::Invalid);
            }
            tx.execute(
                "INSERT INTO entries VALUES(?,?,?)",
                params![kind, id, bytes],
            )
            .map_err(invalid)?;
        }
        tx.commit().map_err(invalid)
    }
    /// Bounded view declarations only; cache pages are addressed explicitly.
    pub fn views(&self) -> Result<Vec<Value>> {
        self.declarations("view", 200)
    }
    pub fn annotations(&self) -> Result<Vec<Value>> {
        self.declarations("annotation", 1000)
    }
    pub(crate) fn owner_jobs(&self) -> Result<Vec<Value>> {
        self.declarations("owner-job", 1000)
    }
    pub(crate) fn analysis_jobs(&self) -> Result<Vec<Value>> {
        self.declarations("analysis-job", 1000)
    }
    fn declarations(&self, kind: &str, limit: usize) -> Result<Vec<Value>> {
        let conn = self.conn.lock().map_err(invalid)?;
        let mut q = conn
            .prepare("SELECT id,body FROM entries WHERE kind=? ORDER BY id LIMIT ?")
            .map_err(invalid)?;
        let rows = q
            .query_map(params![kind, (limit + 1) as i64], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
            })
            .map_err(invalid)?;
        let mut out = Vec::new();
        for row in rows {
            let (id, b) = row.map_err(invalid)?;
            out.push(self.unseal(kind, &id, &b)?);
        }
        if out.len() > limit {
            return Err(Failure::Invalid);
        }
        Ok(out)
    }
}

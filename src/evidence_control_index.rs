//! Owner-signed checkpoints for bounded reads of independently retained control
//! histories. Callers hold their history lease throughout every operation.
//! CURRENT is retained separately from the disposable SQLite node store, so an
//! old database alone cannot roll current policy/custody back. Restoring the
//! entire independent control directory still requires external freshness.
use crate::{
    evidence_index::{self as index, Blocks, Map},
    evidence_proof_service::Binding,
    evidence_service::{self as service, Failure},
    sign::{self, Identity},
};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{io::Read, path::Path};
type Result<T> = std::result::Result<T, Failure>;
const DOMAIN: &[u8] = b"tools.kan.control-checkpoint.v1\0";
const DB: &str = "serving.sqlite";
const CURRENT: &str = "CURRENT";
const DIRTY: &str = "INDEX-DIRTY";
const MAX_HEAD: usize = 8192;
fn invalid<E>(_: E) -> Failure {
    Failure::Corrupt
}
fn json(value: &impl Serialize) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(invalid)
}
fn fixed(value: &str) -> Result<[u8; 32]> {
    service::unhex(value, 32)?
        .try_into()
        .map_err(|_| Failure::Invalid)
}
fn private(path: &Path, limit: u64) -> Result<()> {
    let m = std::fs::symlink_metadata(path).map_err(|_| Failure::Unavailable)?;
    if !m.is_file() || m.file_type().is_symlink() || m.len() > limit {
        return Err(Failure::Invalid);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if m.permissions().mode() & 0o077 != 0 || m.nlink() != 1 {
            return Err(Failure::Invalid);
        }
    }
    Ok(())
}
fn read(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    private(path, maximum as u64)?;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(invalid)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(invalid)?;
    if bytes.len() > maximum {
        return Err(Failure::Unavailable);
    }
    Ok(bytes)
}
fn sync(directory: &Path) -> Result<()> {
    std::fs::File::open(directory)
        .map_err(invalid)?
        .sync_all()
        .map_err(invalid)
}
fn present(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(Failure::Unavailable),
    }
}
pub(crate) fn enabled(directory: &Path) -> Result<bool> {
    Ok(present(&directory.join(DB))?
        || present(&directory.join(CURRENT))?
        || present(&directory.join(DIRTY))?)
}
pub(crate) fn reserved(name: &str) -> bool {
    matches!(name, DB | CURRENT | DIRTY | "serving.sqlite-journal")
        || name.starts_with(".index-head-")
        || name.starts_with(".index-db-")
}
/// Durable refusal barrier, installed before changing any authoritative history.
pub(crate) fn invalidate(directory: &Path) -> Result<()> {
    let path = directory.join(DIRTY);
    if present(&path)? {
        private(&path, 0)?;
    } else {
        // surface-write: evidence-control-index:INDEX-DIRTY
        crate::persistence::write_new_owner_only(
            crate::persistence::SurfaceWrite::EvidenceControlIndex,
            &path,
            &[],
        )
        .map_err(invalid)?;
        sync(directory)?;
    }
    Ok(())
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Statement {
    version: u8,
    kind: String,
    binding: Binding,
    owner: String,
    count: u64,
    tip: String,
    root: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    statement: Statement,
    signature: String,
}
pub(crate) struct Head {
    pub count: u64,
    pub tip: String,
    pub record: Vec<u8>,
}
struct SqlBlocks<'a> {
    conn: &'a Connection,
    tx: Option<&'a rusqlite::Transaction<'a>>,
}
impl Blocks for SqlBlocks<'_> {
    fn read(&mut self, id: &index::Digest) -> index::Result<Option<Vec<u8>>> {
        let row: Option<(i64,Vec<u8>)> = self.conn.query_row(
            "SELECT CASE WHEN typeof(body)='blob' THEN length(body) ELSE -1 END,substr(body,1,4133) FROM serving_nodes WHERE id=?",
            [id], |r| Ok((r.get(0)?,r.get(1)?))
        ).optional().map_err(|_| index::Error::Store)?;
        row.map(|(length, bytes)| {
            if length <= 0 || length as usize > index::MAX_NODE || length as usize != bytes.len() {
                return Err(index::Error::Corrupt);
            }
            Ok(bytes)
        })
        .transpose()
    }
    fn write(&mut self, id: index::Digest, bytes: &[u8]) -> index::Result<()> {
        if index::node_digest(bytes)? != id {
            return Err(index::Error::Corrupt);
        }
        if let Some(old) = self.read(&id)? {
            return if old == bytes {
                Ok(())
            } else {
                Err(index::Error::Corrupt)
            };
        }
        let tx = self.tx.ok_or(index::Error::Store)?;
        // surface-write: evidence-control-index:serving_nodes
        crate::persistence::insert_serving_node(
            crate::persistence::SurfaceWrite::EvidenceControlIndex,
            tx,
            &id,
            bytes,
        )
        .map_err(|_| index::Error::Store)
    }
}
fn key(id: &str) -> Result<index::Digest> {
    index::key(b"control-record", &fixed(id)?).map_err(invalid)
}
fn connection(path: &Path, writable: bool) -> Result<Connection> {
    private(path, u64::MAX)?;
    let conn = Connection::open_with_flags(
        path,
        if writable {
            OpenFlags::SQLITE_OPEN_READ_WRITE
        } else {
            OpenFlags::SQLITE_OPEN_READ_ONLY
        },
    )
    .map_err(invalid)?;
    conn.busy_timeout(std::time::Duration::from_secs(2))
        .map_err(invalid)?;
    conn.set_limit(rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH, 65536)
        .map_err(invalid)?;
    Ok(conn)
}
fn schema(conn: &Connection) -> Result<()> {
    let expected = Connection::open_in_memory().map_err(invalid)?;
    expected
        .execute_batch(crate::evidence_store::serving::SCHEMA)
        .map_err(invalid)?;
    let query = "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name";
    let mut actual = conn.prepare(query).map_err(invalid)?;
    let mut wanted = expected.prepare(query).map_err(invalid)?;
    let mut a = actual.query([]).map_err(invalid)?;
    let mut e = wanted.query([]).map_err(invalid)?;
    loop {
        match (a.next().map_err(invalid)?, e.next().map_err(invalid)?) {
            (None, None) => return Ok(()),
            (Some(a), Some(e)) => {
                for i in 0..4 {
                    if a.get_ref(i).map_err(invalid)? != e.get_ref(i).map_err(invalid)? {
                        return Err(Failure::Corrupt);
                    }
                }
            }
            _ => return Err(Failure::Corrupt),
        }
    }
}
/// Explicit maintenance: caller supplies fully verified history under its owner
/// lease. Failed publication leaves the durable barrier for explicit repair.
pub(crate) fn rebuild(
    directory: &Path,
    kind: &str,
    binding: &Binding,
    signer: &Identity,
    records: impl IntoIterator<Item = Result<String>>,
) -> Result<()> {
    invalidate(directory)?;
    let path = directory.join(format!(
        ".index-db-{}",
        service::hex(&rand::random::<[u8; 32]>())
    ));
    // surface-write: evidence-control-index:.index-db-*
    crate::persistence::write_new_owner_only(
        crate::persistence::SurfaceWrite::EvidenceControlIndex,
        &path,
        &[],
    )
    .map_err(invalid)?;
    let mut conn = connection(&path, true)?;
    conn.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;")
        .map_err(invalid)?;
    let tx = conn.transaction().map_err(invalid)?;
    // surface-write: evidence-control-index:serving_nodes,evidence-control-index:serving_checkpoint
    crate::persistence::initialize_serving_index(
        crate::persistence::SurfaceWrite::EvidenceControlIndex,
        &tx,
    )
    .map_err(invalid)?;
    let mut map = Map::new(
        SqlBlocks {
            conn: &tx,
            tx: Some(&tx),
        },
        None,
    );
    let mut count = 0u64;
    let mut tip = None;
    for id in records {
        let id = id?;
        map.insert(key(&id)?, &count.to_be_bytes())
            .map_err(invalid)?;
        count = count.checked_add(1).ok_or(Failure::Invalid)?;
        tip = Some(id);
    }
    let statement = Statement {
        version: 1,
        kind: kind.into(),
        binding: binding.clone(),
        owner: signer.did().to_string(),
        count,
        tip: tip.ok_or(Failure::AccessLimited)?,
        root: service::hex(&map.root().ok_or(Failure::Corrupt)?),
    };
    let signature = service::hex(
        &signer
            .sign(&[DOMAIN, &json(&statement)?].concat())
            .map_err(invalid)?,
    );
    let bytes = json(&Checkpoint {
        statement,
        signature,
    })?;
    // surface-write: evidence-control-index:serving_checkpoint
    crate::persistence::publish_serving_checkpoint(
        crate::persistence::SurfaceWrite::EvidenceControlIndex,
        &tx,
        &bytes,
    )
    .map_err(invalid)?;
    tx.commit().map_err(invalid)?;
    drop(conn);
    // surface-write: evidence-control-index:.index-db-*,evidence-control-index:serving.sqlite
    crate::persistence::rename(
        crate::persistence::SurfaceWrite::EvidenceControlIndex,
        &path,
        &directory.join(DB),
    )
    .map_err(invalid)?;
    let journal = directory.join("serving.sqlite-journal");
    if present(&journal)? {
        // surface-write: evidence-control-index:serving.sqlite-journal
        crate::persistence::remove_file(
            crate::persistence::SurfaceWrite::EvidenceControlIndex,
            &journal,
        )
        .map_err(invalid)?;
    }
    sync(directory)?;
    let temporary = directory.join(format!(
        ".index-head-{}",
        service::hex(&rand::random::<[u8; 32]>())
    ));
    // surface-write: evidence-control-index:.index-head-*
    crate::persistence::write_new_owner_only(
        crate::persistence::SurfaceWrite::EvidenceControlIndex,
        &temporary,
        &bytes,
    )
    .map_err(invalid)?;
    // surface-write: evidence-control-index:.index-head-*,evidence-control-index:CURRENT
    crate::persistence::rename(
        crate::persistence::SurfaceWrite::EvidenceControlIndex,
        &temporary,
        &directory.join(CURRENT),
    )
    .map_err(invalid)?;
    sync(directory)?;
    // surface-write: evidence-control-index:INDEX-DIRTY
    crate::persistence::remove_file(
        crate::persistence::SurfaceWrite::EvidenceControlIndex,
        &directory.join(DIRTY),
    )
    .map_err(invalid)?;
    sync(directory)
}
/// Selected latest record and minimum membership only; no whole-history audit.
pub(crate) fn current(
    directory: &Path,
    kind: &str,
    binding: &Binding,
    owner: &str,
    minimum: Option<&str>,
    maximum: usize,
) -> Result<Head> {
    if present(&directory.join(DIRTY))? {
        return Err(Failure::Unavailable);
    }
    let bytes = read(&directory.join(CURRENT), MAX_HEAD)?;
    let checkpoint: Checkpoint = serde_json::from_slice(&bytes).map_err(invalid)?;
    if json(&checkpoint)? != bytes {
        return Err(Failure::Corrupt);
    }
    let s = &checkpoint.statement;
    if s.version != 1 || s.kind != kind || s.binding != *binding || s.owner != owner || s.count == 0
    {
        return Err(Failure::Corrupt);
    }
    if !sign::verify(
        owner,
        &[DOMAIN, &json(s)?].concat(),
        &service::unhex(&checkpoint.signature, 64)?,
    ) {
        return Err(Failure::Corrupt);
    }
    let root = fixed(&s.root)?;
    fixed(&s.tip)?;
    let conn = connection(&directory.join(DB), false)?;
    conn.execute_batch("PRAGMA query_only=ON; BEGIN;")
        .map_err(invalid)?;
    schema(&conn)?;
    let stored: Vec<u8> = conn
        .query_row(
            "SELECT substr(body,1,8192) FROM serving_checkpoint WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .map_err(invalid)?;
    if stored != bytes {
        return Err(Failure::AccessLimited);
    }
    let mut map = Map::new(
        SqlBlocks {
            conn: &conn,
            tx: None,
        },
        Some(root),
    );
    if map.get(&key(&s.tip)?).map_err(invalid)?.as_deref()
        != Some((s.count - 1).to_be_bytes().as_slice())
    {
        return Err(Failure::Corrupt);
    }
    if let Some(minimum) = minimum {
        let value = map
            .get(&key(minimum)?)
            .map_err(invalid)?
            .ok_or(Failure::AccessLimited)?;
        let sequence = u64::from_be_bytes(value.try_into().map_err(invalid)?);
        if sequence >= s.count {
            return Err(Failure::Corrupt);
        }
    }
    let record = read(
        &directory.join(format!("{kind}-{:020}-{}.json", s.count - 1, s.tip)),
        maximum,
    )?;
    if service::hex(&Sha256::digest(&record)) != s.tip {
        return Err(Failure::Corrupt);
    }
    Ok(Head {
        count: s.count,
        tip: s.tip.clone(),
        record,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{evidence_erasure_history as custody, evidence_policy as policy};
    fn identity(n: u8) -> Identity {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&[n; 32]).unwrap();
        Identity::load_existing(f.path()).unwrap()
    }
    // Synthetic private fixture setup, never a service mutation path.
    fn directory(path: &Path) {
        // surface-write: container:workspace
        crate::persistence::create_dir_owner_only(
            crate::persistence::SurfaceWrite::Container,
            path,
        )
        .unwrap();
    }
    // Deliberate fixture replacement exercises rollback/corruption refusal.
    // Existing files retain their private permissions; new policy fixtures are
    // created owner-only through the same persistence facade as service writes.
    fn file(path: &Path, bytes: &[u8]) {
        let name = path.file_name().unwrap().to_str().unwrap();
        if name.starts_with("policy-") && name.ends_with(".json") {
            if path.exists() {
                // surface-write: evidence-policy:policy-*.json
                crate::persistence::write(
                    crate::persistence::SurfaceWrite::EvidencePolicy,
                    path,
                    bytes,
                )
                .unwrap();
            } else {
                // surface-write: evidence-policy:policy-*.json
                crate::persistence::write_new_owner_only(
                    crate::persistence::SurfaceWrite::EvidencePolicy,
                    path,
                    bytes,
                )
                .unwrap();
            }
        } else {
            assert!(matches!(name, DB | CURRENT));
            assert!(path.is_file());
            // surface-write: evidence-control-index:serving.sqlite,evidence-control-index:CURRENT
            crate::persistence::write(
                crate::persistence::SurfaceWrite::EvidenceControlIndex,
                path,
                bytes,
            )
            .unwrap();
        }
    }
    fn binding() -> Binding {
        Binding {
            profile: crate::evidence_proof_service::Profile::Admitted,
            archive: service::hex(&[1; 32]),
            scope: service::hex(&[2; 32]),
            issuer: identity(8).did().to_string(),
        }
    }
    fn grant() -> service::Grant {
        service::Grant {
            principal: identity(6).did().to_string(),
            append: true,
            inventory: true,
        }
    }
    fn fixture(root: &Path) -> policy::Access {
        let directory = root.join("policy");
        self::directory(&directory);
        let mut access = policy::Access {
            directory,
            binding: binding(),
            owner: identity(9).did().to_string(),
            minimum: None,
        };
        access.initialize().unwrap();
        let change = access
            .preview(vec![grant()], service::hex(&[1; 32]))
            .unwrap();
        let record = policy::Record::sign(change, &identity(9)).unwrap();
        access.append(record.clone()).unwrap();
        access.minimum = Some(record.id().unwrap());
        access
    }
    #[test]
    fn policy_checkpoint_fences_database_rollback_interruption_and_revocation() {
        let temp = tempfile::tempdir().unwrap();
        let access = fixture(temp.path());
        access.rebuild_serving_index(&identity(9)).unwrap();
        assert!(access.current().unwrap().grants().unwrap()[0].append);
        let old_db = std::fs::read(access.directory.join(DB)).unwrap();
        let old_head = std::fs::read(access.directory.join(CURRENT)).unwrap();
        let change = access.preview(Vec::new(), service::hex(&[2; 32])).unwrap();
        let record = policy::Record::sign(change, &identity(9)).unwrap();
        assert!(
            access.append(record.clone()).is_err(),
            "legacy mutation cannot leave a stale serving checkpoint"
        );
        assert!(access
            .append_with_checkpoint(record.clone(), &identity(8))
            .is_err());
        access
            .append_with_checkpoint(record.clone(), &identity(9))
            .unwrap();
        assert!(access.current().unwrap().grants().unwrap().is_empty());
        let current_head = std::fs::read(access.directory.join(CURRENT)).unwrap();
        file(&access.directory.join(DB), &old_db);
        assert!(
            access.current().is_err(),
            "an old database alone cannot restore revoked grants"
        );
        access.rebuild_serving_index(&identity(9)).unwrap();
        assert!(access.current().unwrap().grants().unwrap().is_empty());
        file(&access.directory.join(CURRENT), &old_head);
        assert!(
            access.current().is_err(),
            "an old pointer alone cannot select a different database checkpoint"
        );
        file(&access.directory.join(CURRENT), &current_head);
        // Same canonical statement can be signed afresh, so rebuild restores both
        // copies rather than relying on byte equality of different signatures.
        access.rebuild_serving_index(&identity(9)).unwrap();
        invalidate(&access.directory).unwrap();
        assert!(access.current().is_err());
        access.append_with_checkpoint(record, &identity(9)).unwrap();
        assert!(access.current().unwrap().grants().unwrap().is_empty());
        file(&access.directory.join(DB), b"broken disposable database");
        assert!(access.current().is_err());
        access.rebuild_serving_index(&identity(9)).unwrap();
        assert!(access.current().unwrap().grants().unwrap().is_empty());
    }
    #[test]
    fn bounded_policy_reads_use_signed_minimum_membership_not_a_lifetime_scan() {
        let temp = tempfile::tempdir().unwrap();
        let access = fixture(temp.path());
        let genesis = access.read().unwrap().history[0].clone();
        let mut previous = genesis.id().unwrap();
        // Construct a valid retained history directly to avoid O(n²) fixture
        // preparation through an intentionally full-audit maintenance API.
        for n in 1..=1025 {
            let record = policy::Record::sign(
                policy::Change {
                    version: 1,
                    binding: access.binding.clone(),
                    owner: access.owner.clone(),
                    sequence: n.to_string(),
                    previous: Some(previous),
                    nonce: service::hex(&[3; 32]),
                    recorded_at: "100".into(),
                    grants: vec![grant()],
                },
                &identity(9),
            )
            .unwrap();
            previous = record.id().unwrap();
            file(
                &access
                    .directory
                    .join(format!("policy-{n:020}-{previous}.json")),
                &json(&record).unwrap(),
            );
        }
        access.rebuild_serving_index(&identity(9)).unwrap();
        assert_eq!(access.read().unwrap().history.len(), 1026);
        let change = access.preview(Vec::new(), service::hex(&[4; 32])).unwrap();
        access
            .append_with_checkpoint(
                policy::Record::sign(change, &identity(9)).unwrap(),
                &identity(9),
            )
            .unwrap();
        assert!(access.current().unwrap().grants().unwrap().is_empty());
        let mut wrong_minimum = access.clone();
        wrong_minimum.minimum = Some(service::hex(&[99; 32]));
        assert!(wrong_minimum.current().is_err());
        let path =
            access
                .directory
                .join(format!("policy-{:020}-{}.json", 0, genesis.id().unwrap()));
        file(&path, b"damaged unselected historical record");
        assert!(access.read().is_err());
        assert!(access.current().unwrap().grants().unwrap().is_empty());
        assert!(access.rebuild_serving_index(&identity(9)).is_err());
        file(&path, &json(&genesis).unwrap());
        access.rebuild_serving_index(&identity(9)).unwrap();
        let head: Checkpoint =
            serde_json::from_slice(&std::fs::read(access.directory.join(CURRENT)).unwrap())
                .unwrap();
        let latest = access.directory.join(format!(
            "policy-{:020}-{}.json",
            head.statement.count - 1,
            head.statement.tip
        ));
        file(&latest, b"damaged selected record");
        assert!(access.current().is_err());
    }
    #[test]
    fn indexed_proof_service_observes_current_revocation_without_historical_scan() {
        use crate::{
            evidence_proof_service as wire,
            evidence_store::{attested, inventory},
        };
        let temp = tempfile::tempdir().unwrap();
        let access = fixture(temp.path());
        access.rebuild_serving_index(&identity(9)).unwrap();
        let root = temp.path().join("archive");
        attested::Archive::create(&root, access.binding.owner_binding().unwrap())
            .unwrap()
            .rebuild_serving_index(&identity(8))
            .unwrap();
        let reader = wire::Service::new_indexed(
            root.join("archive.sqlite"),
            access.binding.clone(),
            identity(8),
            Vec::new(),
            inventory::Budget {
                items: 1,
                metadata_bytes: 65536,
                duration: std::time::Duration::from_secs(10),
                cancelled: Default::default(),
            },
            None,
        )
        .unwrap()
        .with_policy(access.clone())
        .unwrap();
        let request = wire::SignedRequest::sign(
            wire::Request {
                version: 2,
                binding: access.binding.clone(),
                principal: identity(6).did().to_string(),
                expires: 1600,
                command: wire::Command::Snapshot,
            },
            &identity(6),
        )
        .unwrap()
        .bytes()
        .unwrap();
        assert!(reader
            .dispatch(&request, 1500)
            .unwrap()
            .reply
            .result
            .is_ok());
        let record = policy::Record::sign(
            access.preview(Vec::new(), service::hex(&[7; 32])).unwrap(),
            &identity(9),
        )
        .unwrap();
        access.append_with_checkpoint(record, &identity(9)).unwrap();
        let path = access.directory.join(format!(
            "policy-{:020}-{}.json",
            0,
            access.minimum.as_ref().unwrap()
        ));
        file(&path, b"unselected history damage");
        assert!(access.read().is_err());
        assert_eq!(
            reader
                .dispatch(&request, 1500)
                .unwrap()
                .reply
                .result
                .unwrap_err(),
            Failure::AccessLimited
        );
    }
    #[test]
    fn initialized_control_schema_matches_the_surface_catalog() {
        use std::collections::BTreeSet;
        let temp = tempfile::tempdir().unwrap();
        let access = fixture(temp.path());
        access.rebuild_serving_index(&identity(9)).unwrap();
        let conn = connection(&access.directory.join(DB), false).unwrap();
        let mut actual = BTreeSet::new();
        for table in ["serving_nodes", "serving_checkpoint"] {
            let mut q = conn
                .prepare(&format!("PRAGMA table_info({table})"))
                .unwrap();
            for name in q.query_map([], |row| row.get::<_, String>(1)).unwrap() {
                actual.insert((format!("evidence-control-index:{table}"), name.unwrap()));
            }
        }
        let expected = include_str!("../tests/fixtures/read-write-surface.tsv")
            .lines()
            .filter_map(|line| {
                let c: Vec<_> = line.split('\t').collect();
                (c.len() > 5
                    && matches!(
                        c[4],
                        "evidence-control-index:serving_nodes"
                            | "evidence-control-index:serving_checkpoint"
                    ))
                .then(|| (c[4].to_owned(), c[5].to_owned()))
            })
            .collect();
        assert_eq!(actual, expected);
    }
    #[test]
    fn custody_checkpoint_binds_latest_native_erasure_and_preserves_owner_history() {
        use crate::evidence_store::{attested, erasure};
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("custody");
        directory(&path);
        let mut history = custody::Access {
            directory: path,
            binding: binding(),
            owner: identity(9).did().to_string(),
            minimum: None,
        };
        history.initialize().unwrap();
        let genesis = custody::Record::sign(
            history.preview(None, service::hex(&[1; 32])).unwrap(),
            &identity(9),
        )
        .unwrap();
        history.append(genesis.clone()).unwrap();
        history.minimum = Some(genesis.id().unwrap());
        history.rebuild_serving_index(&identity(9)).unwrap();
        assert!(history
            .current_head()
            .unwrap()
            .storage_tip()
            .unwrap()
            .is_none());
        let old_db = std::fs::read(history.directory.join(DB)).unwrap();
        let mut archive = attested::Archive::create(
            &temp.path().join("archive"),
            history.binding.owner_binding().unwrap(),
        )
        .unwrap();
        let request = service::SignedRequest::sign(
            service::Request {
                version: 1,
                scope: history.binding.scope.clone(),
                principal: identity(6).did().to_string(),
                audience: history.binding.issuer.clone(),
                expires: None,
                command: service::Command::Append {
                    id: service::hex(&[1; 16]),
                    position: 0,
                    previous: None,
                    ciphertext: service::hex(b"synthetic ciphertext"),
                },
            },
            &identity(6),
        )
        .unwrap()
        .bytes()
        .unwrap();
        archive
            .admit(&request, &identity(8), &grant(), 100)
            .unwrap();
        let erasure = erasure::Record::sign(
            archive
                .preview_erasure(&[1], service::hex(&[2; 32]), 101)
                .unwrap(),
            &identity(8),
        )
        .unwrap();
        let record = custody::Record::sign(
            history
                .preview(Some(erasure.clone()), service::hex(&[3; 32]))
                .unwrap(),
            &identity(9),
        )
        .unwrap();
        history
            .append_with_checkpoint(record, &identity(9))
            .unwrap();
        assert_eq!(
            history.current_head().unwrap().storage_tip().unwrap(),
            Some(erasure.id().unwrap())
        );
        assert_eq!(history.current().unwrap().history.len(), 2);
        file(&history.directory.join(DB), &old_db);
        assert!(history.current_head().is_err());
        history.rebuild_serving_index(&identity(9)).unwrap();
        assert_eq!(
            history.current_head().unwrap().storage_tip().unwrap(),
            history.current().unwrap().storage_tip().unwrap()
        );
        invalidate(&history.directory).unwrap();
        assert!(history.current_head().is_err());
        history.rebuild_serving_index(&identity(9)).unwrap();
        assert_eq!(
            history.current_head().unwrap().storage_tip().unwrap(),
            Some(erasure.id().unwrap())
        );
    }
}

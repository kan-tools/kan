//! Authenticated metadata index. Explicit initialization audits the archive;
//! point reads authenticate selected metadata, never certify unselected payloads.
//! The caller must supply its independently accepted frontier and current custody.
use super::*;
use crate::{
    evidence_attestation::{self as proof, Frontier, Verified},
    evidence_index::{self as index, Blocks, Map},
    evidence_proof_service::{Binding as WireBinding, Coordinate, Profile},
    evidence_service as service,
    sign::{self, Identity},
};
use serde::{Deserialize, Serialize};

pub(crate) const SCHEMA: &str = "CREATE TABLE serving_nodes(id BLOB NOT NULL PRIMARY KEY CHECK(length(id)=32),body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=4133));
CREATE TABLE serving_checkpoint(singleton INTEGER PRIMARY KEY CHECK(singleton=1),body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=8192));";
const DOMAIN: &[u8] = b"tools.kan.serving-checkpoint.v1\0";
const MAX_CHECKPOINT: usize = 8192;
fn corrupt() -> Error {
    Error::Corrupt("serving index or checkpoint".into())
}
fn index_error(_: index::Error) -> Error {
    corrupt()
}
fn json(value: &impl Serialize) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| corrupt())
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Statement {
    version: u8,
    binding: WireBinding,
    frontier: Coordinate,
    root: Option<String>,
    erasure_tip: Option<String>,
    erasure_through: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    statement: Statement,
    signature: String,
}
impl Checkpoint {
    pub fn frontier(&self) -> &Coordinate {
        &self.statement.frontier
    }
    pub fn erasure_tip(&self) -> Option<&str> {
        self.statement.erasure_tip.as_deref()
    }
    pub fn bytes(&self) -> Result<Vec<u8>> {
        json(self)
    }
    fn root(&self) -> Result<Option<index::Digest>> {
        self.statement
            .root
            .as_ref()
            .map(|s| {
                service::unhex(s, 32)
                    .map_err(|_| corrupt())?
                    .try_into()
                    .map_err(|_| corrupt())
            })
            .transpose()
    }
    pub(super) fn validate(&self, binding: &attested::Binding) -> Result<Frontier> {
        binding.validate()?;
        if self.statement.version != 1
            || self.statement.binding != wire(binding)
            || self.statement.erasure_through > evidence::MAX_SAFE_INTEGER as u64
            || (self.statement.erasure_through == 0) != self.statement.erasure_tip.is_none()
        {
            return Err(corrupt());
        }
        let frontier = self
            .statement
            .frontier
            .frontier(&self.statement.binding)
            .map_err(|_| corrupt())?;
        if (frontier.through == 0) != self.root()?.is_none() {
            return Err(corrupt());
        }
        if let Some(tip) = &self.statement.erasure_tip {
            if service::unhex(tip, 32).map_err(|_| corrupt())?.len() != 32 {
                return Err(corrupt());
            }
        }
        let signature = service::unhex(&self.signature, 64).map_err(|_| corrupt())?;
        if !sign::verify(
            &binding.issuer,
            &[DOMAIN, &json(&self.statement)?].concat(),
            &signature,
        ) {
            return Err(corrupt());
        }
        Ok(frontier)
    }
}
fn wire(binding: &attested::Binding) -> WireBinding {
    WireBinding {
        profile: Profile::Admitted,
        archive: service::hex(&binding.archive),
        scope: service::hex(&binding.scope),
        issuer: binding.issuer.clone(),
    }
}
pub(super) fn exists(conn: &Connection) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='serving_checkpoint')",
        [],
        |r| r.get(0),
    )?)
}
pub(super) fn extend_schema(source: &Connection, expected: &Connection) -> Result<()> {
    if exists(source)? {
        expected.execute_batch(SCHEMA)?;
    }
    Ok(())
}
fn load(conn: &Connection, binding: &attested::Binding) -> Result<Checkpoint> {
    if !exists(conn)? {
        return Err(Error::Invalid(
            "serving index requires explicit initialization",
        ));
    }
    let row: Option<(i64, Vec<u8>)> = conn
        .query_row(
            "SELECT CASE WHEN typeof(body)='blob' THEN length(body) ELSE -1 END,substr(body,1,8192) FROM serving_checkpoint WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (len, bytes) = row.ok_or_else(corrupt)?;
    if len <= 0 || len as usize > MAX_CHECKPOINT || bytes.len() as i64 != len {
        return Err(corrupt());
    }
    let checkpoint: Checkpoint = serde_json::from_slice(&bytes).map_err(|_| corrupt())?;
    if checkpoint.bytes()? != bytes {
        return Err(corrupt());
    }
    checkpoint.validate(binding)?;
    Ok(checkpoint)
}
struct SqlBlocks<'a> {
    conn: &'a Connection,
    tx: Option<&'a rusqlite::Transaction<'a>>,
}
impl Blocks for SqlBlocks<'_> {
    fn read(&mut self, id: &index::Digest) -> index::Result<Option<Vec<u8>>> {
        let row: Option<(i64, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT CASE WHEN typeof(body)='blob' THEN length(body) ELSE -1 END,substr(body,1,4133) FROM serving_nodes WHERE id=?",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| index::Error::Store)?;
        row.map(|(len, bytes)| {
            if len <= 0 || len as usize > index::MAX_NODE || len as usize != bytes.len() {
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
        // surface-write: evidence-serving-sqlite:serving_nodes
        crate::persistence::insert_serving_node(
            crate::persistence::SurfaceWrite::EvidenceServingIndex,
            tx,
            &id,
            bytes,
        )
        .map_err(|_| index::Error::Store)?;
        Ok(())
    }
}
fn record_key(sequence: u64) -> Result<index::Digest> {
    index::key(b"record", &sequence.to_be_bytes()).map_err(index_error)
}
fn commitment(record: &Committed, envelope: &[u8]) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(b"tools.kan.serving-record.v1\0");
    hash.update(record.sequence.to_be_bytes());
    for bytes in [record.manifest.bytes(), record.receipt.bytes(), envelope] {
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    hash.finalize().to_vec()
}
fn insert_record(map: &mut Map<SqlBlocks<'_>>, row: &Committed, envelope: &[u8]) -> Result<()> {
    map.insert(record_key(row.sequence)?, &commitment(row, envelope))
        .map_err(index_error)?;
    let b = row.manifest.body();
    let writer = writer(&row.manifest);
    let mut operation = writer.as_bytes().to_vec();
    operation.push(0);
    operation.extend(blob(&b["operation"]));
    map.insert(
        index::key(b"operation", &operation).map_err(index_error)?,
        &row.sequence.to_be_bytes(),
    )
    .map_err(index_error)?;
    let mut head = row.sequence.to_be_bytes().to_vec();
    head.extend(number(&b["position"]).to_be_bytes());
    head.extend(row.manifest.cid().to_string().as_bytes());
    map.insert(
        index::key(b"writer", writer.as_bytes()).map_err(index_error)?,
        &head,
    )
    .map_err(index_error)?;
    for entry in entries(&row.manifest) {
        let mut slot = writer.as_bytes().to_vec();
        slot.push(0);
        slot.extend(blob(&entry["slot"]));
        let mut value = number(&entry["length"]).to_be_bytes().to_vec();
        value.extend(cid(&entry["ciphertext"]).as_bytes());
        map.insert(index::key(b"slot", &slot).map_err(index_error)?, &value)
            .map_err(index_error)?;
    }
    Ok(())
}
fn publish(
    tx: &rusqlite::Transaction<'_>,
    binding: &attested::Binding,
    frontier: &Frontier,
    root: Option<index::Digest>,
    history: &erasure::History,
    signer: &Identity,
) -> Result<Checkpoint> {
    if signer.did().as_str() != binding.issuer {
        return Err(Error::Invalid("serving checkpoint signer"));
    }
    let statement = Statement {
        version: 1,
        binding: wire(binding),
        frontier: Coordinate::from_frontier(frontier),
        root: root.map(|v| service::hex(&v)),
        erasure_tip: history.tip.clone(),
        erasure_through: history
            .records
            .iter()
            .map(|r| r.plan.through)
            .max()
            .unwrap_or(0),
    };
    sign_and_publish(tx, binding, statement, signer)
}
fn sign_and_publish(
    tx: &rusqlite::Transaction<'_>,
    binding: &attested::Binding,
    statement: Statement,
    signer: &Identity,
) -> Result<Checkpoint> {
    if signer.did().as_str() != binding.issuer {
        return Err(Error::Invalid("serving checkpoint signer"));
    }
    let signature = signer
        .sign(&[DOMAIN, &json(&statement)?].concat())
        .map_err(|_| corrupt())?;
    let checkpoint = Checkpoint {
        statement,
        signature: service::hex(&signature),
    };
    checkpoint.validate(binding)?;
    // surface-write: evidence-serving-sqlite:serving_checkpoint
    crate::persistence::publish_serving_checkpoint(
        crate::persistence::SurfaceWrite::EvidenceServingIndex,
        tx,
        &checkpoint.bytes()?,
    )?;
    Ok(checkpoint)
}
impl attested::Archive {
    /// Explicit full verification and atomic initialization/rebuild. It does not
    /// change capture bytes, receipt/proof formats, or independently held custody.
    pub fn rebuild_serving_index(&self, signer: &Identity) -> Result<Checkpoint> {
        if self.copy.is_some() {
            return Err(Error::Invalid("copied serving index not initialized"));
        }
        if signer.did().as_str() != self.binding.issuer {
            return Err(Error::Invalid("serving checkpoint signer"));
        }
        let tx = rusqlite::Transaction::new_unchecked(
            &self.ledger.conn,
            TransactionBehavior::Immediate,
        )?;
        self.ledger.check_write_profile(true)?;
        let verified = self.ledger.verify_contents()?;
        let (frontier, _) =
            attested::audit_prefix(&tx, &self.binding, verified.snapshot.through, None, None)?;
        if frontier.manifest != verified.snapshot.tip {
            return Err(corrupt());
        }
        let history = erasure::load(&tx)?;
        if !exists(&tx)? {
            // surface-write: evidence-serving-sqlite:serving_nodes,evidence-serving-sqlite:serving_checkpoint
            crate::persistence::initialize_serving_index(
                crate::persistence::SurfaceWrite::EvidenceServingIndex,
                &tx,
            )?;
        }
        // surface-write: evidence-serving-sqlite:serving_nodes
        crate::persistence::reset_serving_nodes(
            crate::persistence::SurfaceWrite::EvidenceServingIndex,
            &tx,
        )?;
        let mut map = Map::new(
            SqlBlocks {
                conn: &tx,
                tx: Some(&tx),
            },
            None,
        );
        for sequence in 1..=frontier.through {
            let row = attested::record(&tx, sequence)?;
            insert_record(&mut map, &row, &attested::envelope(&tx, sequence)?)?;
        }
        insert_erasures(&mut map, &history)?;
        let checkpoint = publish(&tx, &self.binding, &frontier, map.root(), &history, signer)?;
        tx.commit()?;
        Ok(checkpoint)
    }
}
/// Advance an already initialized map inside the evidence/proof transaction.
/// Existing callers still audit the old archive; bounded admission is separate.
pub(super) fn advance(
    tx: &rusqlite::Transaction<'_>,
    binding: &attested::Binding,
    previous: &Frontier,
    row: &Committed,
    proof: &Verified,
    signer: &Identity,
    indexed: Option<&Checkpoint>,
) -> Result<()> {
    if !exists(tx)? {
        return Ok(());
    }
    let checkpoint = load(tx, binding)?;
    if checkpoint.validate(binding)? != *previous {
        return Err(Error::Conflict("serving checkpoint frontier"));
    }
    let mut map = Map::new(
        SqlBlocks {
            conn: tx,
            tx: Some(tx),
        },
        checkpoint.root()?,
    );
    if row.duplicate {
        if map
            .get(&record_key(row.sequence)?)
            .map_err(index_error)?
            .as_deref()
            != Some(commitment(row, proof.bytes()).as_slice())
        {
            return Err(corrupt());
        }
        return Ok(());
    }
    insert_record(&mut map, row, proof.bytes())?;
    if let Some(indexed) = indexed {
        check_current(tx, binding, indexed)?;
        let mut statement = indexed.statement.clone();
        statement.frontier = Coordinate::from_frontier(proof.frontier());
        statement.root = map.root().map(|v| service::hex(&v));
        sign_and_publish(tx, binding, statement, signer)?;
    } else {
        let history = erasure::load(tx)?;
        insert_erasures(&mut map, &history)?;
        publish(tx, binding, proof.frontier(), map.root(), &history, signer)?;
    }
    Ok(())
}
/// Read selected metadata with bounded work. No assertion about other records,
/// current payload availability, or external custody is made by this result.
pub struct Metadata {
    pub record: Committed,
    pub proof: Verified,
}
pub fn read_metadata(
    path: &Path,
    binding: attested::Binding,
    expected: &Frontier,
    current_erasure_tip: Option<&str>,
    sequence: u64,
) -> Result<Metadata> {
    binding.validate()?;
    if sequence == 0 || sequence > expected.through {
        return Err(Error::Invalid("serving sequence"));
    }
    private_file(path)?;
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    conn.set_limit(
        rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH,
        RECOVERY_SQLITE_LENGTH_LIMIT,
    )?;
    conn.busy_timeout(Duration::from_secs(5))?;
    let ledger = Ledger { conn };
    let tx = ledger.conn.unchecked_transaction()?;
    ledger.check_profile(2)?;
    ledger.check_write_profile(true)?;
    attested::check_binding(&tx, &binding)?;
    let checkpoint = load(&tx, &binding)?;
    check_current(&tx, &binding, &checkpoint)?;
    if checkpoint.validate(&binding)? != *expected
        || checkpoint.erasure_tip() != current_erasure_tip
    {
        return Err(Error::Conflict("serving checkpoint freshness"));
    }
    let selected = selected_metadata(&tx, &binding, &checkpoint, sequence)?;
    tx.commit()?;
    Ok(selected)
}
pub(super) fn selected_metadata(
    conn: &Connection,
    binding: &attested::Binding,
    checkpoint: &Checkpoint,
    sequence: u64,
) -> Result<Metadata> {
    let through: u64 = checkpoint
        .statement
        .frontier
        .through
        .parse()
        .map_err(|_| corrupt())?;
    if sequence == 0 || sequence > through {
        return Err(Error::Invalid("indexed selection outside checkpoint"));
    }
    let mut map = Map::new(SqlBlocks { conn, tx: None }, checkpoint.root()?);
    let row = attested::record(conn, sequence)?;
    let envelope = attested::envelope(conn, sequence)?;
    if map
        .get(&record_key(sequence)?)
        .map_err(index_error)?
        .as_deref()
        != Some(commitment(&row, &envelope).as_slice())
    {
        return Err(corrupt());
    }
    let value = evidence::canonical_value(&envelope, proof::MAX_ENVELOPE_BYTES)?;
    let envelope_fields = evidence::closed(&value, &["statement", "signature"])?;
    let Ipld::Bytes(statement) = &envelope_fields["statement"] else {
        return Err(corrupt());
    };
    let statement = evidence::canonical_value(statement, proof::MAX_ENVELOPE_BYTES)?;
    let statement_cid = crate::cid::content_cid(&statement).map_err(|_| corrupt())?;
    let frontier = Frontier {
        through: sequence,
        manifest: Some(row.manifest.cid().clone()),
        attestation: Some(statement_cid),
        archive: Some(binding.archive),
        scope: Some(binding.scope),
        issuer: Some(binding.issuer.clone()),
    };
    let verified = proof::verify_at(
        &envelope,
        &binding.context(),
        &row.manifest,
        &row.receipt,
        &frontier,
    )?;
    Ok(Metadata {
        record: row,
        proof: verified,
    })
}

fn insert_erasures(map: &mut Map<SqlBlocks<'_>>, history: &erasure::History) -> Result<()> {
    for (id, target) in &history.objects {
        map.insert(
            index::key(b"erased", id.as_bytes()).map_err(index_error)?,
            &json(target)?,
        )
        .map_err(index_error)?;
    }
    Ok(())
}
fn native_erasure_tip(conn: &Connection) -> Result<Option<String>> {
    if !erasure::exists(conn)? {
        return Ok(None);
    }
    let value: Option<(i64, String)> = conn
        .query_row(
            "SELECT length(id),substr(id,1,64) FROM erasures ORDER BY ordinal DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    value
        .map(|(len, id)| {
            if len != 64 || service::unhex(&id, 32).map_err(|_| corrupt())?.len() != 32 {
                return Err(corrupt());
            }
            Ok(id)
        })
        .transpose()
}
pub(super) fn check_current(
    conn: &Connection,
    binding: &attested::Binding,
    checkpoint: &Checkpoint,
) -> Result<()> {
    let current = load(conn, binding)?;
    if current.statement != checkpoint.statement
        || native_erasure_tip(conn)? != checkpoint.statement.erasure_tip
    {
        return Err(Error::Conflict("serving checkpoint or custody changed"));
    }
    if checkpoint.statement.erasure_through > checkpoint.validate(binding)?.through {
        return Err(Error::Conflict("archive is behind erasure custody"));
    }
    Ok(())
}
fn operation_key(manifest: &Record) -> Result<index::Digest> {
    let mut key = writer(manifest).as_bytes().to_vec();
    key.push(0);
    key.extend(blob(&manifest.body()["operation"]));
    index::key(b"operation", &key).map_err(index_error)
}
/// Validate an initialized checkpoint under the caller's independent current
/// custody. Raw database lookup results never establish operation membership.
pub(super) fn admission_checkpoint(
    conn: &Connection,
    binding: &attested::Binding,
    manifest: &Record,
    expected_erasure_tip: Option<&str>,
) -> Result<(Checkpoint, Frontier, Option<Verified>)> {
    let tx = conn.unchecked_transaction()?;
    let checkpoint = load(&tx, binding)?;
    check_current(&tx, binding, &checkpoint)?;
    if checkpoint.erasure_tip() != expected_erasure_tip {
        return Err(Error::Conflict("serving custody differs from owner"));
    }
    let previous = checkpoint.validate(binding)?;
    let mut map = Map::new(
        SqlBlocks {
            conn: &tx,
            tx: None,
        },
        checkpoint.root()?,
    );
    let operation = map.get(&operation_key(manifest)?).map_err(index_error)?;
    let duplicate = if let Some(sequence) = operation {
        let sequence = u64::from_be_bytes(sequence.try_into().map_err(|_| corrupt())?);
        if sequence == 0 || sequence > previous.through {
            return Err(corrupt());
        }
        let selected = selected_metadata(&tx, binding, &checkpoint, sequence)?;
        if selected.record.manifest.cid() != manifest.cid() {
            return Err(Error::Conflict("operation reused for different manifest"));
        }
        Some(selected.proof)
    } else {
        None
    };
    tx.commit()?;
    Ok((checkpoint, previous, duplicate))
}
pub(super) fn stage_allowed(
    conn: &Connection,
    binding: &attested::Binding,
    checkpoint: &Checkpoint,
    id: &Cid,
) -> Result<()> {
    check_current(conn, binding, checkpoint)?;
    let mut map = Map::new(SqlBlocks { conn, tx: None }, checkpoint.root()?);
    if map
        .get(&index::key(b"erased", id.to_string().as_bytes()).map_err(index_error)?)
        .map_err(index_error)?
        .is_some()
    {
        return Err(Error::Erased(id.to_string()));
    }
    Ok(())
}
/// Authenticate every lookup that can allow an admission. Runs under the writer
/// transaction; any disagreement rolls back the tentative row and bindings.
pub(super) fn check_admission(
    conn: &Connection,
    binding: &attested::Binding,
    checkpoint: &Checkpoint,
    row: &Committed,
) -> Result<()> {
    check_current(conn, binding, checkpoint)?;
    let mut map = Map::new(SqlBlocks { conn, tx: None }, checkpoint.root()?);
    let operation = map
        .get(&operation_key(&row.manifest)?)
        .map_err(index_error)?;
    if row.duplicate {
        if operation.as_deref() != Some(row.sequence.to_be_bytes().as_slice()) {
            return Err(corrupt());
        }
        return Ok(());
    }
    if operation.is_some() {
        return Err(Error::Conflict("indexed operation already exists"));
    }
    let body = row.manifest.body();
    let writer = writer(&row.manifest);
    let head = map
        .get(&index::key(b"writer", writer.as_bytes()).map_err(index_error)?)
        .map_err(index_error)?;
    match head {
        Some(head) => {
            if head.len() < 17 {
                return Err(corrupt());
            }
            let sequence = u64::from_be_bytes(head[..8].try_into().map_err(|_| corrupt())?);
            let position = i64::from_be_bytes(head[8..16].try_into().map_err(|_| corrupt())?);
            let previous = std::str::from_utf8(&head[16..]).map_err(|_| corrupt())?;
            if sequence == 0
                || sequence >= row.sequence
                || position.checked_add(1) != Some(number(&body["position"]))
                || optional_cid(&body["previous"]).as_deref() != Some(previous)
            {
                return Err(Error::Conflict("indexed writer frontier"));
            }
        }
        None => {
            if number(&body["position"]) != 0 || optional_cid(&body["previous"]).is_some() {
                return Err(Error::Conflict("indexed writer genesis"));
            }
        }
    }
    for entry in entries(&row.manifest) {
        let mut slot = writer.as_bytes().to_vec();
        slot.push(0);
        slot.extend(blob(&entry["slot"]));
        if let Some(old) = map
            .get(&index::key(b"slot", &slot).map_err(index_error)?)
            .map_err(index_error)?
        {
            let mut expected = number(&entry["length"]).to_be_bytes().to_vec();
            expected.extend(cid(&entry["ciphertext"]).as_bytes());
            if old != expected {
                return Err(Error::Conflict("indexed slot rebound"));
            }
        }
        stage_allowed(
            conn,
            binding,
            checkpoint,
            &cid(&entry["ciphertext"]).parse().map_err(|_| corrupt())?,
        )?;
    }
    Ok(())
}
impl attested::Archive {
    /// Bounded metadata open. It authenticates the selected checkpoint and tip;
    /// use verify() for a full retained-byte/chain audit. External custody must be
    /// supplied again for every indexed admission, not inferred from this file.
    pub fn open_indexed(
        root: &Path,
        binding: attested::Binding,
        expected_erasure_tip: Option<&str>,
    ) -> Result<Self> {
        binding.validate()?;
        let path = root.join("archive.sqlite");
        private_file(&path)?;
        let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        conn.set_limit(
            rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH,
            RECOVERY_SQLITE_LENGTH_LIMIT,
        )?;
        conn.busy_timeout(Duration::from_secs(5))?;
        let archive = Self {
            audit_cache: Default::default(),
            ledger: Ledger { conn },
            binding,
            copy: None,
        };
        archive.indexed_frontier(expected_erasure_tip)?;
        configure(&archive.ledger.conn)?;
        Ok(archive)
    }
    /// Authenticate current indexed metadata without a lifetime audit.
    pub fn indexed_frontier(&self, expected_erasure_tip: Option<&str>) -> Result<Frontier> {
        if self.copy.is_some() {
            return Err(Error::Invalid("indexed admitted profile required"));
        }
        let tx = self.ledger.conn.unchecked_transaction()?;
        self.ledger.check_profile(2)?;
        self.ledger.check_write_profile(true)?;
        attested::check_binding(&tx, &self.binding)?;
        let checkpoint = load(&tx, &self.binding)?;
        check_current(&tx, &self.binding, &checkpoint)?;
        let frontier = checkpoint.validate(&self.binding)?;
        if checkpoint.erasure_tip() != expected_erasure_tip
            || self.ledger.snapshot()?
                != (Snapshot {
                    through: frontier.through,
                    tip: frontier.manifest.clone(),
                })
        {
            return Err(Error::Conflict("serving archive frontier or custody"));
        }
        if frontier.through > 0 {
            selected_metadata(&tx, &self.binding, &checkpoint, frontier.through)?;
        }
        tx.commit()?;
        Ok(frontier)
    }
}

impl attested::Archive {
    /// Owner maintenance after native erasure reconciliation. Refresh only the
    /// erased-object map; source metadata and the archive frontier cannot change.
    /// The caller holds independent custody through this operation. Legacy
    /// archives without an index remain unindexed; no hidden initialization.
    pub fn refresh_serving_custody(
        &self,
        signer: &Identity,
        expected_tip: &str,
    ) -> Result<Option<Checkpoint>> {
        if signer.did().as_str() != self.binding.issuer || self.copy.is_some() {
            return Err(Error::Invalid("serving custody signer/profile"));
        }
        let tx = rusqlite::Transaction::new_unchecked(
            &self.ledger.conn,
            TransactionBehavior::Immediate,
        )?;
        if !exists(&tx)? {
            return Ok(None);
        }
        self.ledger.check_write_profile(true)?;
        attested::check_binding(&tx, &self.binding)?;
        let checkpoint = load(&tx, &self.binding)?;
        let frontier = checkpoint.validate(&self.binding)?;
        if self.ledger.snapshot()?
            != (Snapshot {
                through: frontier.through,
                tip: frontier.manifest.clone(),
            })
        {
            return Err(Error::Conflict("serving custody frontier changed"));
        }
        if frontier.through > 0 {
            selected_metadata(&tx, &self.binding, &checkpoint, frontier.through)?;
        }
        let history = erasure::load(&tx)?;
        if history.tip.as_deref() != Some(expected_tip)
            || checkpoint.erasure_tip().is_some_and(|tip| {
                !history
                    .records
                    .iter()
                    .any(|record| record.id().ok().as_deref() == Some(tip))
            })
        {
            return Err(Error::Conflict("serving custody is not an extension"));
        }
        if history
            .records
            .iter()
            .any(|r| r.plan.through > frontier.through)
        {
            return Err(Error::Conflict("serving custody ahead of archive"));
        }
        if checkpoint.erasure_tip() == Some(expected_tip) {
            return Ok(Some(checkpoint));
        }
        let mut map = Map::new(
            SqlBlocks {
                conn: &tx,
                tx: Some(&tx),
            },
            checkpoint.root()?,
        );
        insert_erasures(&mut map, &history)?;
        let next = publish(&tx, &self.binding, &frontier, map.root(), &history, signer)?;
        tx.commit()?;
        Ok(Some(next))
    }
}

/// Authenticate local serving state against separately supplied current custody.
pub(super) fn checkpoint(
    conn: &Connection,
    binding: &attested::Binding,
    expected_tip: Option<&str>,
) -> Result<Checkpoint> {
    let checkpoint = load(conn, binding)?;
    check_current(conn, binding, &checkpoint)?;
    if checkpoint.erasure_tip() != expected_tip {
        return Err(Error::Conflict("indexed custody differs from owner"));
    }
    let frontier = checkpoint.validate(binding)?;
    let actual: Option<(i64, String)> = conn
        .query_row(
            "SELECT sequence,cid FROM commits ORDER BY sequence DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let wanted = frontier
        .manifest
        .as_ref()
        .map(|cid| (frontier.through as i64, cid.to_string()));
    if actual != wanted {
        return Err(Error::Conflict("indexed archive tip changed"));
    }
    Ok(checkpoint)
}
pub(super) fn erased(conn: &Connection, checkpoint: &Checkpoint, id: &Cid) -> Result<bool> {
    let mut map = Map::new(SqlBlocks { conn, tx: None }, checkpoint.root()?);
    let Some(value) = map
        .get(&index::key(b"erased", id.to_string().as_bytes()).map_err(index_error)?)
        .map_err(index_error)?
    else {
        return Ok(false);
    };
    let target: erasure::Target = serde_json::from_slice(&value).map_err(|_| corrupt())?;
    if target.object != id.to_string()
        || target.sequence == 0
        || target.sequence > checkpoint.statement.erasure_through
    {
        return Err(corrupt());
    }
    Ok(true)
}

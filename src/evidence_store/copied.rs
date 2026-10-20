//! Explicit profile 3: a recipe-bound copy, followed by current-issuer admission.
//! This owner API does not activate a service or fence another physical copy.
use super::copy_upgrade::{frame, PlannedCopy, SOURCE_DOMAIN};
use super::*;
use crate::{
    evidence_attestation::{self as proof, Purpose},
    evidence_copy_plan::Plan,
    evidence_service::{Failure, Grant},
    sign::Identity,
};

pub(crate) const SCHEMA: &str = "
CREATE TABLE upgrade_plan(
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 envelope BLOB NOT NULL CHECK(length(envelope)>0 AND length(envelope)<=4096));
CREATE TABLE upgrade_objects(
 cid TEXT PRIMARY KEY,
 length INTEGER NOT NULL CHECK(length>=1 AND length<=4194304)) WITHOUT ROWID;
PRAGMA user_version=3;
";

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Status {
    pub original_objects: u64,
    pub erased_original_objects: u64,
    pub copied_records: u64,
    pub planned_records: u64,
    pub source_copy_complete: bool,
}
#[derive(Debug)]
pub struct Verification {
    pub contents: super::Verification,
    pub copy: Status,
}
#[derive(Debug, Clone, Copy)]
pub struct Budget {
    pub objects: usize,
    pub records: usize,
    pub bytes: usize,
}
impl Budget {
    pub fn validate(self) -> Result<()> {
        if self.objects > 4096
            || self.records > 4096
            || (self.objects == 0 && self.records == 0)
            || !(MAX_CHUNK..=64 * 1024 * 1024).contains(&self.bytes)
        {
            return Err(Error::Invalid("copy budget"));
        }
        Ok(())
    }
}
#[derive(Debug)]
pub struct Batch {
    pub status: Status,
    pub objects_written: usize,
    pub records_written: usize,
    pub bytes_written: usize,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyBoundary {
    ObjectInserted,
    InventoryInserted,
    ManifestInserted,
    ProofSigned,
    ProofInserted,
    BeforeCommit,
    AfterCommit,
}

fn corrupt(message: &str) -> Error {
    Error::Corrupt(message.into())
}
fn configured(binding: &attested::Binding, plan: &Plan) -> Result<()> {
    binding.validate()?;
    plan.check_archive(&binding.archive)?;
    if plan.target().scope != binding.scope || plan.target().issuer != binding.issuer {
        return Err(Error::Invalid("copy plan differs from owner binding"));
    }
    Ok(())
}
pub(super) fn stored_plan(conn: &Connection, binding: &attested::Binding) -> Result<Plan> {
    let count: i64 = conn.query_row("SELECT count(*) FROM upgrade_plan", [], |r| r.get(0))?;
    let (length, bytes): (i64, Vec<u8>) = conn.query_row(
        "SELECT length(envelope),substr(envelope,1,4096) FROM upgrade_plan WHERE singleton=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if count != 1 || !(1..=4096).contains(&length) || length as usize != bytes.len() {
        return Err(corrupt("copy plan cardinality or length"));
    }
    let plan = Plan::decode(&bytes)?;
    configured(binding, &plan)?;
    attested::check_binding(conn, binding)?;
    Ok(plan)
}
pub(super) fn check_plan(
    conn: &Connection,
    binding: &attested::Binding,
    plan: &Plan,
) -> Result<()> {
    configured(binding, plan)?;
    if stored_plan(conn, binding)?.bytes() != plan.bytes() {
        return Err(corrupt("stored copy plan changed"));
    }
    Ok(())
}
pub(super) fn initialize(
    tx: &rusqlite::Transaction<'_>,
    binding: &attested::Binding,
    plan: &Plan,
) -> Result<()> {
    configured(binding, plan)?;
    // surface-write: evidence-copy-sqlite:upgrade_plan,evidence-copy-sqlite:upgrade_objects
    crate::persistence::initialize_evidence_copy(
        crate::persistence::SurfaceWrite::EvidenceCopy,
        tx,
        plan.bytes(),
    )?;
    Ok(())
}

// Caller owns a pinned transaction and has fully verified payloads/base metadata.
// Partial source-copy status is not proof that a prefix matches an unavailable
// source; resumption additionally compares it against the audited PlannedCopy.
pub(super) fn audit(
    ledger: &Ledger,
    binding: &attested::Binding,
    plan: &Plan,
    base: &super::Verification,
) -> Result<Status> {
    ledger.check_profile(3)?;
    audit_state(
        &ledger.conn,
        binding,
        plan,
        base.snapshot.through,
        base.objects,
    )
}
fn audit_state(
    conn: &Connection,
    binding: &attested::Binding,
    plan: &Plan,
    through: u64,
    objects: u64,
) -> Result<Status> {
    check_plan(conn, binding, plan)?;
    let copied_records = through.min(plan.source().through);
    let mut hash = Sha256::new();
    hash.update(SOURCE_DOMAIN);
    frame(&mut hash, b"commits");
    hash.update(plan.source().through.to_be_bytes());
    for sequence in 1..=copied_records {
        let row = attested::record(conn, sequence)?;
        let es: Vec<_> = entries(&row.manifest).collect();
        if es.len() != 1 {
            return Err(corrupt("copy request entry"));
        }
        let request: Cid = cid(&es[0]["ciphertext"])
            .parse()
            .map_err(|_| corrupt("copy request CID"))?;
        hash.update(sequence.to_be_bytes());
        frame(&mut hash, row.manifest.bytes());
        frame(&mut hash, row.receipt.bytes());
        frame(&mut hash, &request.to_bytes());
        if sequence == plan.source().through
            && plan.source().tip.as_ref() != Some(row.manifest.cid())
        {
            return Err(corrupt("copy source tip"));
        }
    }
    let count: i64 = conn.query_row("SELECT count(*) FROM upgrade_objects", [], |r| r.get(0))?;
    let original_objects = u64::try_from(count).map_err(|_| corrupt("copy object count"))?;
    frame(&mut hash, b"objects");
    hash.update(original_objects.to_be_bytes());
    let erasures = erasure::load(conn)?;
    let mut erased_original_objects = 0;
    let mut stmt = conn.prepare("SELECT cid,length FROM upgrade_objects ORDER BY cid")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let text: String = row.get(0)?;
        let id: Cid = text.parse().map_err(|_| corrupt("original object CID"))?;
        let length: i64 = row.get(1)?;
        if !(1..=MAX_CHUNK as i64).contains(&length) || id.to_string() != text {
            return Err(corrupt("original object coordinate"));
        }
        if let Some(erased) = erasures.objects.get(&text) {
            erased_original_objects += 1;
            if erased.length as i64 != length {
                return Err(corrupt("erased copy length"));
            }
            erasure::check_marker(conn, &text)?;
            frame(&mut hash, &id.to_bytes());
            hash.update((length as u64).to_be_bytes());
            continue;
        }
        let payload: Vec<u8> = conn
            .query_row(
                "SELECT substr(bytes,1,4194304) FROM objects WHERE cid=? AND length(bytes)=?",
                params![text, length],
                |r| r.get(0),
            )
            .optional()?
            .ok_or_else(|| corrupt("original object missing or length changed"))?;
        if payload.len() as i64 != length || ciphertext_cid(&payload) != id {
            return Err(corrupt("original object length"));
        }
        frame(&mut hash, &id.to_bytes());
        hash.update((length as u64).to_be_bytes());
    }
    let digest: [u8; 32] = hash.finalize().into();
    let complete = copied_records == plan.source().through && digest == plan.source().digest;
    if !complete && (through > plan.source().through || objects != original_objects) {
        return Err(corrupt("admission or untracked objects in incomplete copy"));
    }
    Ok(Status {
        original_objects,
        erased_original_objects,
        copied_records,
        planned_records: plan.source().through,
        source_copy_complete: complete,
    })
}
pub(super) fn full_audit(
    ledger: &Ledger,
    binding: &attested::Binding,
    plan: &Plan,
) -> Result<Verification> {
    ledger.check_profile(3)?;
    ledger.check_copy_schema()?;
    let contents = ledger.verify_contents()?;
    let (frontier, _) = attested::audit_prefix(
        &ledger.conn,
        binding,
        contents.snapshot.through,
        None,
        Some(plan),
    )?;
    if frontier.manifest != contents.snapshot.tip {
        return Err(corrupt("copy proof tip"));
    }
    let copy = audit(ledger, binding, plan, &contents)?;
    Ok(Verification { contents, copy })
}

pub struct Archive {
    inner: attested::Archive,
}
impl Archive {
    #[cfg(feature = "v2-crypto")]
    pub fn preview_capture_erasure(
        &self,
        capture: super::erasure::Capture,
        keys: &[[u8; 32]],
        nonce: String,
        now: u64,
    ) -> Result<super::erasure::CapturePreview> {
        if !self.verify()?.copy.source_copy_complete {
            return Err(Error::Conflict("copy incomplete"));
        }
        self.inner
            .preview_capture_erasure(capture, keys, nonce, now)
    }

    #[cfg(feature = "v2-crypto")]
    pub fn scan_capture_erasure(
        &self,
        capture: super::erasure::Capture,
        keys: &[[u8; 32]],
        previous: Option<super::erasure::CaptureScan>,
        max_records: usize,
        max_bytes: usize,
    ) -> Result<super::erasure::CaptureScan> {
        if !self.verify()?.copy.source_copy_complete {
            return Err(Error::Conflict("copy incomplete"));
        }
        self.inner
            .scan_capture_erasure(capture, keys, previous, max_records, max_bytes)
    }
    #[cfg(feature = "v2-crypto")]
    pub fn finish_capture_erasure(
        &self,
        scan: super::erasure::CaptureScan,
        nonce: String,
        now: u64,
    ) -> Result<super::erasure::CapturePreview> {
        if !self.verify()?.copy.source_copy_complete {
            return Err(Error::Conflict("copy incomplete"));
        }
        self.inner.finish_capture_erasure(scan, nonce, now)
    }

    pub fn preview_erasure(
        &self,
        sequences: &[u64],
        nonce: String,
        now: u64,
    ) -> Result<super::erasure::Plan> {
        if !self.verify()?.copy.source_copy_complete {
            return Err(Error::Conflict("copy incomplete"));
        }
        self.inner.preview_erasure(sequences, nonce, now)
    }
    pub fn apply_erasure(
        &mut self,
        record: super::erasure::Record,
    ) -> Result<super::erasure::Package> {
        if !self.verify()?.copy.source_copy_complete {
            return Err(Error::Conflict("copy incomplete"));
        }
        self.inner.apply_erasure(record)
    }
    pub fn erasure_history(&self) -> Result<super::erasure::Package> {
        self.inner.erasure_history()
    }
    pub fn reconcile_erasure(
        &mut self,
        package: &super::erasure::Package,
        expected_tip: &str,
    ) -> Result<super::erasure::Package> {
        if !self.verify()?.copy.source_copy_complete {
            return Err(Error::Conflict("copy incomplete"));
        }
        self.inner.reconcile_erasure(package, expected_tip)
    }
    pub fn reclaim_erased_pages(&self) -> Result<bool> {
        self.inner.reclaim_erased_pages()
    }

    /// The owner must retain the exact plan artifact and external binding before
    /// calling. The verified source is required even for empty initialization.
    /// This initializes an empty archive; it does not certify possession of the
    /// signing key. An executor that requires no output before key verification
    /// must check that key first (the owner CLI does). Batches check the signer.
    pub fn create(root: &Path, source: &PlannedCopy, binding: attested::Binding) -> Result<Self> {
        Self::create_observed(root, source, binding, &mut |_| {})
    }
    pub fn create_observed(
        root: &Path,
        source: &PlannedCopy,
        binding: attested::Binding,
        observe: &mut dyn FnMut(InitializationBoundary),
    ) -> Result<Self> {
        configured(&binding, source.plan())?;
        let ledger = Ledger::create_with_plan(root, observe, Some(&binding), Some(source.plan()))?;
        Self::from_ledger(ledger, binding, source.plan().clone())
    }
    fn from_ledger(ledger: Ledger, binding: attested::Binding, plan: Plan) -> Result<Self> {
        ledger.conn.set_limit(
            rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH,
            RECOVERY_SQLITE_LENGTH_LIMIT,
        )?;
        let archive = Self {
            inner: attested::Archive {
                audit_cache: Default::default(),
                ledger,
                binding,
                copy: Some(plan),
            },
        };
        archive.verify()?;
        Ok(archive)
    }
    pub fn open(root: &Path, binding: attested::Binding) -> Result<Self> {
        binding.validate()?;
        let path = root.join("archive.sqlite");
        private_file(&path)?;
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        conn.set_limit(
            rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH,
            RECOVERY_SQLITE_LENGTH_LIMIT,
        )?;
        conn.busy_timeout(Duration::from_secs(5))?;
        let ledger = Ledger { conn };
        ledger.check_profile(3)?;
        ledger.check_copy_schema()?;
        let tx = ledger.conn.unchecked_transaction()?;
        let plan = stored_plan(&tx, &binding)?;
        full_audit(&ledger, &binding, &plan)?;
        tx.commit()?;
        configure(&ledger.conn)?;
        Self::from_ledger(ledger, binding, plan)
    }
    pub fn resume_initialization(
        root: &Path,
        source: &PlannedCopy,
        binding: attested::Binding,
    ) -> Result<Self> {
        configured(&binding, source.plan())?;
        let path = root.join("archive.sqlite");
        private_file(&path)?;
        let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        let app: i64 = conn.query_row("PRAGMA application_id", [], |r| r.get(0))?;
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        drop(conn);
        let result = if app == APPLICATION_ID && version == 3 {
            let result = Self::open(root, binding)?;
            if result.plan().bytes() != source.plan().bytes() {
                return Err(Error::Conflict("resume recipe differs"));
            }
            result
        } else {
            let ledger = Ledger::initialize_with_plan(
                root,
                &path,
                &mut |_| {},
                Some(&binding),
                Some(source.plan()),
            )?;
            Self::from_ledger(ledger, binding, source.plan().clone())?
        };
        std::fs::File::open(root)?.sync_all()?;
        std::fs::File::open(parent_directory(root))?.sync_all()?;
        Ok(result)
    }
    pub fn plan(&self) -> &Plan {
        self.inner.copy.as_ref().expect("copy constructor")
    }
    pub fn binding(&self) -> &attested::Binding {
        &self.inner.binding
    }
    pub fn verify(&self) -> Result<Verification> {
        let tx = self.inner.ledger.conn.unchecked_transaction()?;
        let result = full_audit(&self.inner.ledger, self.binding(), self.plan())?;
        tx.commit()?;
        Ok(result)
    }
    pub fn verify_file(path: &Path, binding: attested::Binding) -> Result<Verification> {
        binding.validate()?;
        let reader = RecoveryReader::open_profile(path, 3)?;
        let plan = stored_plan(&reader.ledger.conn, &binding)?;
        full_audit(&reader.ledger, &binding, &plan)
    }
    pub fn backup(&self, destination: &Path) -> Result<Verification> {
        self.backup_observed(destination, &mut |_| {})
    }
    pub fn backup_observed(
        &self,
        destination: &Path,
        observe: &mut dyn FnMut(BackupBoundary),
    ) -> Result<Verification> {
        let destination = self.inner.ledger.backup_copy(destination, observe)?;
        Self::verify_file(&destination, self.binding().clone())
    }
    /// `now` is Unix seconds, matching service request expiry.
    pub fn admit(
        &mut self,
        bytes: &[u8],
        signer: &Identity,
        grant: &Grant,
        now: u64,
    ) -> std::result::Result<attested::Admission, Failure> {
        self.inner.admit(bytes, signer, grant, now)
    }
    /// Fault harness only; callbacks cannot establish durability.
    pub fn admit_observed(
        &mut self,
        bytes: &[u8],
        signer: &Identity,
        grant: &Grant,
        now: u64,
        observe: &mut dyn FnMut(Boundary),
    ) -> std::result::Result<attested::Admission, Failure> {
        self.inner
            .admit_observed(bytes, signer, grant, now, observe)
    }
    /// `issued_at` is Unix milliseconds, matching retained proof timestamps.
    pub fn copy_batch(
        &mut self,
        source: &PlannedCopy,
        signer: &Identity,
        issued_at: u64,
        budget: Budget,
    ) -> Result<Batch> {
        self.copy_batch_observed(source, signer, issued_at, budget, &mut |_| {})
    }
    pub fn copy_batch_observed(
        &mut self,
        source: &PlannedCopy,
        signer: &Identity,
        issued_at: u64,
        budget: Budget,
        observe: &mut dyn FnMut(CopyBoundary),
    ) -> Result<Batch> {
        budget.validate()?;
        if signer.did().as_str() != self.binding().issuer
            || source.plan().bytes() != self.plan().bytes()
        {
            return Err(Error::Invalid("copy signer or recipe mismatch"));
        }
        let ledger = &self.inner.ledger;
        let tx =
            rusqlite::Transaction::new_unchecked(&ledger.conn, TransactionBehavior::Immediate)?;
        let before = full_audit(ledger, self.binding(), self.plan())?;
        let src = &source.reader().ledger;
        let mut originals = src
            .conn
            .prepare("SELECT cid,length(bytes) FROM objects ORDER BY cid")?;
        let mut source_rows = originals.query([])?;
        let mut inventory = tx.prepare("SELECT cid,length FROM upgrade_objects ORDER BY cid")?;
        let mut copied = inventory.query([])?;
        while let Some(old) = copied.next()? {
            let expected = source_rows
                .next()?
                .ok_or_else(|| corrupt("destination has extra original objects"))?;
            let id: String = old.get(0)?;
            let length: i64 = old.get(1)?;
            if id != expected.get::<_, String>(0)? || length != expected.get::<_, i64>(1)? {
                return Err(corrupt(
                    "original object inventory differs from source prefix",
                ));
            }
            let parsed: Cid = id.parse().map_err(|_| corrupt("original CID"))?;
            if ledger.read_object(&parsed)? != src.read_object(&parsed)? {
                return Err(corrupt("copied object bytes differ"));
            }
        }
        drop(copied);
        drop(inventory);
        for sequence in 1..=before.copy.copied_records {
            let old = attested::record(&tx, sequence)?;
            let expected = source.reader().record(sequence)?;
            if old.manifest.bytes() != expected.manifest.bytes()
                || old.receipt.bytes() != expected.receipt.bytes()
            {
                return Err(corrupt("copied record differs from source"));
            }
        }
        let mut objects_written = 0;
        let mut records_written = 0;
        let mut bytes_written = 0;
        let mut objects_done = true;
        while let Some(row) = source_rows.next()? {
            if before.contents.commits > 0 {
                return Err(corrupt("records precede complete original inventory"));
            }
            let id: String = row.get(0)?;
            let length: i64 = row.get(1)?;
            let length = usize::try_from(length).map_err(|_| corrupt("source object length"))?;
            if objects_written == budget.objects || length > budget.bytes - bytes_written {
                objects_done = false;
                break;
            }
            let parsed: Cid = id.parse().map_err(|_| corrupt("source object CID"))?;
            let bytes = src.read_object(&parsed)?;
            tx.execute("INSERT INTO objects VALUES(?,?)", params![id, bytes])?;
            observe(CopyBoundary::ObjectInserted);
            // surface-write: evidence-copy-sqlite:upgrade_objects
            crate::persistence::insert_evidence_copy_object(
                crate::persistence::SurfaceWrite::EvidenceCopy,
                &tx,
                &id,
                length as i64,
            )?;
            observe(CopyBoundary::InventoryInserted);
            objects_written += 1;
            bytes_written += length;
        }
        drop(source_rows);
        drop(originals);
        if objects_done {
            let (mut frontier, _) = attested::audit_prefix(
                &tx,
                self.binding(),
                before.contents.snapshot.through,
                None,
                Some(self.plan()),
            )?;
            for sequence in before.copy.copied_records + 1..=self.plan().source().through {
                if records_written == budget.records {
                    break;
                }
                let row = source.reader().record(sequence)?;
                let required = row.manifest.bytes().len()
                    + row.receipt.bytes().len()
                    + proof::MAX_ENVELOPE_BYTES;
                if required > budget.bytes - bytes_written {
                    break;
                }
                insert_record(&tx, &row)?;
                observe(CopyBoundary::ManifestInserted);
                let signed = proof::issue(
                    signer,
                    &self.binding().context(),
                    &row.manifest,
                    &row.receipt,
                    &frontier,
                    Purpose::RetainedVerified,
                    issued_at,
                )?;
                observe(CopyBoundary::ProofSigned);
                // surface-write: evidence-proof-sqlite:attestations
                crate::persistence::insert_evidence_proof(
                    crate::persistence::SurfaceWrite::EvidenceAttestation,
                    &tx,
                    sequence as i64,
                    signed.bytes(),
                )?;
                observe(CopyBoundary::ProofInserted);
                frontier = signed.frontier().clone();
                records_written += 1;
                bytes_written +=
                    row.manifest.bytes().len() + row.receipt.bytes().len() + signed.bytes().len();
            }
        }
        let status = full_audit(ledger, self.binding(), self.plan())?.copy;
        observe(CopyBoundary::BeforeCommit);
        tx.commit()?;
        observe(CopyBoundary::AfterCommit);
        Ok(Batch {
            status,
            objects_written,
            records_written,
            bytes_written,
        })
    }
}

fn insert_record(tx: &rusqlite::Transaction<'_>, row: &Committed) -> Result<()> {
    let b = row.manifest.body();
    let id = row.manifest.cid().to_string();
    tx.execute(
        "INSERT INTO commits VALUES(?,?,?,?,?,?,?,?,?)",
        params![
            i64::try_from(row.sequence).map_err(|_| Error::Invalid("sequence overflow"))?,
            id,
            blob(&b["scopeToken"]),
            writer(&row.manifest),
            blob(&b["operation"]),
            number(&b["position"]),
            optional_cid(&b["previous"]),
            row.manifest.bytes(),
            row.receipt.bytes()
        ],
    )?;
    for e in entries(&row.manifest) {
        tx.execute(
            "INSERT INTO bindings VALUES(?,?,?,?,?,?) ON CONFLICT(scope,writer,slot) DO NOTHING",
            params![
                blob(&b["scopeToken"]),
                writer(&row.manifest),
                blob(&e["slot"]),
                cid(&e["ciphertext"]),
                number(&e["length"]),
                id
            ],
        )?;
    }
    Ok(())
}

/// A pinned raw source for rebuilding derived metadata while preserving every
/// authoritative plan, membership, request, receipt, and proof byte.
pub struct Recovery {
    reader: RecoveryReader,
    binding: attested::Binding,
    plan: Plan,
}
impl Recovery {
    pub fn open(path: &Path, binding: attested::Binding) -> Result<Self> {
        binding.validate()?;
        let reader = RecoveryReader::open_profile(path, 3)?;
        let plan = stored_plan(&reader.ledger.conn, &binding)?;
        Ok(Self {
            reader,
            binding,
            plan,
        })
    }
    pub fn rebuild(&self, destination: &Path) -> Result<Verification> {
        self.rebuild_observed(destination, &mut |_| {})
    }
    pub fn rebuild_observed(
        &self,
        destination: &Path,
        observe: &mut dyn FnMut(RecoveryBoundary),
    ) -> Result<Verification> {
        self.reader.rebuild_with_plan(
            destination,
            observe,
            Some(&self.binding),
            Some(&self.plan),
        )?;
        Archive::verify_file(destination, self.binding.clone())
    }
}
pub(super) fn copy_inventory(source: &Connection, tx: &rusqlite::Transaction<'_>) -> Result<()> {
    let mut stmt =
        source.prepare("SELECT cid,length FROM upgrade_objects NOT INDEXED ORDER BY cid")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let text: String = row.get(0)?;
        let length: i64 = row.get(1)?;
        let id: Cid = text.parse().map_err(|_| corrupt("original object CID"))?;
        if id.to_string() != text || !(1..=MAX_CHUNK as i64).contains(&length) {
            return Err(corrupt("original object coordinate"));
        }
        // surface-write: evidence-copy-sqlite:upgrade_objects
        crate::persistence::insert_evidence_copy_object(
            crate::persistence::SurfaceWrite::EvidenceCopy,
            tx,
            &text,
            length,
        )?;
    }
    Ok(())
}

// Re-evaluate original membership under admission's immediate writer transaction,
// after staging and before signing. A preflight audit alone is not a fence.
pub(super) fn admission_ready(
    conn: &Connection,
    binding: &attested::Binding,
    plan: &Plan,
    through: u64,
) -> Result<()> {
    let count: i64 = conn.query_row("SELECT count(*) FROM objects", [], |r| r.get(0))?;
    let status = audit_state(
        conn,
        binding,
        plan,
        through,
        u64::try_from(count).map_err(|_| corrupt("object count"))?,
    )?;
    if !status.source_copy_complete {
        return Err(Error::Conflict("copy is incomplete"));
    }
    Ok(())
}

//! Profile 2: opaque service evidence and authoritative admission proofs.
//!
//! This is an owner-side storage API, not an RPC authorization boundary. Grants
//! and archive bindings must come from trusted configuration. The legacy Ledger
//! cannot open this profile. Writable opens require every retained payload.
use super::*;
use crate::{
    evidence_attestation::{self as proof, Context, Frontier, Purpose, Verified},
    evidence_service::{self as service, Failure, Grant, SignedRequest},
    sign::Identity,
};

pub(crate) const SCHEMA: &str = "
CREATE TABLE archive_identity(
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 archive BLOB NOT NULL CHECK(length(archive)=32),
 scope BLOB NOT NULL CHECK(length(scope)=32), issuer TEXT NOT NULL);
CREATE TABLE attestations(
 sequence INTEGER PRIMARY KEY REFERENCES commits(sequence),
 envelope BLOB NOT NULL CHECK(length(envelope)>0 AND length(envelope)<=16384));
PRAGMA user_version=2;
";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub archive: [u8; 32],
    pub scope: [u8; 32],
    pub issuer: String,
}
impl Binding {
    fn context(&self) -> Context<'_> {
        Context {
            archive: self.archive,
            scope: self.scope,
            issuer: &self.issuer,
        }
    }
    fn validate(&self) -> Result<()> {
        // The service author codec rejects unsupported/noncanonical keys. The
        // attestation codec further checks the exact static P-256 spelling.
        if !(56..=80).contains(&self.issuer.len())
            || !self.issuer.starts_with("did:key:z")
            || !self.issuer.is_ascii()
        {
            return Err(Error::Invalid("archive issuer"));
        }
        service::author(&self.issuer).map_err(|_| Error::Invalid("archive issuer"))?;
        let (algorithm, key) = atrium_crypto::did::parse_did_key(&self.issuer)
            .map_err(|_| Error::Invalid("archive issuer"))?;
        if algorithm != atrium_crypto::Algorithm::P256
            || atrium_crypto::did::format_did_key(algorithm, &key)
                .ok()
                .as_ref()
                != Some(&self.issuer)
        {
            return Err(Error::Invalid("archive requires canonical P-256 issuer"));
        }
        Ok(())
    }
}

pub(super) fn initialize(tx: &rusqlite::Transaction<'_>, binding: &Binding) -> Result<()> {
    binding.validate()?;
    // surface-write: evidence-proof-sqlite:archive_identity,evidence-proof-sqlite:attestations
    crate::persistence::initialize_evidence_proofs(
        crate::persistence::SurfaceWrite::EvidenceAttestation,
        tx,
        &binding.archive,
        &binding.scope,
        &binding.issuer,
    )?;
    Ok(())
}

pub struct Archive {
    ledger: Ledger,
    binding: Binding,
}
#[derive(Debug)]
pub struct Admission {
    pub record: Committed,
    pub attestation: Verified,
}

fn corrupt(message: &str) -> Error {
    Error::Corrupt(message.into())
}
fn check_binding(conn: &Connection, binding: &Binding) -> Result<()> {
    let count: i64 = conn.query_row("SELECT count(*) FROM archive_identity", [], |r| r.get(0))?;
    let actual: (Vec<u8>, Vec<u8>, String) = conn.query_row(
        "SELECT archive,scope,issuer FROM archive_identity WHERE singleton=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    if count != 1
        || actual.0 != binding.archive
        || actual.1 != binding.scope
        || actual.2 != binding.issuer
    {
        return Err(corrupt(
            "archive identity does not match owner configuration",
        ));
    }
    Ok(())
}
fn envelope(conn: &Connection, sequence: u64) -> Result<Vec<u8>> {
    let row: Option<(i64, Vec<u8>)> = conn
        .query_row(
            "SELECT length(envelope),substr(envelope,1,16384) FROM attestations WHERE sequence=?",
            [i64::try_from(sequence).map_err(|_| Error::Invalid("sequence overflow"))?],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (len, bytes) = row.ok_or_else(|| corrupt("missing attestation"))?;
    if !(1..=proof::MAX_ENVELOPE_BYTES as i64).contains(&len) {
        return Err(corrupt("attestation length"));
    }
    Ok(bytes)
}
fn record(conn: &Connection, sequence: u64) -> Result<Committed> {
    let mut stmt = conn.prepare(&format!("{RAW_COMMITS} WHERE sequence=?"))?;
    let mut rows =
        stmt.query([i64::try_from(sequence).map_err(|_| Error::Invalid("sequence overflow"))?])?;
    raw_commit(rows.next()?.ok_or(Error::MissingCommit(sequence))?)
}
fn retained(conn: &Connection, record: &Committed, binding: &Binding) -> Result<SignedRequest> {
    let es: Vec<_> = entries(&record.manifest).collect();
    if es.len() != 1 {
        return Err(corrupt("service manifest entries"));
    }
    let id = cid(&es[0]["ciphertext"]);
    let row: Option<(i64, Vec<u8>)> = conn
        .query_row(
            "SELECT length(bytes),substr(bytes,1,2101248) FROM objects WHERE cid=?",
            [&id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (len, bytes) = row.ok_or_else(|| Error::Missing(id.clone()))?;
    if !(1..=service::MAX_REQUEST as i64).contains(&len)
        || bytes.len() as i64 != len
        || ciphertext_cid(&bytes).to_string() != id
    {
        return Err(corrupt("retained signed request"));
    }
    let signed = service::verify_retained_request(record, &bytes)
        .map_err(|_| corrupt("retained request binding"))?;
    if signed.request.scope != service::hex(&binding.scope) {
        return Err(corrupt("retained request scope"));
    }
    Ok(signed)
}

// Caller owns a transaction. Constant working memory; currently a full scan.
// `through` excludes a new, not-yet-attested row inside admission's transaction.
fn audit_prefix(
    conn: &Connection,
    binding: &Binding,
    through: u64,
    target: Option<&Cid>,
) -> Result<(Frontier, Option<Verified>)> {
    check_binding(conn, binding)?;
    let count: i64 = conn.query_row("SELECT count(*) FROM attestations", [], |r| r.get(0))?;
    if u64::try_from(count).ok() != Some(through) {
        return Err(corrupt("attestation cardinality"));
    }
    let mut frontier = Frontier::default();
    let mut selected = None;
    let mut historical_issuer: Option<String> = None;
    let mut admitted = false;
    let mut stmt = conn.prepare(&format!(
        "{RAW_COMMITS} WHERE sequence<=? ORDER BY sequence"
    ))?;
    let mut rows =
        stmt.query([i64::try_from(through).map_err(|_| Error::Invalid("sequence overflow"))?])?;
    while let Some(row) = rows.next()? {
        let record = raw_commit(row)?;
        if record.sequence != frontier.through + 1 {
            return Err(corrupt("noncontiguous attestation chain"));
        }
        let verified = proof::verify(
            &envelope(conn, record.sequence)?,
            &binding.context(),
            &record.manifest,
            &record.receipt,
            &frontier,
        )
        .map_err(|_| corrupt("invalid attestation chain"))?;
        let signed = retained(conn, &record, binding)?;
        match verified.purpose() {
            Purpose::Admitted => {
                admitted = true;
                if signed.request.audience != binding.issuer {
                    return Err(corrupt("admitted request audience"));
                }
            }
            Purpose::RetainedVerified => {
                if admitted
                    || historical_issuer
                        .as_ref()
                        .is_some_and(|h| h != &signed.request.audience)
                {
                    return Err(corrupt("retained-verified prefix"));
                }
                historical_issuer = Some(signed.request.audience);
            }
        }
        frontier = verified.frontier().clone();
        if target == Some(record.manifest.cid()) {
            selected = Some(verified);
        }
    }
    if frontier.through != through {
        return Err(corrupt("attestation chain length"));
    }
    Ok((frontier, selected))
}
impl Archive {
    pub fn create(root: &Path, binding: Binding) -> Result<Self> {
        Self::create_observed(root, binding, &mut |_| {})
    }
    /// Fault harness only; callbacks do not establish durability.
    pub fn create_observed(
        root: &Path,
        binding: Binding,
        observe: &mut dyn FnMut(InitializationBoundary),
    ) -> Result<Self> {
        binding.validate()?;
        let ledger = Ledger::create_profile(root, observe, Some(&binding))?;
        ledger.conn.set_limit(
            rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH,
            RECOVERY_SQLITE_LENGTH_LIMIT,
        )?;
        Ok(Self { ledger, binding })
    }
    pub fn open(root: &Path, binding: Binding) -> Result<Self> {
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
            ledger: Ledger { conn },
            binding,
        };
        archive.ledger.check_profile(2)?;
        archive.ledger.check_write_profile(true)?;
        archive.verify()?;
        configure(&archive.ledger.conn)?;
        Ok(archive)
    }
    /// Explicit owner opt-in for interrupted creation. Empty foreign files are
    /// indistinguishable from interrupted output; no existing profile is converted.
    pub fn resume_initialization(root: &Path, binding: Binding) -> Result<Self> {
        binding.validate()?;
        let path = root.join("archive.sqlite");
        private_file(&path)?;
        let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        let app: i64 = conn.query_row("PRAGMA application_id", [], |r| r.get(0))?;
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        drop(conn);
        let archive = if app == APPLICATION_ID && version == 2 {
            Self::open(root, binding)?
        } else {
            let ledger = Ledger::initialize_empty(root, &path, &mut |_| {}, Some(&binding))?;
            ledger.conn.set_limit(
                rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH,
                RECOVERY_SQLITE_LENGTH_LIMIT,
            )?;
            Self { ledger, binding }
        };
        std::fs::File::open(root)?.sync_all()?;
        std::fs::File::open(parent_directory(root))?.sync_all()?;
        Ok(archive)
    }
    /// Full standalone backup. A failure may leave an incomplete or complete
    /// output; use a fresh destination, never overwrite or promote automatically.
    pub fn backup(&self, destination: &Path) -> Result<Verification> {
        self.backup_observed(destination, &mut |_| {})
    }
    pub fn backup_observed(
        &self,
        destination: &Path,
        observe: &mut dyn FnMut(BackupBoundary),
    ) -> Result<Verification> {
        let destination = self.ledger.backup_copy(destination, observe)?;
        Self::verify_file(&destination, self.binding.clone())
    }
    /// Full audit of a standalone profile-2 file against owner configuration.
    /// Read-only SQLite can initialize its declared WAL/SHM coordination files.
    pub fn verify_file(path: &Path, binding: Binding) -> Result<Verification> {
        let reader = Recovery::open(path, binding)?;
        reader.reader.ledger.check_write_profile(true)?;
        let base = reader.reader.ledger.verify_contents()?;
        verify_contents(&reader.reader.ledger, &reader.binding, &base)?;
        Ok(base)
    }
    pub fn binding(&self) -> &Binding {
        &self.binding
    }
    pub fn verify(&self) -> Result<Frontier> {
        self.verify_for(None).map(|(frontier, _)| frontier)
    }
    fn verify_for(&self, target: Option<&Cid>) -> Result<(Frontier, Option<Verified>)> {
        let tx = self.ledger.conn.unchecked_transaction()?;
        let base = self.ledger.verify_contents()?;
        let (frontier, selected) = audit_prefix(&tx, &self.binding, base.snapshot.through, target)?;
        if frontier.manifest != base.snapshot.tip {
            return Err(corrupt("attestation tip"));
        }
        tx.commit()?;
        Ok((frontier, selected))
    }
    /// Owner-side admission. The caller supplies a current trusted grant; remote
    /// callers must never be allowed to supply or choose this grant themselves.
    pub fn admit(
        &mut self,
        bytes: &[u8],
        signer: &Identity,
        grant: &Grant,
        now: u64,
    ) -> std::result::Result<Admission, Failure> {
        self.admit_observed(bytes, signer, grant, now, &mut |_| {})
    }
    /// Fault harness only: callbacks cannot establish durability.
    pub fn admit_observed(
        &mut self,
        bytes: &[u8],
        signer: &Identity,
        grant: &Grant,
        now: u64,
        observe: &mut dyn FnMut(Boundary),
    ) -> std::result::Result<Admission, Failure> {
        let signed = SignedRequest::decode(bytes)?;
        if !grant.append
            || grant.principal != signed.request.principal
            || signed.request.scope != service::hex(&self.binding.scope)
            || signed.request.audience != self.binding.issuer
            || signer.did().as_str() != self.binding.issuer
        {
            return Err(Failure::AccessLimited);
        }
        let manifest = service::append_manifest(bytes)?;
        let receipt = service::receipt(&manifest, &self.binding.issuer, now)?;
        let (previous, duplicate_proof) = self.verify_for(Some(manifest.cid()))?;
        self.ledger.stage_observed(bytes, observe)?;
        let expected = Snapshot {
            through: previous.through,
            tip: previous.manifest.clone(),
        };
        let binding = &self.binding;
        let mut result = None;
        let mut hook = |tx: &rusqlite::Transaction<'_>,
                        row: &Committed,
                        observe: &mut dyn FnMut(Boundary)|
         -> Result<()> {
            // All archive mutations through this API append. Recheck both tips
            // and proof cardinality under the immediate writer transaction; a
            // raw append or same-height replacement cannot cross this fence.
            check_binding(tx, binding)?;
            let count: i64 = tx.query_row("SELECT count(*) FROM attestations", [], |r| r.get(0))?;
            if u64::try_from(count).ok() != Some(previous.through) {
                return Err(Error::Conflict("attestation audit frontier"));
            }
            if previous.through > 0 {
                let tip = record(tx, previous.through)?;
                proof::verify_at(
                    &envelope(tx, previous.through)?,
                    &binding.context(),
                    &tip.manifest,
                    &tip.receipt,
                    &previous,
                )
                .map_err(|_| Error::Conflict("attestation audit frontier"))?;
            }
            let verified = if row.duplicate {
                let old = duplicate_proof
                    .as_ref()
                    .ok_or_else(|| corrupt("unaudited retry"))?;
                if old.frontier().through != row.sequence
                    || old.frontier().manifest.as_ref() != Some(row.manifest.cid())
                    || envelope(tx, row.sequence)? != old.bytes()
                {
                    return Err(Error::Conflict("retry proof changed"));
                }
                // Recheck exact receipt binding against the previously verified proof.
                proof::verify_at(
                    old.bytes(),
                    &binding.context(),
                    &row.manifest,
                    &row.receipt,
                    old.frontier(),
                )
                .map_err(|_| Error::Conflict("retry receipt changed"))?;
                if old.purpose() != Purpose::Admitted {
                    return Err(Error::Conflict(
                        "imported retry requires explicit confirmation",
                    ));
                }
                old.clone()
            } else {
                if row.sequence != previous.through + 1 {
                    return Err(corrupt("new attestation sequence"));
                }
                let proof = proof::issue(
                    signer,
                    &binding.context(),
                    &row.manifest,
                    &row.receipt,
                    &previous,
                    Purpose::Admitted,
                    now.checked_mul(1000).ok_or(Error::Invalid("timestamp"))?,
                )?;
                observe(Boundary::AttestationSigned);
                // surface-write: evidence-proof-sqlite:attestations
                crate::persistence::insert_evidence_proof(
                    crate::persistence::SurfaceWrite::EvidenceAttestation,
                    tx,
                    i64::try_from(row.sequence).map_err(|_| Error::Invalid("sequence overflow"))?,
                    proof.bytes(),
                )?;
                observe(Boundary::AttestationInserted);
                proof
            };
            result = Some(verified);
            Ok(())
        };
        let record = self.ledger.commit_inner(
            manifest.bytes(),
            receipt.bytes(),
            observe,
            true,
            Some(&expected),
            Some(&mut hook),
        )?;
        Ok(Admission {
            record,
            attestation: result.ok_or(Failure::Corrupt)?,
        })
    }
}

/// Read-only pinned source for a full proof-preserving rebuild. Opening does not
/// certify raw contents; successful rebuild verifies all metadata, proofs and
/// payloads. No degraded or metadata-only success is returned by this API.
pub struct Recovery {
    reader: RecoveryReader,
    binding: Binding,
}
impl Recovery {
    pub fn open(path: &Path, binding: Binding) -> Result<Self> {
        binding.validate()?;
        let reader = RecoveryReader::open_profile(path, 2)?;
        check_binding(&reader.ledger.conn, &binding)?;
        Ok(Self { reader, binding })
    }
    pub fn rebuild(&self, destination: &Path) -> Result<Verification> {
        self.rebuild_observed(destination, &mut |_| {})
    }
    pub fn rebuild_observed(
        &self,
        destination: &Path,
        observe: &mut dyn FnMut(RecoveryBoundary),
    ) -> Result<Verification> {
        self.reader
            .rebuild_profile(destination, observe, Some(&self.binding))
    }
}
pub(super) fn check_copy_source(conn: &Connection, binding: &Binding, through: u64) -> Result<()> {
    check_binding(conn, binding)?;
    let count: i64 = conn.query_row("SELECT count(*) FROM attestations", [], |r| r.get(0))?;
    if u64::try_from(count).ok() != Some(through) {
        return Err(corrupt("attestation cardinality"));
    }
    Ok(())
}
pub(super) fn copy_proof(
    source: &Connection,
    target: &rusqlite::Transaction<'_>,
    sequence: u64,
) -> Result<()> {
    let bytes = envelope(source, sequence)?;
    // surface-write: evidence-proof-sqlite:attestations
    crate::persistence::insert_evidence_proof(
        crate::persistence::SurfaceWrite::EvidenceAttestation,
        target,
        i64::try_from(sequence).map_err(|_| Error::Invalid("sequence overflow"))?,
        &bytes,
    )?;
    Ok(())
}
pub(super) fn verify_contents(
    ledger: &Ledger,
    binding: &Binding,
    base: &Verification,
) -> Result<()> {
    let (frontier, _) = audit_prefix(&ledger.conn, binding, base.snapshot.through, None)?;
    if frontier.manifest != base.snapshot.tip {
        return Err(corrupt("attestation tip"));
    }
    Ok(())
}

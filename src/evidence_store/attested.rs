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
    pub(super) fn context(&self) -> Context<'_> {
        Context {
            archive: self.archive,
            scope: self.scope,
            issuer: &self.issuer,
        }
    }
    pub(super) fn validate(&self) -> Result<()> {
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

/// Disposable memoization of successful cryptographic checks over exact bytes.
/// Every audit still checks current payload hashes, metadata, shape and chain.
#[derive(Default)]
pub(super) struct AuditCache {
    entries: std::collections::BTreeMap<[u8; 32], (Verified, String)>,
    bytes: usize,
    #[cfg(test)]
    hits: usize,
}
impl AuditCache {
    fn insert(&mut self, key: [u8; 32], proof: &Verified, audience: &str) {
        let cost = proof.bytes().len() + proof.statement_bytes().len() + audience.len() + 1024;
        if self.entries.len() < 4096
            && self.bytes + cost <= 8 * 1024 * 1024
            && !self.entries.contains_key(&key)
        {
            self.bytes += cost;
            self.entries
                .insert(key, (proof.clone(), audience.to_owned()));
        }
    }
}
pub struct Archive {
    pub(super) audit_cache: std::cell::RefCell<AuditCache>,
    pub(super) ledger: Ledger,
    pub(super) binding: Binding,
    pub(super) copy: Option<crate::evidence_copy_plan::Plan>,
}
#[derive(Debug)]
pub struct Admission {
    pub record: Committed,
    pub attestation: Verified,
}

fn corrupt(message: &str) -> Error {
    Error::Corrupt(message.into())
}
pub(super) fn check_binding(conn: &Connection, binding: &Binding) -> Result<()> {
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
pub(super) fn envelope(conn: &Connection, sequence: u64) -> Result<Vec<u8>> {
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
pub(super) fn record(conn: &Connection, sequence: u64) -> Result<Committed> {
    let mut stmt = conn.prepare(&format!("{RAW_COMMITS} WHERE sequence=?"))?;
    let mut rows =
        stmt.query([i64::try_from(sequence).map_err(|_| Error::Invalid("sequence overflow"))?])?;
    raw_commit(rows.next()?.ok_or(Error::MissingCommit(sequence))?)
}
fn retained_bytes(conn: &Connection, record: &Committed) -> Result<Vec<u8>> {
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
    Ok(bytes)
}

// Caller owns a transaction. Full scan; optional bounded crypto memoization.
// `through` excludes a new, not-yet-attested row inside admission's transaction.
pub(super) fn audit_prefix(
    conn: &Connection,
    binding: &Binding,
    through: u64,
    target: Option<&Cid>,
    copy: Option<&crate::evidence_copy_plan::Plan>,
) -> Result<(Frontier, Option<Verified>)> {
    audit_prefix_cached(conn, binding, through, target, copy, None)
}
fn audit_prefix_cached(
    conn: &Connection,
    binding: &Binding,
    through: u64,
    target: Option<&Cid>,
    copy: Option<&crate::evidence_copy_plan::Plan>,
    mut cache: Option<&mut AuditCache>,
) -> Result<(Frontier, Option<Verified>)> {
    check_binding(conn, binding)?;
    let count: i64 = conn.query_row("SELECT count(*) FROM attestations", [], |r| r.get(0))?;
    if u64::try_from(count).ok() != Some(through) {
        return Err(corrupt("attestation cardinality"));
    }
    let erasures = erasure::load(conn)?;
    let mut frontier = Frontier::default();
    let mut selected = None;
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
        let envelope = envelope(conn, record.sequence)?;
        // Hash the CURRENT retained bytes even on a memoized cryptographic check.
        // The authenticated manifest includes this checked ciphertext CID.
        let object = cid(&entries(&record.manifest)
            .next()
            .ok_or_else(|| corrupt("empty manifest"))?["ciphertext"]);
        let erased = erasures.objects.contains_key(&object);
        let bytes = if erased {
            erasure::check_marker(conn, &object)?;
            Vec::new()
        } else {
            retained_bytes(conn, &record)?
        };
        let mut fingerprint = Sha256::new();
        fingerprint.update(b"kan.admission.crypto-cache.v1\0");
        fingerprint.update(binding.archive);
        fingerprint.update(binding.scope);
        for part in [
            binding.issuer.as_bytes(),
            record.manifest.bytes(),
            record.receipt.bytes(),
            envelope.as_slice(),
        ] {
            fingerprint.update((part.len() as u64).to_be_bytes());
            fingerprint.update(part);
        }
        let key: [u8; 32] = fingerprint.finalize().into();
        let cached = cache.as_ref().and_then(|c| c.entries.get(&key)).cloned();
        let (verified, audience) = if erased {
            let verified = proof::verify(
                &envelope,
                &binding.context(),
                &record.manifest,
                &record.receipt,
                &frontier,
            )
            .map_err(|_| corrupt("invalid erased attestation"))?;
            let audience = match verified.purpose() {
                Purpose::Admitted => binding.issuer.clone(),
                Purpose::RetainedVerified => copy
                    .ok_or_else(|| corrupt("erased copy without plan"))?
                    .source()
                    .historical_issuer
                    .clone(),
            };
            (verified, audience)
        } else if let Some((verified, audience)) = cached {
            #[cfg(test)]
            if let Some(cache) = cache.as_mut() {
                cache.hits += 1;
            }
            if verified.previous() != &frontier {
                return Err(corrupt("invalid attestation chain"));
            }
            (verified, audience)
        } else {
            let verified = proof::verify(
                &envelope,
                &binding.context(),
                &record.manifest,
                &record.receipt,
                &frontier,
            )
            .map_err(|_| corrupt("invalid attestation chain"))?;
            let signed = service::verify_retained_request(&record, &bytes)
                .map_err(|_| corrupt("retained request binding"))?;
            if signed.request.scope != service::hex(&binding.scope) {
                return Err(corrupt("retained request scope"));
            }
            let audience = signed.request.audience;
            if let Some(cache) = cache.as_mut() {
                cache.insert(key, &verified, &audience);
            }
            (verified, audience)
        };
        match verified.purpose() {
            Purpose::Admitted => {
                if copy.is_some_and(|p| record.sequence <= p.source().through) {
                    return Err(corrupt("admission inside planned retained prefix"));
                }
                if audience != binding.issuer {
                    return Err(corrupt("admitted request audience"));
                }
            }
            Purpose::RetainedVerified => {
                let plan =
                    copy.ok_or_else(|| corrupt("retained-verified prefix requires copy profile"))?;
                if record.sequence > plan.source().through {
                    return Err(corrupt("retained-verified row after planned prefix"));
                }
                if audience != plan.source().historical_issuer {
                    return Err(corrupt(
                        "retained-verified historical issuer differs from copy plan",
                    ));
                }
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
        Ok(Self {
            audit_cache: Default::default(),
            ledger,
            binding,
            copy: None,
        })
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
            audit_cache: Default::default(),
            ledger: Ledger { conn },
            binding,
            copy: None,
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
            Self {
                audit_cache: Default::default(),
                ledger,
                binding,
                copy: None,
            }
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
        if let Some(plan) = &self.copy {
            let status = copied::audit(&self.ledger, &self.binding, plan, &base)?;
            if target.is_some() && !status.source_copy_complete {
                return Err(Error::Conflict("copy is incomplete"));
            }
        }
        let mut cache = target.map(|_| self.audit_cache.borrow_mut());
        let (frontier, selected) = audit_prefix_cached(
            &tx,
            &self.binding,
            base.snapshot.through,
            target,
            self.copy.as_ref(),
            cache.as_deref_mut(),
        )?;
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
        self.admit_internal(bytes, signer, grant, now, observe, None)
    }
    /// Owner-side commitment-only admission. The caller must first publish the
    /// exact independently owner-authorized erasure record. No raw bytes stage.
    pub fn admit_erased(
        &mut self,
        bytes: &[u8],
        signer: &Identity,
        grant: &Grant,
        erasure: &erasure::Record,
    ) -> std::result::Result<Admission, Failure> {
        self.admit_erased_observed(bytes, signer, grant, erasure, &mut |_| {})
    }
    /// Fault harness for atomic commitment, proof and initial erasure insertion.
    pub fn admit_erased_observed(
        &mut self,
        bytes: &[u8],
        signer: &Identity,
        grant: &Grant,
        erasure: &erasure::Record,
        observe: &mut dyn FnMut(Boundary),
    ) -> std::result::Result<Admission, Failure> {
        if self.copy.is_some() {
            return Err(Failure::Invalid);
        }
        self.admit_internal(
            bytes,
            signer,
            grant,
            erasure.plan.recorded_at,
            observe,
            Some(erasure),
        )
    }
    fn admit_internal(
        &mut self,
        bytes: &[u8],
        signer: &Identity,
        grant: &Grant,
        now: u64,
        observe: &mut dyn FnMut(Boundary),
        initial_erasure: Option<&erasure::Record>,
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
        if let Some(record) = initial_erasure {
            erasure::check_initial_request(&self.ledger.conn, &self.binding, record, bytes)?;
            self.ledger
                .conn
                .execute_batch("PRAGMA secure_delete=ON;")
                .map_err(Error::from)?;
        } else {
            self.ledger.stage_observed(bytes, observe)?;
        }
        let expected = Snapshot {
            through: previous.through,
            tip: previous.manifest.clone(),
        };
        let binding = &self.binding;
        let copy = self.copy.as_ref();
        let mut result = None;
        let mut hook = |tx: &rusqlite::Transaction<'_>,
                        row: &Committed,
                        observe: &mut dyn FnMut(Boundary)|
         -> Result<()> {
            // All archive mutations through this API append. Recheck both tips
            // and proof cardinality under the immediate writer transaction; a
            // raw append or same-height replacement cannot cross this fence.
            check_binding(tx, binding)?;
            if let Some(plan) = copy {
                copied::admission_ready(tx, binding, plan, previous.through)?;
            }
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
            initial_erasure.map_or(CommitMode::Partitioned, CommitMode::InitiallyErased),
            Some(&expected),
            Some(&mut hook),
        )?;
        if initial_erasure.is_some() {
            self.audit_cache.replace(Default::default());
        }
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
    let (frontier, _) = audit_prefix(&ledger.conn, binding, base.snapshot.through, None, None)?;
    if frontier.manifest != base.snapshot.tip {
        return Err(corrupt("attestation tip"));
    }
    Ok(())
}

#[cfg(test)]
mod audit_cache_tests {
    use super::*;
    use std::io::Write;
    fn identity(n: u8) -> Identity {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&[n; 32]).unwrap();
        Identity::load_existing(file.path()).unwrap()
    }
    #[test]
    fn exact_crypto_checks_are_reused_but_payload_and_proof_damage_still_refuse_admission() {
        let dir = tempfile::tempdir().unwrap();
        let signer = identity(8);
        let writer = identity(6);
        let binding = Binding {
            archive: [1; 32],
            scope: [2; 32],
            issuer: signer.did().to_string(),
        };
        let grant = Grant {
            principal: writer.did().to_string(),
            append: true,
            inventory: true,
        };
        let mut archive = Archive::create(dir.path(), binding.clone()).unwrap();
        let make = |position: u64, previous: Option<String>| {
            SignedRequest::sign(
                service::Request {
                    version: 1,
                    scope: service::hex(&binding.scope),
                    principal: writer.did().to_string(),
                    audience: binding.issuer.clone(),
                    expires: None,
                    command: service::Command::Append {
                        id: service::hex(&[position as u8; 16]),
                        position,
                        previous,
                        ciphertext: service::hex(b"retained encrypted bytes"),
                    },
                },
                &writer,
            )
            .unwrap()
            .bytes()
            .unwrap()
        };
        let first = make(0, None);
        let a = archive.admit(&first, &signer, &grant, 100).unwrap();
        let second = make(1, Some(a.record.manifest.cid().to_string()));
        archive.admit(&second, &signer, &grant, 101).unwrap();
        let before = archive.audit_cache.borrow().hits;
        archive.admit(&first, &signer, &grant, 102).unwrap();
        assert!(archive.audit_cache.borrow().hits > before);
        assert_eq!(archive.audit_cache.borrow().entries.len(), 2);
        let conn = Connection::open(dir.path().join("archive.sqlite")).unwrap();
        let object = ciphertext_cid(&first).to_string();
        let mut bad = first.clone();
        *bad.last_mut().unwrap() ^= 1;
        conn.execute(
            "UPDATE objects SET bytes=? WHERE cid=?",
            rusqlite::params![bad, object],
        )
        .unwrap();
        assert!(archive.admit(&second, &signer, &grant, 103).is_err());
        conn.execute(
            "UPDATE objects SET bytes=? WHERE cid=?",
            rusqlite::params![first, object],
        )
        .unwrap();
        let original = envelope(&conn, 1).unwrap();
        let mut corrupt_proof = original.clone();
        *corrupt_proof.last_mut().unwrap() ^= 1;
        conn.execute(
            "UPDATE attestations SET envelope=? WHERE sequence=1",
            [corrupt_proof],
        )
        .unwrap();
        assert!(archive.admit(&second, &signer, &grant, 104).is_err());
        conn.execute(
            "UPDATE attestations SET envelope=? WHERE sequence=1",
            [original],
        )
        .unwrap();
        let hits = archive.audit_cache.borrow().hits;
        archive.verify().unwrap();
        assert_eq!(
            archive.audit_cache.borrow().hits,
            hits,
            "standalone verification must not depend on memoized checks"
        );
        assert!(
            archive
                .admit(&first, &signer, &grant, 105)
                .unwrap()
                .record
                .duplicate
        );
        assert!(archive.audit_cache.borrow().bytes <= 8 * 1024 * 1024);
    }
}

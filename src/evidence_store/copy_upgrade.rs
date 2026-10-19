//! Read-only source planning for an explicit owner copy. No destination writes.
use super::*;
use crate::{
    evidence_copy_plan::{Plan, Source, Target},
    evidence_service as service,
};
pub(super) const SOURCE_DOMAIN: &[u8] = b"tools.kan.archive.copy-source.v1\0";

/// A verified complete legacy snapshot retained by a read-only transaction.
/// A plan decoded from disk cannot construct this value without re-verification.
pub struct PlannedCopy {
    reader: RecoveryReader,
    plan: Plan,
}
pub(super) fn frame(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}
impl PlannedCopy {
    /// Pin and fully verify a healthy legacy archive before producing a recipe.
    /// The source's derived indexes must also be valid; use the separate recovery
    /// workflow first if they need rebuilding. No files are promoted or erased.
    pub fn open(
        path: &Path,
        target: Target,
        historical_issuer: String,
        nonce: [u8; 32],
    ) -> Result<Self> {
        // Validate owner configuration before opening source media.
        Plan::new(
            Source {
                through: 0,
                tip: None,
                digest: [0; 32],
                historical_issuer: historical_issuer.clone(),
            },
            target.clone(),
            nonce,
        )?;
        let reader = RecoveryReader::open(path)?;
        reader.ledger.check_write_profile(false)?;
        let verification = reader.ledger.verify_contents()?;
        let snapshot = &verification.snapshot;
        let mut hash = Sha256::new();
        hash.update(SOURCE_DOMAIN);
        frame(&mut hash, b"commits");
        hash.update(snapshot.through.to_be_bytes());
        for sequence in 1..=snapshot.through {
            let record = reader.record(sequence)?;
            let es: Vec<_> = entries(&record.manifest).collect();
            if es.len() != 1 {
                return Err(Error::Invalid(
                    "copy requires a service request per manifest",
                ));
            }
            let object: Cid = cid(&es[0]["ciphertext"])
                .parse()
                .map_err(|_| Error::Invalid("copy request CID"))?;
            // The full audit above has already checked every object size/hash
            // in this same pinned transaction. Indexed reads cannot now reveal
            // an unaudited oversized row; avoid a full object scan per request.
            let request_bytes = reader.ledger.read_object(&object)?;
            let signed = service::verify_retained_request(&record, &request_bytes)
                .map_err(|_| Error::Corrupt("copy retained request".into()))?;
            if signed.request.scope != service::hex(&target.scope)
                || signed.request.audience != historical_issuer
            {
                return Err(Error::Invalid(
                    "copy source scope or historical issuer mismatch",
                ));
            }
            hash.update(sequence.to_be_bytes());
            frame(&mut hash, record.manifest.bytes());
            frame(&mut hash, record.receipt.bytes());
            frame(&mut hash, &object.to_bytes());
        }
        // Bind staged-but-uncommitted objects as well as the committed stream.
        // verify_contents already checked every object's CID against its bytes.
        frame(&mut hash, b"objects");
        hash.update(verification.objects.to_be_bytes());
        {
            let mut query = reader
                .ledger
                .conn
                .prepare("SELECT cid,length(bytes) FROM objects ORDER BY cid")?;
            let mut rows = query.query([])?;
            while let Some(row) = rows.next()? {
                let id: String = row.get(0)?;
                let object: Cid = id.parse().map_err(|_| Error::Invalid("copy object CID"))?;
                let length: i64 = row.get(1)?;
                frame(&mut hash, &object.to_bytes());
                hash.update(
                    u64::try_from(length)
                        .map_err(|_| Error::Invalid("copy object length"))?
                        .to_be_bytes(),
                );
            }
        }
        let plan = Plan::new(
            Source {
                through: snapshot.through,
                tip: snapshot.tip.clone(),
                digest: hash.finalize().into(),
                historical_issuer,
            },
            target,
            nonce,
        )?;
        Ok(Self { reader, plan })
    }
    /// Reopen a source and require the entire exact owner-pinned recipe. Matching
    /// only the high-water sequence or tip is insufficient for copy resumption.
    pub fn confirm(path: &Path, plan: &Plan, expected_archive: &[u8; 32]) -> Result<Self> {
        plan.check_archive(expected_archive)?;
        let checked = Self::open(
            path,
            plan.target().clone(),
            plan.source().historical_issuer.clone(),
            *plan.nonce(),
        )?;
        if checked.plan.bytes() != plan.bytes() {
            return Err(Error::Conflict("copy source differs from pinned plan"));
        }
        Ok(checked)
    }
    pub(super) fn reader(&self) -> &RecoveryReader {
        &self.reader
    }
    pub fn plan(&self) -> &Plan {
        &self.plan
    }
    pub fn snapshot(&self) -> Result<Snapshot> {
        self.reader.snapshot()
    }
}

/// Retain a recipe before creating its destination. The new file is private and
/// durable; errors leave any output for explicit owner inspection.
pub fn retain_plan(path: &Path, source: &PlannedCopy) -> Result<()> {
    plan_outside_sqlite(&source.reader.source, path)?;
    let plan = source.plan();
    // surface-write: evidence-copy-plan:artifact
    crate::persistence::write_new_owner_only(
        crate::persistence::SurfaceWrite::EvidenceCopyPlan,
        path,
        plan.bytes(),
    )?;
    std::fs::File::open(parent_directory(path))?.sync_all()?;
    let actual = read_plan(path, &plan.archive_id())?;
    if actual.bytes() != plan.bytes() {
        return Err(Error::Conflict("retained recipe changed"));
    }
    Ok(())
}
// A plan is an ordinary retained file, never a SQLite main file or sidecar.
fn plan_outside_sqlite(database: &Path, plan: &Path) -> Result<()> {
    if same_existing_file(database, plan) {
        return Err(Error::Invalid("plan aliases a SQLite database"));
    }
    sqlite_destination(database, plan)?;
    Ok(())
}

/// Validate plan custody against both SQLite families before any database opens.
/// An absent destination root must have an existing parent, as creation requires.
/// This protects owner-selected paths under the same trusted-filesystem contract
/// as archive creation; it does not fence concurrent hostile path replacement.
pub fn read_plan_for_copy(
    path: &Path,
    source: &Path,
    destination_root: &Path,
    expected_archive: &[u8; 32],
) -> Result<Plan> {
    let source = std::fs::canonicalize(source)?;
    plan_outside_sqlite(&source, path)?;
    let root = if destination_root.exists() {
        std::fs::canonicalize(destination_root)?
    } else {
        std::fs::canonicalize(parent_directory(destination_root))?.join(
            destination_root
                .file_name()
                .ok_or(Error::Invalid("destination directory"))?,
        )
    };
    plan_outside_sqlite(&root.join("archive.sqlite"), path)?;
    read_plan(path, expected_archive)
}

/// Decode bounded private recipe bytes and compare the separately supplied pin.
/// This decoder never opens SQLite. Executors must use `read_plan_for_copy` to
/// protect artifact custody before opening either source or destination.
pub fn read_plan(path: &Path, expected_archive: &[u8; 32]) -> Result<Plan> {
    use std::io::Read;
    private_file(path).map_err(|e| match e {
        Error::Invalid("database must be owner-only") => Error::Invalid("plan must be owner-only"),
        Error::Invalid("expected regular database file") => {
            Error::Invalid("expected regular plan file")
        }
        other => other,
    })?;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(crate::evidence_copy_plan::MAX_PLAN_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    let plan = Plan::decode(&bytes)?;
    plan.check_archive(expected_archive)?;
    Ok(plan)
}

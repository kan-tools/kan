//! Read-only source planning for an explicit owner copy. No destination writes.
use super::*;
use crate::{
    evidence_copy_plan::{Plan, Source, Target},
    evidence_service as service,
};
const SOURCE_DOMAIN: &[u8] = b"tools.kan.archive.copy-source.v1\0";

/// A verified complete legacy snapshot retained by a read-only transaction.
/// A plan decoded from disk cannot construct this value without re-verification.
pub struct PlannedCopy {
    reader: RecoveryReader,
    plan: Plan,
}
fn frame(hash: &mut Sha256, bytes: &[u8]) {
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
            let request_bytes = reader.read_object(&object)?;
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
    pub fn plan(&self) -> &Plan {
        &self.plan
    }
    pub fn snapshot(&self) -> Result<Snapshot> {
        self.reader.snapshot()
    }
}

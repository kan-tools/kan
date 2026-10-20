//! Independently retained owner authorization for storage erasure. Enrolled
//! services keep a shared lease through each operation and require the archive
//! to match current custody exactly. A backup is never its own freshness oracle.
//! This is managed non-resurrection, not deletion of historical offline copies.
use crate::{
    evidence_proof_service::Binding,
    evidence_service::{self as service, Failure},
    sign::Identity,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    path::{Path, PathBuf},
};
type Result<T> = std::result::Result<T, Failure>;
const DOMAIN: &[u8] = b"tools.kan.owner.erasure.v1\0";
const MAX_RECORD: usize = 1024 * 1024 + 4096;
const MAX_HISTORY: usize = 1025;
const MAX_TOTAL: usize = 18 * 1024 * 1024;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Access {
    pub directory: PathBuf,
    pub binding: Binding,
    pub owner: String,
    #[serde(default)]
    pub minimum: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Change {
    pub version: u8,
    pub binding: Binding,
    pub owner: String,
    pub sequence: String,
    pub previous: Option<String>,
    pub nonce: String,
    pub recorded_at: String,
    pub erasure: Option<crate::evidence_store::erasure::Record>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub change: Change,
    pub signature: String,
}
pub struct Snapshot {
    _lease: std::fs::File,
    pub history: Vec<Record>,
    pub tip: Option<String>,
}
impl Snapshot {
    pub fn package(&self) -> Result<crate::evidence_store::erasure::Package> {
        let records: Vec<_> = self
            .history
            .iter()
            .filter_map(|r| r.change.erasure.clone())
            .collect();
        let tip = records
            .last()
            .map(|r| r.id().map_err(Failure::from))
            .transpose()?;
        Ok(crate::evidence_store::erasure::Package {
            version: 1,
            records,
            tip,
        })
    }
    /// Exact matching denies both lagging restores and issuer-only erasures.
    pub fn check_archive(&self, path: &Path, binding: &Binding) -> Result<()> {
        let stored = crate::evidence_store::erasure::read_history(
            path,
            binding.profile.inventory(),
            binding.owner_binding()?,
        )?;
        self.check_package(&stored)
    }
    pub fn check_package(&self, stored: &crate::evidence_store::erasure::Package) -> Result<()> {
        if serde_json::to_vec(stored).map_err(invalid)?
            != serde_json::to_vec(&self.package()?).map_err(invalid)?
        {
            return Err(Failure::AccessLimited);
        }
        Ok(())
    }
}

fn invalid<E>(_: E) -> Failure {
    Failure::Corrupt
}
fn digest(bytes: &[u8]) -> String {
    service::hex(&Sha256::digest(bytes))
}
fn fixed(s: &str) -> Result<()> {
    if s.len() != 64 || service::unhex(s, 32)?.len() != 32 {
        return Err(Failure::Invalid);
    }
    Ok(())
}
fn private(path: &Path, directory: bool, maximum: u64) -> Result<std::fs::Metadata> {
    let m = std::fs::symlink_metadata(path).map_err(|_| Failure::Unavailable)?;
    if m.file_type().is_symlink()
        || (directory && !m.is_dir())
        || (!directory && (!m.is_file() || m.len() > maximum))
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
    Ok(m)
}
impl Change {
    pub fn digest(&self) -> Result<String> {
        Ok(digest(&serde_json::to_vec(self).map_err(invalid)?))
    }
    fn signed_bytes(&self) -> Result<Vec<u8>> {
        Ok([DOMAIN, &serde_json::to_vec(self).map_err(invalid)?].concat())
    }
}
impl Record {
    pub fn sign(change: Change, signer: &Identity) -> Result<Self> {
        if signer.did().as_str() != change.owner {
            return Err(Failure::AccessLimited);
        }
        let signature = service::hex(&signer.sign(&change.signed_bytes()?).map_err(invalid)?);
        Ok(Self { change, signature })
    }
    /// Verify the attributed signature only; current owner authority and chain
    /// membership still come from independently configured Access::current.
    pub(crate) fn verify_signature(&self) -> Result<()> {
        service::author(&self.change.owner)?;
        let signature = service::unhex(&self.signature, 64)?;
        if signature.len() != 64
            || !crate::sign::verify(&self.change.owner, &self.change.signed_bytes()?, &signature)
        {
            return Err(Failure::Corrupt);
        }
        Ok(())
    }
    pub fn id(&self) -> Result<String> {
        Ok(digest(&serde_json::to_vec(self).map_err(invalid)?))
    }
}
impl Access {
    /// Reconcile an inactive restored archive against independently current owner
    /// custody. Keep the shared lease until the final match is checked. This does
    /// not enroll a deployment or purge spools, workspaces and historical backups.
    pub fn reconcile_archive(&self, root: &Path) -> Result<Value> {
        let current = self.current()?;
        let package = current.package()?;
        let path = root.join("archive.sqlite");
        let expected = self.binding.owner_binding()?;
        if let Some(tip) = &package.tip {
            match self.binding.profile {
                crate::evidence_proof_service::Profile::Admitted => {
                    crate::evidence_store::attested::Archive::open(root, expected)?
                        .reconcile_erasure(&package, tip)?;
                }
                crate::evidence_proof_service::Profile::Copied => {
                    crate::evidence_store::copied::Archive::open(root, expected)?
                        .reconcile_erasure(&package, tip)?;
                }
            }
        }
        current.check_archive(&path, &self.binding)?;
        Ok(
            json!({"state":"storage-history-reconciled", "owner_checkpoint":current.tip,
            "storage_tip":package.tip,"erasures":package.records.len(),
            "managed_cleanup":"pending-coordination", "page_reclamation":"not-performed",
            "activation":"not-performed", "backup_purge":"not-performed"}),
        )
    }
    pub fn validate(&self) -> Result<()> {
        if !self.directory.is_absolute() {
            return Err(Failure::Invalid);
        }
        private(&self.directory, true, 0)?;
        self.binding.owner_binding()?;
        service::author(&self.owner)?;
        if let Some(id) = &self.minimum {
            fixed(id)?;
        }
        Ok(())
    }
    /// Initialize a pre-provisioned private directory. The first owner-signed
    /// record is an explicit empty genesis; services require a pinned record.
    pub fn initialize(&self) -> Result<()> {
        self.validate()?;
        let path = self.directory.join("LOCK");
        // surface-write: evidence-erasure-history:LOCK
        crate::persistence::write_new_owner_only(
            crate::persistence::SurfaceWrite::EvidenceErasureHistory,
            &path,
            &[],
        )
        .map_err(|_| Failure::Conflict)?;
        std::fs::File::open(&self.directory)
            .map_err(invalid)?
            .sync_all()
            .map_err(invalid)?;
        Ok(())
    }
    fn lease(&self, exclusive: bool) -> Result<std::fs::File> {
        self.validate()?;
        let path = self.directory.join("LOCK");
        private(&path, false, 0)?;
        let file = std::fs::File::open(path).map_err(invalid)?;
        if exclusive {
            fs4::FileExt::try_lock(&file)
        } else {
            fs4::FileExt::try_lock_shared(&file)
        }
        .map_err(|_| Failure::Unavailable)?;
        Ok(file)
    }
    /// Enrolled services must pin at least genesis, and retain this lease until
    /// their operation completes. Missing custody or rollback fails closed.
    pub fn current(&self) -> Result<Snapshot> {
        if self.minimum.is_none() {
            return Err(Failure::AccessLimited);
        }
        let snapshot = self.read()?;
        if snapshot.history.is_empty() {
            return Err(Failure::AccessLimited);
        }
        Ok(snapshot)
    }
    pub fn read(&self) -> Result<Snapshot> {
        self.read_locked(self.lease(false)?)
    }
    fn read_locked(&self, lease: std::fs::File) -> Result<Snapshot> {
        let mut names = Vec::new();
        let mut pending = 0;
        for entry in std::fs::read_dir(&self.directory).map_err(invalid)? {
            let entry = entry.map_err(invalid)?;
            let name = entry.file_name().into_string().map_err(invalid)?;
            if name == "LOCK" {
                continue;
            }
            if name.starts_with(".pending-") {
                pending += 1;
                if pending > MAX_HISTORY {
                    return Err(Failure::Unavailable);
                }
                continue;
            }
            if !name.starts_with("erasure-")
                || !name.ends_with(".json")
                || names.len() >= MAX_HISTORY
            {
                return Err(Failure::Corrupt);
            }
            names.push(name);
        }
        names.sort();
        let mut history = Vec::new();
        let mut tip = None;
        let mut seen_minimum = self.minimum.is_none();
        let mut total = 0usize;
        let mut storage_tip = None;
        for (index, name) in names.into_iter().enumerate() {
            let path = self.directory.join(&name);
            private(&path, false, MAX_RECORD as u64)?;
            let mut bytes = Vec::new();
            std::fs::File::open(&path)
                .map_err(invalid)?
                .take((MAX_RECORD + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(invalid)?;
            total += bytes.len();
            if bytes.len() > MAX_RECORD || total > MAX_TOTAL {
                return Err(Failure::Unavailable);
            }
            let record: Record = serde_json::from_slice(&bytes).map_err(invalid)?;
            if serde_json::to_vec(&record).map_err(invalid)? != bytes {
                return Err(Failure::Corrupt);
            }
            self.check(&record.change, index, &tip, &storage_tip)?;
            if let Some(erasure) = &record.change.erasure {
                storage_tip = Some(erasure.id()?);
            }
            let sig = service::unhex(&record.signature, 64)?;
            if sig.len() != 64
                || !crate::sign::verify(&self.owner, &record.change.signed_bytes()?, &sig)
            {
                return Err(Failure::Corrupt);
            }
            let id = record.id()?;
            if name != format!("erasure-{index:020}-{id}.json") {
                return Err(Failure::Corrupt);
            }
            seen_minimum |= self.minimum.as_ref() == Some(&id);
            tip = Some(id);
            history.push(record);
        }
        if !seen_minimum {
            return Err(Failure::AccessLimited);
        }
        Ok(Snapshot {
            _lease: lease,
            history,
            tip,
        })
    }
    fn check(
        &self,
        change: &Change,
        sequence: usize,
        previous: &Option<String>,
        storage_tip: &Option<String>,
    ) -> Result<()> {
        if change.version != 1
            || change.binding != self.binding
            || change.owner != self.owner
            || change.sequence != sequence.to_string()
            || &change.previous != previous
        {
            return Err(Failure::Corrupt);
        }
        fixed(&change.nonce)?;
        let time: u64 = change.recorded_at.parse().map_err(|_| Failure::Invalid)?;
        if time.to_string() != change.recorded_at {
            return Err(Failure::Invalid);
        }
        match (&change.erasure, sequence) {
            (None, 0) => {}
            (Some(erasure), n) if n > 0 => {
                erasure.validate(&self.binding.owner_binding()?, storage_tip)?
            }
            _ => return Err(Failure::Invalid),
        }
        Ok(())
    }
    /// The first record must be genesis. Subsequent records authorize exactly
    /// one issuer-signed plan, including the capture selection and pinned tip.
    pub fn preview(
        &self,
        erasure: Option<crate::evidence_store::erasure::Record>,
        nonce: String,
    ) -> Result<Change> {
        let snapshot = self.read()?;
        fixed(&nonce)?;
        if snapshot.history.len() >= MAX_HISTORY {
            return Err(Failure::Unavailable);
        }
        let change = Change {
            version: 1,
            binding: self.binding.clone(),
            owner: self.owner.clone(),
            sequence: snapshot.history.len().to_string(),
            previous: snapshot.tip.clone(),
            nonce,
            recorded_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(invalid)?
                .as_secs()
                .to_string(),
            erasure,
        };
        self.check(
            &change,
            snapshot.history.len(),
            &snapshot.tip,
            &snapshot.package()?.tip,
        )?;
        Ok(change)
    }
    /// Validate a signed compare-and-swap and atomically publish one immutable
    /// record. A lost acknowledgement may retry the same bytes after later edits.
    pub fn append(&self, record: Record) -> Result<Value> {
        let snapshot = self.read_locked(self.lease(true)?)?;
        self.append_locked(record, snapshot)
    }
    /// Prepare and durably journal an owner action while enrolled readers and
    /// ingest writers are excluded. The callback must not reacquire this history.
    /// This closes the preview/publication race for prospective erased admission.
    pub(crate) fn append_prepared(
        &self,
        prepare: impl FnOnce(&Snapshot) -> Result<Record>,
    ) -> Result<Record> {
        if self.minimum.is_none() {
            return Err(Failure::AccessLimited);
        }
        let snapshot = self.read_locked(self.lease(true)?)?;
        if snapshot.history.is_empty() {
            return Err(Failure::AccessLimited);
        }
        let record = prepare(&snapshot)?;
        self.append_locked(record.clone(), snapshot)?;
        Ok(record)
    }
    fn append_locked(&self, record: Record, snapshot: Snapshot) -> Result<Value> {
        let bytes = serde_json::to_vec(&record).map_err(invalid)?;
        if bytes.len() > MAX_RECORD {
            return Err(Failure::Invalid);
        }
        let id = record.id()?;
        if snapshot
            .history
            .iter()
            .any(|r| r.id().ok().as_ref() == Some(&id))
        {
            return Ok(json!({"state":"already-applied","id":id,"current_tip":snapshot.tip}));
        }
        if snapshot.history.len() >= MAX_HISTORY {
            return Err(Failure::Unavailable);
        }
        if record.change.previous != snapshot.tip
            || record.change.sequence != snapshot.history.len().to_string()
        {
            return Err(Failure::Conflict);
        }
        self.check(
            &record.change,
            snapshot.history.len(),
            &snapshot.tip,
            &snapshot.package()?.tip,
        )?;
        let sig = service::unhex(&record.signature, 64)?;
        if sig.len() != 64
            || !crate::sign::verify(&self.owner, &record.change.signed_bytes()?, &sig)
        {
            return Err(Failure::AccessLimited);
        }
        let used: usize = snapshot
            .history
            .iter()
            .map(|r| serde_json::to_vec(r).map(|b| b.len()).unwrap_or(MAX_TOTAL))
            .sum();
        if used + bytes.len() > MAX_TOTAL {
            return Err(Failure::Unavailable);
        }
        let mut package = snapshot.package()?;
        if let Some(erasure) = &record.change.erasure {
            package.records.push(erasure.clone());
            package.tip = Some(erasure.id()?);
        }
        // Do not publish a custody head which the bounded storage history cannot install.
        let mut objects = std::collections::BTreeMap::new();
        for record in &package.records {
            for target in &record.plan.targets {
                if let Some(old) = objects.insert(&target.object, target) {
                    if old != target {
                        return Err(Failure::Conflict);
                    }
                }
            }
        }
        if serde_json::to_vec(&package).map_err(invalid)?.len() > 16 * 1024 * 1024
            || objects.len() > 32768
        {
            return Err(Failure::Unavailable);
        }
        let destination = self
            .directory
            .join(format!("erasure-{:020}-{id}.json", snapshot.history.len()));
        if std::fs::symlink_metadata(&destination).is_ok() {
            return Err(Failure::Conflict);
        }
        let temporary = self.directory.join(format!(
            ".pending-{}",
            service::hex(&rand::random::<[u8; 32]>())
        ));
        // surface-write: evidence-erasure-history:.pending-*
        crate::persistence::write_new_owner_only(
            crate::persistence::SurfaceWrite::EvidenceErasureHistory,
            &temporary,
            &bytes,
        )
        .map_err(invalid)?;
        // surface-write: evidence-erasure-history:.pending-*,evidence-erasure-history:erasure-*.json
        crate::persistence::rename(
            crate::persistence::SurfaceWrite::EvidenceErasureHistory,
            &temporary,
            &destination,
        )
        .map_err(invalid)?;
        std::fs::File::open(&self.directory)
            .map_err(invalid)?
            .sync_all()
            .map_err(invalid)?;
        Ok(json!({"state":"applied","id":id,"current_tip":id,"sequence":record.change.sequence}))
    }
}

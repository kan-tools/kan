//! Signed immutable encryption epochs, wrapped to an independent recovery key.
//! Storage and capture need public metadata only; unlocking belongs to the reader.
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
const DOMAIN: &[u8] = b"tools.kan.archive.key-epoch.v1\0";
const MAX_RECORD: usize = 65536;
const MAX_HISTORY: usize = 64;
const MAX_TOTAL: usize = 128 * 1024;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Access {
    pub directory: PathBuf,
    pub binding: Binding,
    pub owner: String,
    pub recovery_recipient: String,
    #[serde(default)]
    pub minimum: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Change {
    pub version: u8,
    pub binding: Binding,
    pub owner: String,
    pub recovery_recipient: String,
    pub sequence: String,
    pub previous: Option<String>,
    pub nonce: String,
    pub recorded_at: String,
    pub recipient: String,
    pub wrapped: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<KeyOrigin>,
}
/// Signed provenance retained when existing epoch custody is transferred.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyOrigin {
    pub record: String,
    pub tip: String,
    pub recovery_recipient: String,
    pub purpose: TransferPurpose,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransferPurpose {
    ReplaceRecovery,
    ShareEpochs,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferPlan {
    pub binding: Binding,
    pub owner: String,
    pub source_recipient: String,
    pub source_tip: String,
    pub recipient: String,
    pub epochs: Vec<String>,
    pub purpose: TransferPurpose,
    pub nonce: String,
}
impl TransferPlan {
    pub fn digest(&self) -> Result<String> {
        Ok(digest(&serde_json::to_vec(self).map_err(invalid)?))
    }
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
    pub fn current(&self) -> Result<String> {
        self.history
            .last()
            .map(|r| r.change.recipient.clone())
            .ok_or(Failure::AccessLimited)
    }
    pub fn value(&self) -> Value {
        json!({"tip":self.tip,"epochs":self.history.len(),"current_recipient":self.history.last().map(|r| &r.change.recipient),"history":self.history,"retention":"All epoch keys retained under independent recovery wrapping. Rotation does not erase earlier evidence or recall distributed keys."})
    }
    pub fn unlock(&self, private: &[u8; 32]) -> Result<Vec<[u8; 32]>> {
        self.history
            .iter()
            .map(|r| r.change.unlock(private))
            .collect()
    }
}
fn invalid<E>(_: E) -> Failure {
    Failure::Corrupt
}
fn wrapping_scope(binding: &Binding) -> Result<[u8; 32]> {
    binding.owner_binding()?;
    let mut hash = Sha256::new();
    hash.update(b"tools.kan.archive.epoch-wrapping.v1\0");
    hash.update(serde_json::to_vec(binding).map_err(invalid)?);
    Ok(hash.finalize().into())
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
    if !cfg!(unix) {
        return Err(Failure::Invalid);
    }
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
fn unchanged(before: &std::fs::Metadata, file: &std::fs::File) -> Result<()> {
    let actual = file.metadata().map_err(invalid)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if !actual.is_file()
            || actual.permissions().mode() & 0o077 != 0
            || actual.nlink() != 1
            || actual.dev() != before.dev()
            || actual.ino() != before.ino()
        {
            return Err(Failure::Invalid);
        }
    }
    Ok(())
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
    pub fn id(&self) -> Result<String> {
        Ok(digest(&serde_json::to_vec(self).map_err(invalid)?))
    }
}
impl Access {
    pub fn validate(&self) -> Result<()> {
        if !self.directory.is_absolute() {
            return Err(Failure::Invalid);
        }
        private(&self.directory, true, 0)?;
        self.binding.owner_binding()?;
        service::author(&self.owner)?;
        fixed(&self.recovery_recipient)?;
        if let Some(id) = &self.minimum {
            fixed(id)?;
        }
        Ok(())
    }
    /// Initialize an existing private directory. No epoch is active yet.
    pub fn initialize(&self) -> Result<()> {
        self.validate()?;
        let path = self.directory.join("LOCK");
        // surface-write: evidence-keys:LOCK
        crate::persistence::write_new_owner_only(
            crate::persistence::SurfaceWrite::EvidenceKeys,
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
        let before = private(&path, false, 0)?;
        let file = std::fs::File::open(path).map_err(invalid)?;
        unchanged(&before, &file)?;
        if exclusive {
            fs4::FileExt::try_lock(&file)
        } else {
            fs4::FileExt::try_lock_shared(&file)
        }
        .map_err(|_| Failure::Unavailable)?;
        Ok(file)
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
            if !name.starts_with("epoch-") || !name.ends_with(".json") || names.len() >= MAX_HISTORY
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
        for (index, name) in names.into_iter().enumerate() {
            let path = self.directory.join(&name);
            let before = private(&path, false, MAX_RECORD as u64)?;
            let file = std::fs::File::open(&path).map_err(invalid)?;
            unchanged(&before, &file)?;
            let mut bytes = Vec::new();
            file.take((MAX_RECORD + 1) as u64)
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
            self.check(&record.change, index, &tip)?;
            if history
                .iter()
                .any(|r: &Record| r.change.recipient == record.change.recipient)
            {
                return Err(Failure::Corrupt);
            }
            let sig = service::unhex(&record.signature, 64)?;
            if sig.len() != 64
                || !crate::sign::verify(&self.owner, &record.change.signed_bytes()?, &sig)
            {
                return Err(Failure::Corrupt);
            }
            let id = record.id()?;
            if name != format!("epoch-{index:020}-{id}.json") {
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
    fn check(&self, change: &Change, sequence: usize, previous: &Option<String>) -> Result<()> {
        if change.version != 1
            || change.binding != self.binding
            || change.owner != self.owner
            || change.recovery_recipient != self.recovery_recipient
            || change.sequence != sequence.to_string()
            || &change.previous != previous
        {
            return Err(Failure::Corrupt);
        }
        if let Some(origin) = &change.origin {
            fixed(&origin.record)?;
            fixed(&origin.tip)?;
            fixed(&origin.recovery_recipient)?;
        }
        fixed(&change.nonce)?;
        let time: u64 = change.recorded_at.parse().map_err(|_| Failure::Invalid)?;
        if time.to_string() != change.recorded_at {
            return Err(Failure::Invalid);
        }
        fixed(&change.recipient)?;
        let bytes = service::unhex(&change.wrapped, 1024)?;
        let recipient = crate::evidence_crypto::recipient_id(&bytes).map_err(invalid)?;
        if recipient != Sha256::digest(service::unhex(&self.recovery_recipient, 32)?).as_slice() {
            return Err(Failure::Corrupt);
        }
        Ok(())
    }
    pub fn preview(&self, nonce: String) -> Result<Change> {
        let snapshot = self.read()?;
        fixed(&nonce)?;
        if snapshot.history.len() >= MAX_HISTORY {
            return Err(Failure::Unavailable);
        }
        let private = rand::random::<[u8; 32]>();
        let recipient = crate::evidence_crypto::public_key(&private).map_err(invalid)?;
        let recovery: [u8; 32] = service::unhex(&self.recovery_recipient, 32)?
            .try_into()
            .map_err(invalid)?;
        let wrapped =
            crate::evidence_crypto::seal(&recovery, &wrapping_scope(&self.binding)?, &private)
                .map_err(invalid)?;
        Ok(Change {
            version: 1,
            binding: self.binding.clone(),
            owner: self.owner.clone(),
            recovery_recipient: self.recovery_recipient.clone(),
            sequence: snapshot.history.len().to_string(),
            previous: snapshot.tip,
            nonce,
            recorded_at: crate::evidence_operations::now().to_string(),
            recipient: service::hex(&recipient),
            wrapped: service::hex(&wrapped),
            origin: None,
        })
    }
    /// Preview is metadata only: it never distributes wrapped epoch keys.
    pub fn preview_transfer(
        &self,
        recipient: String,
        epochs: Vec<String>,
        purpose: TransferPurpose,
    ) -> Result<TransferPlan> {
        let snapshot = self.read()?;
        let plan = TransferPlan {
            binding: self.binding.clone(),
            owner: self.owner.clone(),
            source_recipient: self.recovery_recipient.clone(),
            source_tip: snapshot.tip.clone().ok_or(Failure::Invalid)?,
            recipient,
            epochs,
            purpose,
            nonce: service::hex(&rand::random::<[u8; 32]>()),
        };
        self.check_transfer(&snapshot, &plan)?;
        Ok(plan)
    }
    fn check_transfer(&self, snapshot: &Snapshot, plan: &TransferPlan) -> Result<()> {
        fixed(&plan.recipient)?;
        fixed(&plan.nonce)?;
        if plan.binding != self.binding
            || plan.owner != self.owner
            || plan.source_recipient != self.recovery_recipient
            || plan.recipient == self.recovery_recipient
            || snapshot.tip.as_ref() != Some(&plan.source_tip)
        {
            return Err(Failure::Conflict);
        }
        let all = snapshot
            .history
            .iter()
            .map(Record::id)
            .collect::<Result<Vec<_>>>()?;
        let selected = all
            .iter()
            .filter(|id| plan.epochs.contains(id))
            .cloned()
            .collect::<Vec<_>>();
        // Exact canonical order disallows duplicates, unknown IDs and silent omissions.
        if plan.epochs.is_empty()
            || selected != plan.epochs
            || (plan.purpose == TransferPurpose::ReplaceRecovery && selected != all)
        {
            return Err(Failure::Invalid);
        }
        Ok(())
    }
    /// Export selected existing keys under new custody. Original history is
    /// unchanged; activation and storage permissions are separate owner actions.
    pub fn transfer(
        &self,
        plan: &TransferPlan,
        preview: &str,
        private: &[u8; 32],
        signer: &Identity,
    ) -> Result<Value> {
        if plan.digest()? != preview || signer.did().as_str() != self.owner {
            return Err(Failure::AccessLimited);
        }
        let snapshot = self.read()?; // Hold the lease through signing and wrapping.
        self.check_transfer(&snapshot, plan)?;
        let recipient: [u8; 32] = service::unhex(&plan.recipient, 32)?
            .try_into()
            .map_err(invalid)?;
        let mut records = Vec::new();
        let mut tip = None;
        for source in &snapshot.history {
            let id = source.id()?;
            if !plan.epochs.contains(&id) {
                continue;
            }
            let key = source.change.unlock(private)?;
            let wrapped =
                crate::evidence_crypto::seal(&recipient, &wrapping_scope(&self.binding)?, &key)
                    .map_err(invalid)?;
            let record = Record::sign(
                Change {
                    version: 1,
                    binding: self.binding.clone(),
                    owner: self.owner.clone(),
                    recovery_recipient: plan.recipient.clone(),
                    sequence: records.len().to_string(),
                    previous: tip,
                    nonce: plan.nonce.clone(),
                    recorded_at: crate::evidence_operations::now().to_string(),
                    recipient: source.change.recipient.clone(),
                    wrapped: service::hex(&wrapped),
                    origin: Some(KeyOrigin {
                        record: id,
                        tip: plan.source_tip.clone(),
                        recovery_recipient: self.recovery_recipient.clone(),
                        purpose: plan.purpose,
                    }),
                },
                signer,
            )?;
            tip = Some(record.id()?);
            records.push(record);
        }
        Ok(
            json!({"version":"kan-key-recovery/1","binding":self.binding,"owner":self.owner,
            "recovery_recipient":plan.recipient,"tip":tip,"records":records}),
        )
    }
    /// The package contains only signed public metadata and wrapped private keys.
    pub fn export(&self) -> Result<Value> {
        let snapshot = self.read()?;
        Ok(
            json!({"version":"kan-key-recovery/1","binding":self.binding,"owner":self.owner,"recovery_recipient":self.recovery_recipient,"tip":snapshot.tip,"records":snapshot.history}),
        )
    }
    /// Restore the exact verified history into a separately configured directory.
    /// Repeating after interruption accepts only an identical existing prefix.
    pub fn verify_package(&self, package: &RecoveryPackage) -> Result<()> {
        self.validate()?;
        if package.version != "kan-key-recovery/1"
            || package.binding != self.binding
            || package.owner != self.owner
            || package.recovery_recipient != self.recovery_recipient
            || package.records.is_empty()
            || package.records.len() > MAX_HISTORY
            || serde_json::to_vec(package).map_err(invalid)?.len() > MAX_TOTAL
        {
            return Err(Failure::Invalid);
        }
        let mut recipients = std::collections::BTreeSet::new();
        let mut previous = None;
        let mut witnessed = self.minimum.is_none();
        for (index, record) in package.records.iter().enumerate() {
            self.check(&record.change, index, &previous)?;
            if !recipients.insert(&record.change.recipient) {
                return Err(Failure::Corrupt);
            }
            let sig = service::unhex(&record.signature, 64)?;
            if !crate::sign::verify(&self.owner, &record.change.signed_bytes()?, &sig) {
                return Err(Failure::Corrupt);
            }
            previous = Some(record.id()?);
            witnessed |= self.minimum == previous;
        }
        if previous != package.tip || !witnessed {
            return Err(Failure::AccessLimited);
        }
        Ok(())
    }
    pub fn restore(&self, package: &RecoveryPackage) -> Result<Value> {
        self.verify_package(package)?;
        let mut destination = self.clone();
        destination.minimum = None;
        let current = destination.read()?;
        if current.history.len() > package.records.len()
            || current
                .history
                .iter()
                .zip(&package.records)
                .any(|(a, b)| a.id().ok() != b.id().ok())
        {
            return Err(Failure::Conflict);
        }
        drop(current);
        for record in &package.records {
            destination.append(record.clone())?;
        }
        let restored = self.read()?;
        if restored.tip != package.tip {
            return Err(Failure::Conflict);
        }
        Ok(
            json!({"state":"restored","tip":restored.tip,"epochs":restored.history.len(),"activated":false}),
        )
    }
    /// Validate a signed compare-and-swap and atomically publish one immutable
    /// record. A lost acknowledgement may retry the same bytes after later edits.
    pub fn append(&self, record: Record) -> Result<Value> {
        let snapshot = self.read_locked(self.lease(true)?)?;
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
        self.check(&record.change, snapshot.history.len(), &snapshot.tip)?;
        if snapshot
            .history
            .iter()
            .any(|r| r.change.recipient == record.change.recipient)
        {
            return Err(Failure::Conflict);
        }
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
        let destination = self
            .directory
            .join(format!("epoch-{:020}-{id}.json", snapshot.history.len()));
        if std::fs::symlink_metadata(&destination).is_ok() {
            return Err(Failure::Conflict);
        }
        let temporary = self.directory.join(format!(
            ".pending-{}",
            service::hex(&rand::random::<[u8; 32]>())
        ));
        // surface-write: evidence-keys:.pending-*
        crate::persistence::write_new_owner_only(
            crate::persistence::SurfaceWrite::EvidenceKeys,
            &temporary,
            &bytes,
        )
        .map_err(invalid)?;
        // surface-write: evidence-keys:.pending-*,evidence-keys:epoch-*.json
        crate::persistence::rename(
            crate::persistence::SurfaceWrite::EvidenceKeys,
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
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPackage {
    pub version: String,
    pub binding: Binding,
    pub owner: String,
    pub recovery_recipient: String,
    pub tip: Option<String>,
    pub records: Vec<Record>,
}
impl Change {
    /// Verify recovery custody and public/private correspondence before use.
    pub fn unlock(&self, private: &[u8; 32]) -> Result<[u8; 32]> {
        if service::hex(&crate::evidence_crypto::public_key(private).map_err(invalid)?)
            != self.recovery_recipient
        {
            return Err(Failure::AccessLimited);
        }
        let wrapped = service::unhex(&self.wrapped, 1024)?;
        let key: [u8; 32] =
            crate::evidence_crypto::open(private, &wrapping_scope(&self.binding)?, &wrapped)
                .map_err(invalid)?
                .try_into()
                .map_err(invalid)?;
        if service::hex(&crate::evidence_crypto::public_key(&key).map_err(invalid)?)
            != self.recipient
        {
            return Err(Failure::Corrupt);
        }
        Ok(key)
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReaderAccess {
    pub history: Access,
    pub recovery_key: PathBuf,
}
impl ReaderAccess {
    pub fn keys(&self) -> Result<Vec<[u8; 32]>> {
        if !self.recovery_key.is_absolute() {
            return Err(Failure::Invalid);
        }
        let private = crate::evidence_crypto::read_private_key(&self.recovery_key)
            .map_err(|_| Failure::AccessLimited)?;
        if service::hex(&crate::evidence_crypto::public_key(&private).map_err(invalid)?)
            != self.history.recovery_recipient
        {
            return Err(Failure::AccessLimited);
        }
        self.history.read()?.unlock(&private)
    }
}

//! Owner-pinned live grants. Public policy signatures never confer decryption
//! or administration. Files are immutable; readers hold a shared policy lease.
use crate::{
    evidence_proof_service::Binding,
    evidence_service::{self as service, Failure, Grant},
    file_lease::FileLease,
    sign::Identity,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::Read,
    path::{Path, PathBuf},
};
type Result<T> = std::result::Result<T, Failure>;
const DOMAIN: &[u8] = b"tools.kan.access.policy.v1\0";
const MAX_RECORD: usize = 65536;
const MAX_PENDING: usize = 1024;
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
    pub grants: Vec<Grant>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub change: Change,
    pub signature: String,
}
pub struct Current {
    _lease: FileLease,
    record: Record,
}
impl Current {
    pub fn grants(&self) -> Result<Vec<Grant>> {
        Ok(self.record.change.grants.clone())
    }
}
pub struct Snapshot {
    _lease: FileLease,
    pub history: Vec<Record>,
    pub tip: Option<String>,
}
impl Snapshot {
    pub fn grants(&self) -> Result<Vec<Grant>> {
        self.history
            .last()
            .map(|r| r.change.grants.clone())
            .ok_or(Failure::AccessLimited)
    }
    pub fn value(&self) -> Value {
        json!({"tip":self.tip,"changes":self.history.len(),"current":self.history.last(),"retention":"All policy history retained; removing a grant does not recall previously obtained plaintext or keys."})
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
        if let Some(id) = &self.minimum {
            fixed(id)?;
        }
        Ok(())
    }
    /// Explicitly initialize a pre-provisioned private directory. No grants exist
    /// until an owner signs the first policy; readers fail closed meanwhile.
    pub fn initialize(&self) -> Result<()> {
        self.validate()?;
        let path = self.directory.join("LOCK");
        // surface-write: evidence-policy:LOCK
        crate::persistence::write_new_owner_only(
            crate::persistence::SurfaceWrite::EvidencePolicy,
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
    fn lease(&self, exclusive: bool) -> Result<FileLease> {
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
        Ok(FileLease(file))
    }
    pub fn read(&self) -> Result<Snapshot> {
        self.read_locked(self.lease(false)?)
    }
    fn read_locked(&self, lease: FileLease) -> Result<Snapshot> {
        let mut names = Vec::new();
        let mut pending = 0;
        for entry in std::fs::read_dir(&self.directory).map_err(invalid)? {
            let entry = entry.map_err(invalid)?;
            let name = entry.file_name().into_string().map_err(invalid)?;
            if name == "LOCK" || crate::evidence_control_index::reserved(&name) {
                continue;
            }
            if name.starts_with(".pending-") {
                pending += 1;
                if pending > MAX_PENDING {
                    return Err(Failure::Unavailable);
                }
                continue;
            }
            if !name.starts_with("policy-") || !name.ends_with(".json") {
                return Err(Failure::Corrupt);
            }
            names.push(name);
        }
        names.sort();
        let mut history = Vec::new();
        let mut tip = None;
        let mut seen_minimum = self.minimum.is_none();
        for (index, name) in names.into_iter().enumerate() {
            let path = self.directory.join(&name);
            private(&path, false, MAX_RECORD as u64)?;
            let mut bytes = Vec::new();
            std::fs::File::open(&path)
                .map_err(invalid)?
                .take((MAX_RECORD + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(invalid)?;
            if bytes.len() > MAX_RECORD {
                return Err(Failure::Unavailable);
            }
            let record: Record = serde_json::from_slice(&bytes).map_err(invalid)?;
            if serde_json::to_vec(&record).map_err(invalid)? != bytes {
                return Err(Failure::Corrupt);
            }
            self.check(&record.change, index, &tip)?;
            let sig = service::unhex(&record.signature, 64)?;
            if sig.len() != 64
                || !crate::sign::verify(&self.owner, &record.change.signed_bytes()?, &sig)
            {
                return Err(Failure::Corrupt);
            }
            let id = record.id()?;
            if name != format!("policy-{index:020}-{id}.json") {
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
        let normalized = normalize(change.grants.clone())?;
        if serde_json::to_vec(&normalized).map_err(invalid)?
            != serde_json::to_vec(&change.grants).map_err(invalid)?
        {
            return Err(Failure::Corrupt);
        }
        Ok(())
    }
    pub fn preview(&self, grants: Vec<Grant>, nonce: String) -> Result<Change> {
        let snapshot = self.read()?;
        fixed(&nonce)?;
        Ok(Change {
            version: 1,
            binding: self.binding.clone(),
            owner: self.owner.clone(),
            sequence: snapshot.history.len().to_string(),
            previous: snapshot.tip,
            nonce,
            recorded_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(invalid)?
                .as_secs()
                .to_string(),
            grants: normalize(grants)?,
        })
    }
    /// Validate a signed compare-and-swap and atomically publish one immutable
    /// record. A lost acknowledgement may retry the same bytes after later edits.
    pub fn append(&self, record: Record) -> Result<Value> {
        let snapshot = self.read_locked(self.lease(true)?)?;
        if crate::evidence_control_index::enabled(&self.directory)? {
            return Err(Failure::Conflict);
        }
        self.append_locked(record, &snapshot)
    }
    pub fn append_with_checkpoint(&self, record: Record, signer: &Identity) -> Result<Value> {
        if signer.did().as_str() != self.owner {
            return Err(Failure::AccessLimited);
        }
        let snapshot = self.read_locked(self.lease(true)?)?;
        let indexed = crate::evidence_control_index::enabled(&self.directory)?;
        let result = self.append_locked(record, &snapshot)?;
        if indexed {
            let current = self.read_locked(snapshot._lease)?;
            crate::evidence_control_index::rebuild(
                &self.directory,
                "policy",
                &self.binding,
                signer,
                current.history.iter().map(Record::id),
            )?;
        }
        Ok(result)
    }
    pub fn rebuild_serving_index(&self, signer: &Identity) -> Result<()> {
        if signer.did().as_str() != self.owner {
            return Err(Failure::AccessLimited);
        }
        let snapshot = self.read_locked(self.lease(true)?)?;
        if snapshot.history.is_empty() {
            return Err(Failure::AccessLimited);
        }
        crate::evidence_control_index::rebuild(
            &self.directory,
            "policy",
            &self.binding,
            signer,
            snapshot.history.iter().map(Record::id),
        )
    }
    /// Current grants use a bounded signed checkpoint when explicitly initialized.
    /// Legacy control directories retain their full audit until owner migration.
    pub fn current(&self) -> Result<Current> {
        let lease = self.lease(false)?;
        if !crate::evidence_control_index::enabled(&self.directory)? {
            let snapshot = self.read_locked(lease)?;
            let record = snapshot
                .history
                .last()
                .cloned()
                .ok_or(Failure::AccessLimited)?;
            return Ok(Current {
                _lease: snapshot._lease,
                record,
            });
        }
        let head = crate::evidence_control_index::current(
            &self.directory,
            "policy",
            &self.binding,
            &self.owner,
            self.minimum.as_deref(),
            MAX_RECORD,
        )?;
        let record: Record = serde_json::from_slice(&head.record).map_err(invalid)?;
        if serde_json::to_vec(&record).map_err(invalid)? != head.record || record.id()? != head.tip
        {
            return Err(Failure::Corrupt);
        }
        self.check(
            &record.change,
            usize::try_from(head.count - 1).map_err(invalid)?,
            &record.change.previous,
        )?;
        let sig = service::unhex(&record.signature, 64)?;
        if !crate::sign::verify(&self.owner, &record.change.signed_bytes()?, &sig) {
            return Err(Failure::Corrupt);
        }
        Ok(Current {
            _lease: lease,
            record,
        })
    }
    fn append_locked(&self, record: Record, snapshot: &Snapshot) -> Result<Value> {
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
        if record.change.previous != snapshot.tip
            || record.change.sequence != snapshot.history.len().to_string()
        {
            return Err(Failure::Conflict);
        }
        self.check(&record.change, snapshot.history.len(), &snapshot.tip)?;
        let sig = service::unhex(&record.signature, 64)?;
        if sig.len() != 64
            || !crate::sign::verify(&self.owner, &record.change.signed_bytes()?, &sig)
        {
            return Err(Failure::AccessLimited);
        }
        let destination = self
            .directory
            .join(format!("policy-{:020}-{id}.json", snapshot.history.len()));
        if std::fs::symlink_metadata(&destination).is_ok() {
            return Err(Failure::Conflict);
        }
        if crate::evidence_control_index::enabled(&self.directory)? {
            crate::evidence_control_index::invalidate(&self.directory)?;
        }
        let temporary = self.directory.join(format!(
            ".pending-{}",
            service::hex(&rand::random::<[u8; 32]>())
        ));
        // surface-write: evidence-policy:.pending-*
        crate::persistence::write_new_owner_only(
            crate::persistence::SurfaceWrite::EvidencePolicy,
            &temporary,
            &bytes,
        )
        .map_err(invalid)?;
        // surface-write: evidence-policy:.pending-*,evidence-policy:policy-*.json
        crate::persistence::rename(
            crate::persistence::SurfaceWrite::EvidencePolicy,
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
fn normalize(mut grants: Vec<Grant>) -> Result<Vec<Grant>> {
    if grants.len() > 256 {
        return Err(Failure::Invalid);
    }
    let mut seen = BTreeSet::new();
    for grant in &grants {
        service::author(&grant.principal)?;
        if !seen.insert(&grant.principal) {
            return Err(Failure::Invalid);
        }
    }
    grants.sort_by(|a, b| a.principal.cmp(&b.principal));
    Ok(grants)
}

#[cfg(all(test, unix))]
mod lease_tests {
    use super::*;
    fn access(directory: &Path) -> Access {
        use std::os::unix::fs::PermissionsExt;
        // Test-only fixture: real custody requires a private directory.
        // surface-write: container:workspace
        crate::persistence::set_permissions(
            crate::persistence::SurfaceWrite::Container,
            directory,
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let owner = Identity::generate().did().to_string();
        let access = Access {
            directory: directory.to_owned(),
            binding: Binding {
                profile: crate::evidence_proof_service::Profile::Admitted,
                archive: service::hex(&[2; 32]),
                scope: service::hex(&[1; 32]),
                issuer: owner.clone(),
            },
            owner,
            minimum: None,
        };
        access.initialize().unwrap();
        access
    }
    #[test]
    fn snapshot_ownership_retains_independent_readers_and_releases_inherited_descriptor() {
        let dir = tempfile::tempdir().unwrap();
        let access = access(dir.path());
        let first = access.read().unwrap();
        let inherited = first._lease.0.try_clone().unwrap();
        let other = access.read().unwrap();
        drop(first);
        assert!(matches!(access.lease(true), Err(Failure::Unavailable)));
        drop(other);
        let replacement = access.lease(true).unwrap();
        drop(inherited);
        assert!(matches!(access.read(), Err(Failure::Unavailable)));
        drop(replacement);
        access.read().unwrap();
    }
    #[test]
    fn rejected_history_releases_moved_lease_but_not_an_independent_reader() {
        let dir = tempfile::tempdir().unwrap();
        let access = access(dir.path());
        let other = access.read().unwrap();
        let lease = access.lease(false).unwrap();
        let inherited = lease.0.try_clone().unwrap();
        let mut unsupported = access.clone();
        unsupported.minimum = Some(service::hex(&[9; 32]));
        assert!(matches!(
            unsupported.read_locked(lease),
            Err(Failure::AccessLimited)
        ));
        assert!(matches!(access.lease(true), Err(Failure::Unavailable)));
        drop(other);
        let replacement = access.lease(true).unwrap();
        drop(inherited);
        assert!(matches!(access.read(), Err(Failure::Unavailable)));
        drop(replacement);
        access.read().unwrap();
    }
}

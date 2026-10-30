//! Explicit purge of one verified completed backup output. Authorization and
//! progress stay in the encrypted owner journal; no source archive is modified.
use super::*;
use crate::file_lease::FileLease;
use std::{
    io::Read,
    time::{Duration, Instant},
};
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    version: u8,
    backup_job: String,
    database: PathBuf,
    binding: Binding,
    bytes: String,
    sha256: String,
    nonce: String,
}
fn unavailable<E>(_: E) -> Failure {
    Failure::Unavailable
}
fn private_file(path: &Path) -> Result<FileLease, Failure> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            Failure::Missing
        } else {
            Failure::Unavailable
        }
    })?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(Failure::Invalid);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.mode() & 0o077 != 0 || meta.nlink() != 1 {
            return Err(Failure::Invalid);
        }
    }
    let file = std::fs::File::open(path).map_err(unavailable)?;
    // macOS coordinates flock with SQLite's locks: hold a shared lock while
    // opening read-only verification, then upgrade after that connection closes.
    fs4::FileExt::try_lock_shared(&file).map_err(|_| Failure::Conflict)?;
    let file = FileLease(file);
    same_file(path, &file.0)?;
    Ok(file)
}
fn same_file(path: &Path, file: &std::fs::File) -> Result<(), Failure> {
    let actual = std::fs::symlink_metadata(path).map_err(unavailable)?;
    let opened = file.metadata().map_err(unavailable)?;
    if !actual.is_file() || actual.file_type().is_symlink() || actual.len() != opened.len() {
        return Err(Failure::Conflict);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if actual.dev() != opened.dev() || actual.ino() != opened.ino() || actual.nlink() != 1 {
            return Err(Failure::Conflict);
        }
    }
    Ok(())
}
fn inspected(path: &Path, binding: &Binding) -> Result<(FileLease, String, String), Failure> {
    let mut file = private_file(path)?;
    // A completed backup is a standalone snapshot. Never destroy an active
    // SQLite database or discard a pending journal to make it appear complete.
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = path.as_os_str().to_owned();
        sidecar.push(suffix);
        match std::fs::symlink_metadata(PathBuf::from(sidecar)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err(Failure::Conflict),
        }
    }
    match binding.profile {
        Profile::Admitted => {
            store::attested::Archive::verify_file(path, binding.owner_binding()?)?;
        }
        Profile::Copied => {
            store::copied::Archive::verify_file(path, binding.owner_binding()?)?;
        }
    }
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut hash = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        if Instant::now() >= deadline {
            return Err(Failure::Unavailable);
        }
        let n = file.0.read(&mut buffer).map_err(unavailable)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
        bytes = bytes.checked_add(n as u64).ok_or(Failure::Unavailable)?;
    }
    same_file(path, &file.0)?;
    if file.0.metadata().map_err(unavailable)?.len() != bytes {
        return Err(Failure::Conflict);
    }
    Ok((file, bytes.to_string(), service::hex(&hash.finalize())))
}
fn phase(id: &str, n: usize, name: &str) -> String {
    format!("backup-purge:{id}:{n}:{name}")
}
fn stage(plan: &Plan, id: &str) -> Result<PathBuf, Failure> {
    Ok(plan
        .database
        .parent()
        .ok_or(Failure::Invalid)?
        .join(format!(".kan-purge-{id}")))
}
impl Owner {
    fn backup_target(&self, id: &str) -> Result<(Target, PathBuf, Binding), Failure> {
        fixed(id)?;
        let job = self
            .workspace
            .get("owner-job", id)?
            .ok_or(Failure::Missing)?;
        let contract = &job["contract"];
        if Self::hash(contract)? != id
            || contract["operation"] != "backup"
            || self
                .workspace
                .get("owner-result", id)?
                .is_none_or(|r| r["state"] != "succeeded")
        {
            return Err(Failure::Invalid);
        }
        let target_id = contract["target"]["id"].as_str().ok_or(Failure::Corrupt)?;
        let target = self
            .targets
            .get(target_id)
            .ok_or(Failure::AccessLimited)?
            .clone();
        if serde_json::to_value(&target).map_err(unavailable)? != contract["target"] {
            return Err(Failure::Conflict);
        }
        let Target::Archive {
            output,
            binding: Some(binding),
            ..
        } = &target
        else {
            return Err(Failure::Invalid);
        };
        let nonce = contract["nonce"].as_str().ok_or(Failure::Corrupt)?;
        fixed(nonce)?;
        let database = output.join(format!("{nonce}.sqlite"));
        if contract["destination"] != json!(database) {
            return Err(Failure::Corrupt);
        }
        private_directory(output)?;
        Ok((target.clone(), database, binding.clone()))
    }
    fn purge_plan(&self, backup_job: &str, nonce: &str) -> Result<Plan, Failure> {
        fixed(nonce)?;
        let (_, database, binding) = self.backup_target(backup_job)?;
        let (_held, bytes, sha256) = inspected(&database, &binding)?;
        Ok(Plan {
            version: 1,
            backup_job: backup_job.into(),
            database,
            binding,
            bytes,
            sha256,
            nonce: nonce.into(),
        })
    }
    fn purge_contract(&self, plan: &Plan) -> Result<Value, Failure> {
        let (target, database, binding) = self.backup_target(&plan.backup_job)?;
        if plan.version != 1 || plan.database != database || plan.binding != binding {
            return Err(Failure::Invalid);
        }
        fixed(&plan.sha256)?;
        fixed(&plan.nonce)?;
        Ok(
            json!({"version":1,"operation":"purge-backup","target":target,"plan":plan,
            "effect":"Delete this entire verified backup copy, including unrelated content within it. Preserve the source archive, all other backups, recovery keys and this minimal owner receipt. This does not promise physical or cryptographic erasure of snapshots or off-host copies.",
            "cancellation":"Once accepted, deletion cannot be rolled back. An interrupted purge resumes only this exact retained plan."}),
        )
    }
    pub(super) async fn preview_backup_purge(
        self: &Arc<Self>,
        backup_job: String,
    ) -> Result<Value, Failure> {
        let permit = self
            .preparation
            .clone()
            .try_acquire_owned()
            .map_err(|_| Failure::Unavailable)?;
        let owner = self.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let plan = owner.purge_plan(&backup_job, &service::hex(&rand::random::<[u8; 32]>()))?;
            let contract = owner.purge_contract(&plan)?;
            Ok(json!({"plan":plan,"digest":Self::hash(&contract)?,"contract":contract}))
        })
        .await
        .map_err(unavailable)?
    }
    pub(super) fn backup_purge_status(&self, job: Value) -> Result<Value, Failure> {
        let id = job["id"].as_str().ok_or(Failure::Corrupt)?;
        let attempts = first_unused(|n| {
            Ok(self
                .workspace
                .get("owner-result", &phase(id, n, "started"))?
                .is_some())
        })?;
        let result = if attempts == 0 {
            None
        } else {
            self.workspace
                .get("owner-result", &phase(id, attempts - 1, "finished"))?
        };
        let interrupted = result.is_none();
        let running = self
            .active
            .lock()
            .map_err(unavailable)?
            .get(id)
            .is_some_and(|h| !h.is_finished());
        let succeeded = result.as_ref().is_some_and(|r| r["state"] == "succeeded");
        let state = if running {
            "running"
        } else if interrupted || attempts == 0 {
            "interrupted"
        } else if succeeded {
            "succeeded"
        } else {
            "purge-pending"
        };
        Ok(
            json!({"job":job,"state":state,"result":result,"attempts":attempts,"resumable":!succeeded}),
        )
    }
    pub(super) async fn apply_backup_purge(
        self: &Arc<Self>,
        plan: Plan,
        preview: String,
        wait: bool,
    ) -> Result<Value, Failure> {
        let contract = self.purge_contract(&plan)?;
        let id = Self::hash(&contract)?;
        if id != preview {
            return Err(Failure::Invalid);
        }
        let permit = self
            .preparation
            .clone()
            .try_acquire_owned()
            .map_err(|_| Failure::Unavailable)?;
        let owner = self.clone();
        let key = id.clone();
        tokio::task::spawn_blocking(move || {
            let _permit=permit;
            let existing=owner.workspace.get("owner-job",&key)?;
            if let Some(job)=&existing {
                if job["contract"]!=contract {return Err(Failure::Conflict);}
                if owner.backup_purge_status(job.clone())?["state"]=="succeeded" {return Ok(());}
            } else if owner.purge_plan(&plan.backup_job,&plan.nonce)?!=plan {return Err(Failure::Conflict);}
            let mut active=owner.active.lock().map_err(unavailable)?;
            active.retain(|_,h|!h.is_finished());
            if active.contains_key(&key) {return Ok(());}
            if !active.is_empty() {return Err(Failure::Unavailable);}
            if existing.is_none() {
                owner.workspace.put("owner-job",&key,json!({"id":key,"contract":contract,"started_at":crate::evidence_operations::now().to_string()}))?;
            }
            let attempt=first_unused(|n| Ok(owner.workspace.get("owner-result",&phase(&key,n,"started"))?.is_some()))?;
            owner.workspace.put("owner-result",&phase(&key,attempt,"started"),json!({"job":key,"attempt":attempt}))?;
            let worker=owner.clone();let worker_key=key.clone();
            let task=tokio::task::spawn_blocking(move || {
                let result=match purge(&plan,&worker_key,&worker.workspace) {
                    Ok(report)=>json!({"state":"succeeded","report":report}),
                    Err(error)=>json!({"state":"purge-pending","error":error,"report":{"backup_purge":"unconfirmed","backup_job":plan.backup_job,"database":plan.database,"staging":stage(&plan,&worker_key).ok(),"preserved":"Any remaining original or staging bytes require inspection; no other copy is removed."}}),
                };
                let _=worker.workspace.put("owner-result",&phase(&worker_key,attempt,"finished"),result);
            });
            active.insert(key,task);
            Ok::<_,Failure>(())
        }).await.map_err(unavailable)??;
        loop {
            let status = self.status(&id)?;
            if !wait || status["state"] != "running" {
                return Ok(status);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}
fn exists(path: &Path) -> Result<bool, Failure> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(Failure::Unavailable),
    }
}
fn sync(path: &Path) -> Result<(), Failure> {
    std::fs::File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(unavailable)
}
fn matches(plan: &Plan, path: &Path) -> Result<FileLease, Failure> {
    let (file, bytes, hash) = inspected(path, &plan.binding)?;
    if bytes != plan.bytes || hash != plan.sha256 {
        return Err(Failure::Conflict);
    }
    Ok(file)
}
fn purge(plan: &Plan, id: &str, journal: &Workspace) -> Result<Value, Failure> {
    let directory = stage(plan, id)?;
    let parent = plan.database.parent().ok_or(Failure::Invalid)?;
    private_directory(parent)?;
    if !exists(&directory)? {
        // surface-write: evidence-backup-purge:directory
        crate::persistence::create_dir_owner_only(
            crate::persistence::SurfaceWrite::EvidenceBackupPurge,
            &directory,
        )
        .map_err(unavailable)?;
        sync(parent)?;
    }
    private_directory(&directory)?;
    let staged = directory.join("backup.sqlite");
    for entry in std::fs::read_dir(&directory).map_err(unavailable)? {
        if entry.map_err(unavailable)?.path() != staged {
            return Err(Failure::Conflict);
        }
    }
    if exists(&plan.database)? {
        if exists(&staged)? {
            return Err(Failure::Conflict);
        }
        let held = matches(plan, &plan.database)?;
        fs4::FileExt::try_lock(&held.0).map_err(|_| Failure::Conflict)?;
        same_file(&plan.database, &held.0)?;
        // surface-write: evidence-backup:archive.sqlite,evidence-backup-purge:backup.sqlite
        crate::persistence::rename(
            crate::persistence::SurfaceWrite::EvidenceBackupPurge,
            &plan.database,
            &staged,
        )
        .map_err(unavailable)?;
        sync(&directory)?;
        sync(parent)?;
        drop(held);
    }
    let removed = if exists(&staged)? {
        let held = matches(plan, &staged)?;
        fs4::FileExt::try_lock(&held.0).map_err(|_| Failure::Conflict)?;
        journal.put(
            "owner-result",
            &format!("backup-purge:{id}:verified"),
            json!({"job":id,"sha256":plan.sha256,"bytes":plan.bytes}),
        )?;
        same_file(&staged, &held.0)?;
        // surface-write: evidence-backup-purge:backup.sqlite
        crate::persistence::remove_file(
            crate::persistence::SurfaceWrite::EvidenceBackupPurge,
            &staged,
        )
        .map_err(unavailable)?;
        sync(&directory)?;
        true
    } else {
        false
    };
    if exists(&plan.database)? || exists(&staged)? {
        return Err(Failure::Conflict);
    }
    Ok(
        json!({"backup_purge":if removed{"removed-configured-copy"}else{"absence-observed-after-authorization"},
        "backup_job":plan.backup_job,"database":plan.database,"sha256":plan.sha256,"bytes":plan.bytes,
        "staging":directory,"source_archive":"retained","other_backups":"not-assessed","recovery_keys":"retained",
        "physical_or_cryptographic_erasure":"not-claimed"}),
    )
}

#[cfg(all(test, unix))]
mod lease_tests {
    use super::*;
    #[test]
    fn private_backup_lease_preserves_reader_then_upgrades_and_releases() {
        let path = tempfile::NamedTempFile::new().unwrap();
        let first = private_file(path.path()).unwrap();
        let inherited = first.0.try_clone().unwrap();
        let other = private_file(path.path()).unwrap();
        drop(first);
        let probe = std::fs::File::open(path.path()).unwrap();
        assert!(fs4::FileExt::try_lock(&probe).is_err());
        fs4::FileExt::try_lock(&other.0).unwrap();
        let replacement = other;
        drop(inherited);
        assert!(private_file(path.path()).is_err());
        drop(replacement);
        fs4::FileExt::try_lock(&probe).unwrap();
        drop(FileLease(probe));
        private_file(path.path()).unwrap();
    }
}

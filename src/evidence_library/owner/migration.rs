//! Fenced final snapshot and explicit, reversible client configuration cutover.
//! Raw v1 sources and both client configurations are retained. Old binaries and
//! external publishers must be stopped by the owner; filesystem fences cannot
//! constrain programs that ignore them.
use super::*;
use crate::evidence_import::{Plan, Selection};
use std::{fs, io::Read};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub source: PathBuf,
    pub selection: Selection,
    pub source_id: String,
    pub recipient: String,
    pub spool: PathBuf,
    pub state: PathBuf,
    /// Actual --config file read by the managed Library on its next launch.
    pub client_config: PathBuf,
    pub candidate_config: PathBuf,
    pub client_signing_key: PathBuf,
    pub backup_database: PathBuf,
    pub backup_checkpoint: PathBuf,
    pub backup_author: String,
    pub binding: Binding,
    pub recipient_key: PathBuf,
    pub max_records: u64,
    pub batch: usize,
    /// Explicit acknowledgment that older writers and external publishers stopped.
    pub writers_quiesced: bool,
    #[serde(default)]
    pub allow_uninterpreted: bool,
}
fn read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let m = fs::symlink_metadata(path)?;
    if !m.is_file() || m.file_type().is_symlink() || m.len() > limit {
        return Err("invalid migration input file".into());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err("migration input grew beyond limit".into());
    }
    Ok(bytes)
}
fn digest(bytes: &[u8]) -> String {
    service::hex(&Sha256::digest(bytes))
}
fn sync_parent(path: &Path) -> Result<()> {
    fs::File::open(path.parent().ok_or("missing parent")?)?.sync_all()?;
    Ok(())
}
fn replace_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    // All callers hold the controller/source locks. A fresh sibling keeps a
    // process death from exposing a partial authoritative artifact.
    let stage = path.parent().ok_or("missing parent")?.join(format!(
        ".kan-migration-install-{}",
        service::hex(&rand::random::<[u8; 16]>())
    ));
    // surface-write: evidence-migration:control
    crate::persistence::write_new_owner_only(
        crate::persistence::SurfaceWrite::EvidenceMigration,
        &stage,
        bytes,
    )?;
    // surface-write: evidence-migration:control
    crate::persistence::rename(
        crate::persistence::SurfaceWrite::EvidenceMigration,
        &stage,
        path,
    )?;
    sync_parent(path)
}
fn install(path: &Path, bytes: &[u8]) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            if read(path, 4 * 1024 * 1024)? != bytes {
                return Err("existing migration artifact differs".into());
            }
            return sync_parent(path);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    replace_atomic(path, bytes)
}

impl Config {
    pub(super) fn validate(&self) -> std::result::Result<(), Failure> {
        let check = || -> Result<()> {
            for path in [
                &self.source,
                &self.spool,
                &self.state,
                &self.client_config,
                &self.candidate_config,
                &self.client_signing_key,
                &self.backup_database,
                &self.backup_checkpoint,
                &self.recipient_key,
            ] {
                if !path.is_absolute() {
                    return Err("absolute paths required".into());
                }
            }
            private_directory(&self.state)?;
            if !self.writers_quiesced
                || matches!(self.selection, Selection::Identity)
                || !(1..=1024).contains(&self.batch)
                || self.max_records == 0
            {
                return Err("quiesced store/workspace and bounded batch required".into());
            }
            fixed(&self.source_id)?;
            fixed(&self.recipient)?;
            self.binding.owner_binding()?;
            let source = self.source.canonicalize()?;
            if self.state.canonicalize()?.starts_with(&source)
                || self.client_config == self.candidate_config
            {
                return Err("control state must be independent of source; distinct client configurations required".into());
            }
            self.routes()?;
            Ok(())
        };
        check().map_err(|_| Failure::Invalid)
    }
    fn fence(&self) -> PathBuf {
        match self.selection {
            Selection::Workspace => self.source.join(".kan/V2_FENCE"),
            _ => self.source.join("V2_FENCE"),
        }
    }
    fn stores(&self) -> Vec<PathBuf> {
        match self.selection {
            Selection::Workspace => ["log", "overlay"]
                .iter()
                .map(|p| self.source.join(".kan").join(p))
                .filter(|p| p.is_dir())
                .collect(),
            _ => vec![self.source.clone()],
        }
    }
    fn marker(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(
            &json!({"version":"kan-migration-fence/1","source":self.source.canonicalize()?,"state":self.state.canonicalize()?,"source_id":self.source_id}),
        )?)
    }
    fn owned_fence(&self, marker: &[u8]) -> Result<bool> {
        let bytes = match fs::symlink_metadata(self.fence()) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
            Ok(_) => read(&self.fence(), 4096)?,
        };
        if bytes == marker {
            return Ok(true);
        }
        // A partial marker is recoverable only with prior durable intent tied
        // to this exact source, state directory and source identity.
        if bytes.len() < marker.len()
            && marker.starts_with(&bytes)
            && read(&self.state.join("fence-intent.json"), 4096)? == marker
        {
            return Ok(true);
        }
        Err("foreign fence; refusing to replace or remove".into())
    }
    fn routes(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let old = read(&self.client_config, 1048576)?;
        let new = read(&self.candidate_config, 1048576)?;
        for bytes in [&old, &new] {
            let v: Value = serde_json::from_slice(bytes)?;
            if !v.is_array() || v.as_array().is_none_or(|a| a.is_empty() || a.len() > 16) {
                return Err("client config must contain 1..16 Library sources".into());
            }
        }
        let configured: Vec<super::super::SourceConfig> = serde_json::from_slice(&new)?;
        for source in &configured {
            fixed(&source.scope)?;
            service::author(&source.issuer)?;
            if !source.private_key_file.is_absolute()
                || source.historical_key_files.iter().any(|p| !p.is_absolute())
            {
                return Err("absolute reader key paths required".into());
            }
            crate::evidence_crypto::read_private_key(&source.private_key_file)?;
            let url = reqwest::Url::parse(&source.endpoint)?;
            if !matches!(url.scheme(), "http" | "https")
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
            {
                return Err("invalid reader endpoint".into());
            }
        }
        // Ensure the candidate actually routes to the archive holding the import.
        let v: Value = serde_json::from_slice(&new)?;
        if !v.as_array().unwrap().iter().any(|e| {
            e["archive"] == self.binding.archive
                && e["scope"] == self.binding.scope
                && e["issuer"] == self.binding.issuer
                && e["profile"] == serde_json::to_value(self.binding.profile).unwrap_or(Value::Null)
                && e["protocol"] == crate::evidence_proof_service::PROTOCOL
        }) {
            return Err("candidate does not select the verified destination binding".into());
        }
        Ok((old, new))
    }
    fn plan(&self) -> Result<(Plan, crate::evidence_spool::Spool)> {
        let mut spool = crate::evidence_spool::Spool::open(&self.spool)?;
        let plan = Plan::build(
            &self.source,
            self.selection,
            fixed(&self.source_id)?,
            fixed(&self.recipient)?,
            &mut spool,
        )?;
        Ok((plan, spool))
    }
    pub(super) fn preview(&self, operation: Operation) -> std::result::Result<Value, Failure> {
        let work = || -> Result<Value> {
            let (old, new) = self.routes()?;
            let snapshot = if operation == Operation::RollbackMigration {
                json!({"plan":null,"progress":null})
            } else {
                let (plan, mut spool) = self.plan()?;
                json!({"plan":plan.id(),"progress":plan.progress(&mut spool)?})
            };
            let fenced = read(&self.fence(), 4096)
                .ok()
                .is_some_and(|v| self.marker().ok().as_ref() == Some(&v));
            Ok(
                json!({"plan":snapshot["plan"],"progress":snapshot["progress"],"client_sha256":digest(&old),"candidate_sha256":digest(&new),"source_writers_fenced":fenced,"older_writers_quiesced":self.writers_quiesced,"allow_uninterpreted":self.allow_uninterpreted,"activation":"explicit apply only; restart configured clients after routing change"}),
            )
        };
        work().map_err(|_| Failure::Unavailable)
    }
    fn replace_route(&self, bytes: &[u8], nonce: &str) -> Result<()> {
        let parent = self.client_config.parent().ok_or("client config parent")?;
        let stage = parent.join(format!(".kan-migration-{nonce}"));
        install(&stage, bytes)?;
        // surface-write: evidence-migration:control
        crate::persistence::rename(
            crate::persistence::SurfaceWrite::EvidenceMigration,
            &stage,
            &self.client_config,
        )?;
        sync_parent(&self.client_config)
    }
    pub(super) fn perform(
        &self,
        operation: Operation,
        workspace: &Workspace,
        contract: &Value,
    ) -> Result<Value> {
        // Serialize this controller and source writers. Locks are nonblocking;
        // a busy source produces a visible retry rather than an unbounded job.
        let _locks = acquire_locks(
            std::iter::once(self.state.join("LOCK"))
                .chain(self.stores().into_iter().map(|p| p.join("LOCK"))),
        )?;
        let (current, candidate) = self.routes()?;
        if contract["migration"]["client_sha256"] != digest(&current)
            || contract["migration"]["candidate_sha256"] != digest(&candidate)
        {
            return Err("client configuration changed since preview".into());
        }
        let prior = self.state.join("previous-client.json");
        let marker = self.marker()?;
        let nonce = contract["nonce"].as_str().ok_or("missing nonce")?;
        if operation == Operation::FenceMigration {
            // Save rollback before fencing. Refuse reusing this state directory
            // with a different pre-migration configuration.
            install(&prior, &current)?;
            install(&self.state.join("candidate-client.json"), &candidate)?;
            // Validate existing bytes before creating intent: never legitimize
            // an unknown partial fence merely by retrying this operation.
            self.owned_fence(&marker)?;
            install(&self.state.join("fence-intent.json"), &marker)?;
            replace_atomic(&self.fence(), &marker)?;
            let (plan, mut spool) = self.plan()?;
            return Ok(
                json!({"source_writers_fenced":true,"plan":plan.id(),"progress":plan.progress(&mut spool)?,"originals":"retained","next":"Queue final snapshot, deliver, and checkpoint an independent backup before activation"}),
            );
        }
        let previous = read(&prior, 1048576)?;
        if read(&self.state.join("candidate-client.json"), 1048576)? != candidate {
            return Err("candidate differs from fenced migration".into());
        }
        if current != previous && current != candidate {
            return Err("client configuration was changed outside this migration".into());
        }
        if operation == Operation::RollbackMigration {
            // Restore route first. An interruption may leave v1 writes fenced,
            // but never enables v1 writes while routing still selects v2.
            let fenced = self.owned_fence(&marker)?;
            self.replace_route(&previous, nonce)?;
            if fenced {
                // surface-write: evidence-migration:control
                crate::persistence::remove_file(
                    crate::persistence::SurfaceWrite::EvidenceMigration,
                    &self.fence(),
                )?;
                sync_parent(&self.fence())?;
            }
            return Ok(
                json!({"routing":"previous configuration restored; restart clients","source_writers_fenced":false,"originals":"retained","v2_history":"retained; post-cutover writes are not replayed into v1","rollback_config":prior}),
            );
        }
        if read(&self.fence(), 4096)? != marker {
            return Err("source writer fence is absent or foreign".into());
        }
        let (plan, mut spool) = self.plan()?;
        if contract["migration"]["plan"] != plan.id() {
            return Err("final source snapshot changed since preview".into());
        }
        if operation == Operation::FinalizeMigration {
            let result = workspace.queue_import(&plan, plan.id(), &mut spool, self.batch)?;
            return Ok(
                json!({"source_writers_fenced":true,"final_plan":plan.id(),"progress":result,"next":"Deliver remaining operations; independently back up and verify this exact plan"}),
            );
        }
        if operation != Operation::ActivateMigration {
            return Err("invalid cutover operation".into());
        }
        if plan.summary()["inventory"]["selected_inventory_complete"] != true {
            return Err("selected source inventory is incomplete; cutover refused".into());
        }
        let progress = plan.progress(&mut spool)?;
        if !progress.queue_coverage_complete
            || progress.pending_operations != 0
            || progress.erased_operations != 0
        {
            return Err("final snapshot delivery is incomplete".into());
        }
        let checkpoint: crate::evidence_backup::Checkpoint =
            serde_json::from_slice(&read(&self.backup_checkpoint, 262144)?)?;
        checkpoint.verify(&self.backup_author)?;
        if !checkpoint.statement.independent {
            return Err("independent backup checkpoint required".into());
        }
        let backup_before = fs::metadata(&self.backup_database)?;
        let observed = crate::evidence_backup::inspect(
            &self.backup_database,
            &self.binding,
            &checkpoint.statement.destination,
            true,
        )?;
        let backup =
            crate::evidence_backup::coverage(&checkpoint, &self.backup_author, &observed, None)?;
        let status = spool.status()?;
        let recovery = self.state.join(format!("recovery-{nonce}"));
        let pins = crate::evidence_restore::Pins {
            expected_plan: plan.id(),
            scope: fixed(&status.scope)?,
            writer: &status.writer,
            recipient_private: crate::evidence_crypto::read_private_key(&self.recipient_key)?,
            max_records: self.max_records,
        };
        crate::evidence_restore::restore_proof(
            &self.backup_database,
            &recovery,
            &pins,
            &self.binding,
        )?;
        let backup_after = fs::metadata(&self.backup_database)?;
        if backup_before.len() != backup_after.len()
            || backup_before.modified()? != backup_after.modified()?
        {
            return Err("backup changed during cold verification".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if (
                backup_before.dev(),
                backup_before.ino(),
                backup_before.len(),
                backup_before.mtime(),
                backup_before.mtime_nsec(),
                backup_before.ctime(),
                backup_before.ctime_nsec(),
            ) != (
                backup_after.dev(),
                backup_after.ino(),
                backup_after.len(),
                backup_after.mtime(),
                backup_after.mtime_nsec(),
                backup_after.ctime(),
                backup_after.ctime_nsec(),
            ) {
                return Err("backup changed during cold verification".into());
            }
        }
        let reconciled = plan.reconcile(&recovery, &mut spool)?;
        let semantics = super::super::proof::imports::inspect_restored(&recovery)
            .map_err(|error| format!("restored repository inspection failed: {error:?}"))?;
        if semantics["all_membership_verified"] != true && !self.allow_uninterpreted {
            return Err("repository semantics need explicit uninterpreted-evidence acceptance; recovery retained".into());
        }
        // Verify that the actual routed endpoint authorizes this client and
        // still contains the independently backed checkpoint. A copied config
        // and a healthy backup alone do not prove the client route is usable.
        let configured: Vec<super::super::SourceConfig> = serde_json::from_slice(&candidate)?;
        let selected = configured
            .iter()
            .find(|s| {
                s.archive.as_deref() == Some(self.binding.archive.as_str())
                    && s.scope == self.binding.scope
                    && s.issuer == self.binding.issuer
            })
            .ok_or("destination source absent")?;
        let keys = std::iter::once(&selected.private_key_file)
            .chain(selected.historical_key_files.iter())
            .map(|p| crate::evidence_crypto::read_private_key(p))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if !keys.iter().any(|key| {
            crate::evidence_crypto::public_key(key)
                .ok()
                .is_some_and(|public| service::hex(&public) == self.recipient)
        }) {
            return Err("routed client lacks final import decryption key".into());
        }
        let signer = crate::sign::Identity::load_existing(&self.client_signing_key)?;
        let request = crate::evidence_proof_service::SignedRequest::sign(
            crate::evidence_proof_service::Request {
                version: 2,
                binding: self.binding.clone(),
                principal: signer.did().to_string(),
                expires: crate::evidence_operations::now() + 120,
                command: crate::evidence_proof_service::Command::Page {
                    pin: checkpoint.statement.frontier.clone(),
                    next: checkpoint.statement.frontier.clone(),
                    limit: 1,
                },
            },
            &signer,
        )?
        .bytes()?;
        let live = tokio::runtime::Handle::current().block_on(crate::evidence_http::send_proof(
            &selected.endpoint,
            &self.binding.issuer,
            &request,
        ))?;
        if !matches!(
            live.reply.result,
            Ok(crate::evidence_proof_service::Output::Page { .. })
        ) {
            return Err("routed service does not authorize the backed checkpoint".into());
        }
        // Recheck exact current bytes immediately before atomic publication.
        if read(&self.client_config, 1048576)? != current
            || read(&self.candidate_config, 1048576)? != candidate
        {
            return Err("routing changed during verification".into());
        }
        self.replace_route(&candidate, nonce)?;
        Ok(
            json!({"ready_for_cutover":true,"routing":"candidate installed; restart clients","live_checkpoint_read":"authorized and verified","source_writers_fenced":true,"final_plan":plan.id(),"reconciliation":{"verified_files":reconciled["verified_files"],"verified_bytes":reconciled["verified_bytes"],"current_source_matches":reconciled["current_source_matches"],"recovered_selected_bytes_match":reconciled["recovered_selected_bytes_match"]},"semantics":semantics,"backup":backup,"recovery":recovery,"originals":"retained","rollback_config":prior,"v2_post_cutover_writes":"remain in v2 if rolled back"}),
        )
    }
}

fn acquire_locks(
    paths: impl IntoIterator<Item = PathBuf>,
) -> Result<Vec<crate::file_lease::FileLease>> {
    let mut locks = Vec::new();
    for path in paths {
        if path
            .symlink_metadata()
            .is_ok_and(|m| m.file_type().is_symlink())
        {
            return Err("symlink lock refused".into());
        }
        // surface-write: evidence-migration:control
        let lock = crate::persistence::open_lock_file(
            crate::persistence::SurfaceWrite::EvidenceMigration,
            &path,
        )?;
        fs4::FileExt::try_lock(&lock)?;
        locks.push(crate::file_lease::FileLease(lock));
    }
    Ok(locks)
}

#[cfg(all(test, unix))]
mod lease_tests {
    use super::*;
    #[test]
    fn migration_lock_set_releases_on_drop_and_partial_acquisition_failure() {
        let first = tempfile::NamedTempFile::new().unwrap();
        let second = tempfile::NamedTempFile::new().unwrap();
        let paths = || vec![first.path().to_owned(), second.path().to_owned()];
        let locks = acquire_locks(paths()).unwrap();
        let inherited = locks[0].0.try_clone().unwrap();
        assert!(acquire_locks(paths()).is_err());
        drop(locks);
        let second_owner = acquire_locks([second.path().to_owned()]).unwrap();
        // First acquisition succeeds; second is busy. The partial set must drop.
        assert!(acquire_locks(paths()).is_err());
        let replacement = acquire_locks([first.path().to_owned()]).unwrap();
        drop(inherited);
        assert!(acquire_locks([first.path().to_owned()]).is_err());
        drop(replacement);
        drop(second_owner);
        acquire_locks(paths()).unwrap();
    }
}

//! Separately authorized, configured owner maintenance. No browser paths or
//! shell commands, and no automatic promotion of a recovered/backup artifact.
use crate::{
    evidence_proof_service::{Binding, Profile},
    evidence_service::{self as service, Failure},
    evidence_store::{self as store, Ledger, RecoveryReader},
    evidence_workspace::Workspace,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Target {
    KeyHistory {
        id: String,
        history: crate::evidence_keys::Access,
        signing_key: PathBuf,
        recovery_key: PathBuf,
    },
    AccessPolicy {
        id: String,
        policy: crate::evidence_policy::Access,
        signing_key: PathBuf,
    },
    WorkspaceRecovery {
        id: String,
        database: PathBuf,
        output: PathBuf,
        signing_key: PathBuf,
        recipient_key: PathBuf,
    },
    ImportRecovery {
        id: String,
        database: PathBuf,
        output: PathBuf,
        binding: Option<Binding>,
        plan: String,
        scope: String,
        writer: String,
        recipient_key: PathBuf,
        max_records: u64,
    },
    Migration {
        id: String,
        source: PathBuf,
        selection: crate::evidence_import::Selection,
        source_id: String,
        recipient: String,
        spool: PathBuf,
        batch: usize,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        recovered: Option<PathBuf>,
    },
    Archive {
        id: String,
        root: PathBuf,
        output: PathBuf,
        binding: Option<Binding>,
    },
    Operations {
        id: String,
        collection: PathBuf,
    },
}
impl Target {
    fn id(&self) -> &str {
        match self {
            Self::KeyHistory { id, .. }
            | Self::AccessPolicy { id, .. }
            | Self::WorkspaceRecovery { id, .. }
            | Self::Archive { id, .. }
            | Self::Operations { id, .. }
            | Self::Migration { id, .. }
            | Self::ImportRecovery { id, .. } => id,
        }
    }
}
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Operation {
    Backup,
    Recover,
    Rotate,
    Import,
    RestoreImport,
    ReconcileImport,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub token: String,
    pub targets: Vec<Target>,
    pub max_jobs: usize,
}
#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Request {
    Keys {
        target: String,
    },
    PreviewKeyRotation {
        target: String,
    },
    ApplyKeyRotation {
        target: String,
        change: Box<crate::evidence_keys::Change>,
        preview: String,
    },
    PreviewKeyTransfer {
        target: String,
        recipient: String,
        epochs: Vec<String>,
        purpose: crate::evidence_keys::TransferPurpose,
    },
    ApplyKeyTransfer {
        target: String,
        plan: Box<crate::evidence_keys::TransferPlan>,
        preview: String,
    },
    ExportKeys {
        target: String,
    },
    RestoreKeys {
        target: String,
        package: Box<crate::evidence_keys::RecoveryPackage>,
        preview: Option<String>,
    },
    Access {
        target: String,
        #[serde(default)]
        after: usize,
    },
    PreviewAccess {
        target: String,
        grants: Vec<service::Grant>,
    },
    ApplyAccess {
        target: String,
        change: Box<crate::evidence_policy::Change>,
        preview: String,
    },
    Catalog,
    Preview {
        target: String,
        operation: Operation,
        retry_of: Option<String>,
    },
    Submit {
        target: String,
        operation: Operation,
        retry_of: Option<String>,
        nonce: String,
        preview: String,
        #[serde(default)]
        wait: bool,
    },
    Job {
        id: String,
    },
}
enum KeyAction {
    PreviewTransfer(String, Vec<String>, crate::evidence_keys::TransferPurpose),
    ApplyTransfer(Box<crate::evidence_keys::TransferPlan>, String),
    Read,
    Preview,
    Apply(Box<crate::evidence_keys::Change>, String),
    Export,
    Restore(Box<crate::evidence_keys::RecoveryPackage>, Option<String>),
}
enum PolicyAction {
    Read(usize),
    Preview(Vec<service::Grant>),
    Apply(Box<crate::evidence_policy::Change>, String),
}
pub struct Owner {
    _lease: std::fs::File,
    token: String,
    targets: BTreeMap<String, Target>,
    workspace: Arc<Workspace>,
    max_jobs: usize,
    preparation: Arc<tokio::sync::Semaphore>,
    active: Mutex<BTreeMap<String, tokio::task::JoinHandle<()>>>,
}
fn private_directory(path: &Path) -> Result<(), Failure> {
    if !path.is_absolute() {
        return Err(Failure::Invalid);
    }
    let m = std::fs::symlink_metadata(path).map_err(|_| Failure::Unavailable)?;
    if !m.is_dir() || m.file_type().is_symlink() {
        return Err(Failure::Invalid);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if m.permissions().mode() & 0o077 != 0 {
            return Err(Failure::Invalid);
        }
    }
    Ok(())
}
impl Owner {
    pub fn new(config: Config, workspace: Workspace) -> Result<Arc<Self>, Failure> {
        if config.token.len() < 32
            || config.token.len() > 4096
            || !config.token.bytes().all(|c| c.is_ascii_graphic())
            || config.targets.is_empty()
            || config.targets.len() > 32
            || config.max_jobs == 0
            || config.max_jobs > 1000
        {
            return Err(Failure::Invalid);
        }
        let mut targets = BTreeMap::new();
        for target in config.targets {
            if target.id().is_empty() || target.id().len() > 128 {
                return Err(Failure::Invalid);
            }
            match &target {
                Target::KeyHistory {
                    history,
                    signing_key,
                    recovery_key,
                    ..
                } => {
                    history.validate()?;
                    if !signing_key.is_absolute()
                        || !recovery_key.is_absolute()
                        || crate::sign::Identity::load_existing(signing_key)
                            .map_err(|_| Failure::Invalid)?
                            .did()
                            .as_str()
                            != history.owner
                    {
                        return Err(Failure::Invalid);
                    }
                    let key = crate::evidence_crypto::read_private_key(recovery_key)
                        .map_err(|_| Failure::Invalid)?;
                    if service::hex(
                        &crate::evidence_crypto::public_key(&key).map_err(|_| Failure::Invalid)?,
                    ) != history.recovery_recipient
                    {
                        return Err(Failure::Invalid);
                    }
                }
                Target::AccessPolicy {
                    policy,
                    signing_key,
                    ..
                } => {
                    policy.validate()?;
                    if !signing_key.is_absolute()
                        || crate::sign::Identity::load_existing(signing_key)
                            .map_err(|_| Failure::Invalid)?
                            .did()
                            .as_str()
                            != policy.owner
                    {
                        return Err(Failure::Invalid);
                    }
                }
                Target::WorkspaceRecovery {
                    database,
                    output,
                    signing_key,
                    recipient_key,
                    ..
                } => {
                    if !database.is_absolute()
                        || !signing_key.is_absolute()
                        || !recipient_key.is_absolute()
                    {
                        return Err(Failure::Invalid);
                    }
                    private_directory(output)?;
                    crate::evidence_crypto::read_private_key(recipient_key)
                        .map_err(|_| Failure::Invalid)?;
                    crate::sign::Identity::load_existing(signing_key)
                        .map_err(|_| Failure::Invalid)?;
                }
                Target::Archive {
                    root,
                    output,
                    binding,
                    ..
                } => {
                    private_directory(root)?;
                    private_directory(output)?;
                    if let Some(binding) = binding {
                        binding.owner_binding()?;
                    }
                }
                Target::Operations { collection, .. } => private_directory(collection)?,
                Target::ImportRecovery {
                    database,
                    output,
                    binding,
                    plan,
                    scope,
                    writer,
                    recipient_key,
                    max_records,
                    ..
                } => {
                    if !database.is_absolute()
                        || !recipient_key.is_absolute()
                        || *max_records == 0
                        || *max_records > 1_000_000
                        || writer.is_empty()
                    {
                        return Err(Failure::Invalid);
                    }
                    private_directory(output)?;
                    fixed(plan)?;
                    fixed(scope)?;
                    crate::evidence_crypto::read_private_key(recipient_key)
                        .map_err(|_| Failure::Invalid)?;
                    if let Some(b) = binding {
                        b.owner_binding()?;
                        if &b.scope != scope {
                            return Err(Failure::Invalid);
                        }
                    }
                }
                Target::Migration {
                    source,
                    source_id,
                    recipient,
                    spool,
                    batch,
                    recovered,
                    ..
                } => {
                    if !source.is_absolute() || !spool.is_absolute() || !(1..=1024).contains(batch)
                    {
                        return Err(Failure::Invalid);
                    }
                    if let Some(path) = recovered {
                        if !path.is_absolute() {
                            return Err(Failure::Invalid);
                        }
                    }
                    fixed(source_id)?;
                    fixed(recipient)?;
                    let mut queue = crate::evidence_spool::Spool::open(spool)
                        .map_err(|_| Failure::Unavailable)?;
                    if queue.status().map_err(|_| Failure::Corrupt)?.writer != workspace.author() {
                        return Err(Failure::AccessLimited);
                    }
                }
            }
            if targets.insert(target.id().to_string(), target).is_some() {
                return Err(Failure::Invalid);
            }
        }
        let lease = workspace.analysis_lease()?;
        Ok(Arc::new(Self {
            _lease: lease,
            token: config.token,
            targets,
            workspace: Arc::new(workspace),
            max_jobs: config.max_jobs,
            preparation: Arc::new(tokio::sync::Semaphore::new(1)),
            active: Mutex::new(BTreeMap::new()),
        }))
    }
    pub(super) fn same_token(&self, token: &str) -> bool {
        self.token == token
    }
    pub(super) fn authorized(&self, headers: &hyper::HeaderMap) -> bool {
        headers.get_all("authorization").iter().count() == 1
            && headers.get("authorization").map(|v| v.as_bytes())
                == Some(format!("Bearer {}", self.token).as_bytes())
    }
    fn contract(
        &self,
        target: &str,
        operation: Operation,
        retry_of: Option<&str>,
        nonce: &str,
    ) -> Result<Value, Failure> {
        if nonce.len() != 64 || service::unhex(nonce, 32).is_err() {
            return Err(Failure::Invalid);
        }
        let selected = self.targets.get(target).ok_or(Failure::AccessLimited)?;
        let destination = match selected {
            Target::WorkspaceRecovery { output, .. } if operation == Operation::Recover => {
                Some(output.join(format!("{nonce}.sqlite")))
            }
            Target::Archive { output, .. }
                if matches!(operation, Operation::Backup | Operation::Recover) =>
            {
                Some(output.join(format!("{nonce}.sqlite")))
            }
            Target::Operations { .. } if operation == Operation::Rotate => None,
            Target::Migration { .. } if operation == Operation::Import => None,
            Target::Migration {
                recovered: Some(_), ..
            } if operation == Operation::ReconcileImport => None,
            Target::ImportRecovery { output, .. } if operation == Operation::RestoreImport => {
                Some(output.join(nonce))
            }
            _ => return Err(Failure::Invalid),
        };
        if let Some(id) = retry_of {
            let old = self
                .workspace
                .get("owner-job", id)?
                .ok_or(Failure::AccessLimited)?;
            if old["contract"]["target"]
                != serde_json::to_value(selected).map_err(|_| Failure::Invalid)?
                || old["contract"]["operation"]
                    != serde_json::to_value(operation).map_err(|_| Failure::Invalid)?
            {
                return Err(Failure::Invalid);
            }
        }
        Ok(
            json!({"version":1,"owner":self.workspace.author(),"target":selected,"operation":operation,"destination":destination,"nonce":nonce,"retry_of":retry_of,"import":migration_preview(selected)?,
            "effect":match operation{
                Operation::ReconcileImport=>"Read and hash the configured recovery files against this exact current source plan, then recheck the source inventory. Record remaining cutover preconditions; do not fence writers or activate stores.",
                Operation::RestoreImport=>"Verify and reconstruct the pinned import into a new owner-private PLAINTEXT directory. Retain source and any failed output. This verifies selected file bytes, not repository semantics, independent backup or cutover.",
                Operation::Import=>"Queue a bounded batch of this exact selected v1 snapshot into the configured encrypted durable spool. Retain originals. Sending, independent recovery verification and cutover are separate actions; a completed job may leave more batches to queue.",
                Operation::Backup=>"Copy and verify the current consistent archive snapshot into a new file. Retain the source; do not activate the output. The source may grow after preview.",
                Operation::Recover=>"Recover the configured archive or stopped encrypted workspace into a new file and verify its retained evidence. Workspace recovery requires stopped writers, including older versions. Preserve source and rollback journals and any failed output; do not switch active services.",
                Operation::Rotate=>"Create a fresh operations generation while retaining sealed history. Active writers must stop; contention refuses rotation.",
            },
            "cancellation":"Once started, maintenance runs to its existing safe boundary. Closing this UI does not cancel or roll back writes."}),
        )
    }
    async fn prepare(
        self: &Arc<Self>,
        target: String,
        operation: Operation,
        retry_of: Option<String>,
        nonce: String,
    ) -> Result<Value, Failure> {
        let permit = self
            .preparation
            .clone()
            .try_acquire_owned()
            .map_err(|_| Failure::Unavailable)?;
        let owner = self.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            owner.contract(&target, operation, retry_of.as_deref(), &nonce)
        })
        .await
        .map_err(|_| Failure::Unavailable)?
    }
    fn hash(contract: &Value) -> Result<String, Failure> {
        Ok(service::hex(&Sha256::digest(
            serde_json::to_vec(contract).map_err(|_| Failure::Invalid)?,
        )))
    }
    fn status(&self, id: &str) -> Result<Value, Failure> {
        let job = self
            .workspace
            .get("owner-job", id)?
            .ok_or(Failure::AccessLimited)?;
        let result = self.workspace.get("owner-result", id)?;
        let running = self
            .active
            .lock()
            .map_err(|_| Failure::Unavailable)?
            .get(id)
            .is_some_and(|h| !h.is_finished());
        Ok(
            json!({"job":job,"state":result.as_ref().and_then(|r|r["state"].as_str()).unwrap_or(if running{"running"}else{"interrupted"}),"result":result}),
        )
    }
    async fn policy_action(&self, target: String, action: PolicyAction) -> Result<Value, Failure> {
        let Target::AccessPolicy {
            policy,
            signing_key,
            ..
        } = self
            .targets
            .get(&target)
            .ok_or(Failure::AccessLimited)?
            .clone()
        else {
            return Err(Failure::Invalid);
        };
        let permit = self
            .preparation
            .clone()
            .try_acquire_owned()
            .map_err(|_| Failure::Unavailable)?;
        tokio::task::spawn_blocking(move || {
            let _permit=permit;
            match action {
                PolicyAction::Read(after) => {
                    let snapshot=policy.read()?;
                    if after>snapshot.history.len() {return Err(Failure::Invalid);}
                    let records=snapshot.history.iter().skip(after).take(16).cloned().collect::<Vec<_>>();
                    let next=after+records.len();
                    Ok(json!({"target":target,"binding":policy.binding,"owner":policy.owner,"minimum":policy.minimum,"snapshot":snapshot.value(),"records":records,"next":(next<snapshot.history.len()).then_some(next)}))
                }
                PolicyAction::Preview(grants) => {
                    let change=policy.preview(grants,service::hex(&rand::random::<[u8;32]>()))?;
                    Ok(json!({"target":target,"digest":change.digest()?,"change":change,"effect":"Replace current append/inventory grants with this complete set. Retain signed prior policies. Revocation affects subsequent service operations; it cannot recall plaintext or keys already acquired. No decryption, forwarding or owner powers are granted."}))
                }
                PolicyAction::Apply(change, preview) => {
                    if change.digest()?!=preview || change.binding!=policy.binding || change.owner!=policy.owner {return Err(Failure::Invalid);}
                    let signer=crate::sign::Identity::load_existing(&signing_key).map_err(|_|Failure::Unavailable)?;
                    let record=crate::evidence_policy::Record::sign(*change,&signer)?;
                    let mut result=policy.append(record)?;result["target"]=json!(target);Ok(result)
                }
            }
        }).await.map_err(|_|Failure::Unavailable)?
    }
    async fn key_action(&self, target: String, action: KeyAction) -> Result<Value, Failure> {
        let Target::KeyHistory {
            history,
            signing_key,
            recovery_key,
            ..
        } = self
            .targets
            .get(&target)
            .ok_or(Failure::AccessLimited)?
            .clone()
        else {
            return Err(Failure::Invalid);
        };
        let permit = self
            .preparation
            .clone()
            .try_acquire_owned()
            .map_err(|_| Failure::Unavailable)?;
        tokio::task::spawn_blocking(move || {
            let _permit=permit;
            let private=crate::evidence_crypto::read_private_key(&recovery_key).map_err(|_|Failure::AccessLimited)?;
            if service::hex(&crate::evidence_crypto::public_key(&private).map_err(|_|Failure::Invalid)?)!=history.recovery_recipient {return Err(Failure::AccessLimited);}
            match action {
                KeyAction::Read => {
                    let snapshot=history.read()?;
                    snapshot.unlock(&private)?;
                    let epoch_ids=snapshot.history.iter().map(crate::evidence_keys::Record::id).collect::<Result<Vec<_>,_>>()?;
                    Ok(json!({"target":target,"epoch_ids":epoch_ids,"binding":history.binding,"recovery_recipient":history.recovery_recipient,"minimum":history.minimum,"snapshot":snapshot.value(),"custody":"Recovery key verified; no private key material returned."}))
                }
                KeyAction::Preview => {
                    let change=history.preview(service::hex(&rand::random::<[u8;32]>()))?;
                    change.unlock(&private)?;
                    Ok(json!({"target":target,"digest":change.digest()?,"change":change,"effect":"Append a fresh encryption epoch. Epoch-aware capture uses it for subsequent attempts; existing attempts and spooled retries keep their original epoch. Retain all previous keys and evidence. Export the updated wrapped package and keep the independent recovery credential separately."}))
                }
                KeyAction::Apply(change,preview) => {
                    if change.digest()?!=preview || change.binding!=history.binding || change.owner!=history.owner {return Err(Failure::Invalid);}
                    change.unlock(&private)?;
                    let signer=crate::sign::Identity::load_existing(&signing_key).map_err(|_|Failure::Unavailable)?;
                    let mut result=history.append(crate::evidence_keys::Record::sign(*change,&signer)?)?;
                    result["target"]=json!(target);Ok(result)
                }
                KeyAction::PreviewTransfer(recipient,epochs,purpose) => {
                    let plan=history.preview_transfer(recipient,epochs,purpose)?;
                    Ok(json!({"target":target,"digest":plan.digest()?,"plan":plan,"effect":"Export the selected existing epoch keys wrapped to this recipient. This conveys decryption custody and cannot be recalled. It grants no storage access or future keys. Original history stays unchanged; restore and configuration activation are separate actions. Replacement requires all current epochs, followed by activation and a new epoch to protect future captures."}))
                }
                KeyAction::ApplyTransfer(plan,preview) => {
                    let signer=crate::sign::Identity::load_existing(&signing_key).map_err(|_|Failure::Unavailable)?;
                    Ok(json!({"target":target,"package":history.transfer(&plan,&preview,&private,&signer)?,"custody":"Transferred wrapped keys. Retain the original history as provenance and back up this package independently from its recipient private key. No service configuration or storage grants changed."}))
                }
                KeyAction::Export => Ok(json!({"target":target,"package":history.export()?,"custody":"Wrapped keys only. Store independently from the recovery private credential. This does not include archive ciphertext, reader workspace, or service grants."})),
                KeyAction::Restore(package,preview) => {
                    history.verify_package(&package)?;
                    for record in &package.records {record.change.unlock(&private)?;}
                    let contract=json!({"target":target,"history":history,"package":package});
                    let digest=Self::hash(&contract)?;
                    if let Some(expected)=preview {
                        if expected!=digest {return Err(Failure::Invalid);}
                        let mut result=history.restore(&package)?;result["target"]=json!(target);Ok(result)
                    } else {
                        Ok(json!({"target":target,"digest":digest,"tip":package.tip,"epochs":package.records.len(),"effect":"Restore this signed wrapped history to the configured key directory. Accept only an identical existing prefix; never replace keys or activate a reader/capture configuration."}))
                    }
                }
            }
        }).await.map_err(|_|Failure::Unavailable)?
    }
    pub async fn execute(self: &Arc<Self>, request: Request) -> Result<Value, Failure> {
        match request {
            Request::Keys { target } => self.key_action(target, KeyAction::Read).await,
            Request::PreviewKeyRotation { target } => {
                self.key_action(target, KeyAction::Preview).await
            }
            Request::ApplyKeyRotation {
                target,
                change,
                preview,
            } => {
                self.key_action(target, KeyAction::Apply(change, preview))
                    .await
            }
            Request::PreviewKeyTransfer {
                target,
                recipient,
                epochs,
                purpose,
            } => {
                self.key_action(
                    target,
                    KeyAction::PreviewTransfer(recipient, epochs, purpose),
                )
                .await
            }
            Request::ApplyKeyTransfer {
                target,
                plan,
                preview,
            } => {
                self.key_action(target, KeyAction::ApplyTransfer(plan, preview))
                    .await
            }
            Request::ExportKeys { target } => self.key_action(target, KeyAction::Export).await,
            Request::RestoreKeys {
                target,
                package,
                preview,
            } => {
                self.key_action(target, KeyAction::Restore(package, preview))
                    .await
            }
            Request::Access { target, after } => {
                self.policy_action(target, PolicyAction::Read(after)).await
            }
            Request::PreviewAccess { target, grants } => {
                self.policy_action(target, PolicyAction::Preview(grants))
                    .await
            }
            Request::ApplyAccess {
                target,
                change,
                preview,
            } => {
                self.policy_action(target, PolicyAction::Apply(change, preview))
                    .await
            }
            Request::Catalog => {
                let mut jobs = Vec::new();
                for job in self.workspace.owner_jobs()? {
                    jobs.push(self.status(job["id"].as_str().ok_or(Failure::Corrupt)?)?);
                }
                Ok(
                    json!({"owner":self.workspace.author(),"targets":self.targets.values().collect::<Vec<_>>(),"jobs":jobs,"limits":{"jobs":self.max_jobs,"concurrency":1},"authority":"Separate owner capability. Recovered and backup outputs are not activated."}),
                )
            }
            Request::Preview {
                target,
                operation,
                retry_of,
            } => {
                let nonce = service::hex(&rand::random::<[u8; 32]>());
                let contract = self
                    .prepare(target.clone(), operation, retry_of.clone(), nonce.clone())
                    .await?;
                Ok(json!({"digest":Self::hash(&contract)?,"nonce":nonce,"contract":contract}))
            }
            Request::Job { id } => self.status(&id),
            Request::Submit {
                target,
                operation,
                retry_of,
                nonce,
                preview,
                wait,
            } => {
                let contract = if let Some(job) = self.workspace.get("owner-job", &preview)? {
                    let c = job.get("contract").ok_or(Failure::Corrupt)?;
                    let selected = self.targets.get(&target).ok_or(Failure::AccessLimited)?;
                    if c["target"]
                        != serde_json::to_value(selected).map_err(|_| Failure::Invalid)?
                        || c["operation"]
                            != serde_json::to_value(operation).map_err(|_| Failure::Invalid)?
                        || c["nonce"] != nonce
                        || c["retry_of"] != json!(retry_of)
                    {
                        return Err(Failure::Invalid);
                    }
                    c.clone()
                } else {
                    self.prepare(target.clone(), operation, retry_of.clone(), nonce.clone())
                        .await?
                };
                let id = Self::hash(&contract)?;
                if id != preview {
                    return Err(Failure::Invalid);
                }
                {
                    let mut active = self.active.lock().map_err(|_| Failure::Unavailable)?;
                    if self.workspace.get("owner-job", &id)?.is_none() {
                        active.retain(|_, handle| !handle.is_finished());
                        if !active.is_empty() {
                            return Err(Failure::Unavailable);
                        }
                        if self.workspace.owner_jobs()?.len() >= self.max_jobs {
                            return Err(Failure::Unavailable);
                        }
                        if let Some(path) = contract["destination"].as_str() {
                            match std::fs::symlink_metadata(path) {
                                Ok(_) => return Err(Failure::Invalid),
                                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                                Err(_) => return Err(Failure::Unavailable),
                            }
                        }
                        self.workspace.put("owner-job",&id,json!({"id":id,"contract":contract,"started_at":crate::evidence_operations::now().to_string()}))?;
                        let owner = self.clone();
                        let key = id.clone();
                        let selected = self.targets[&target].clone();
                        let destination = contract["destination"].as_str().map(PathBuf::from);
                        let task = tokio::task::spawn_blocking(move || {
                            let outcome = perform(
                                &selected,
                                operation,
                                destination.as_deref(),
                                &owner.workspace,
                                &contract,
                            );
                            let value = match outcome {
                                Ok(report) => {
                                    json!({"state":"succeeded","report":report,"finished_at":crate::evidence_operations::now().to_string()})
                                }
                                Err(error) => {
                                    json!({"state":"failed","error":error,"outputs":"Any created output is retained. Inspect it and use a new preview for a new destination; never overwrite or assume activation.","finished_at":crate::evidence_operations::now().to_string()})
                                }
                            };
                            let _ = owner.workspace.put("owner-result", &key, value);
                        });
                        active.insert(id.clone(), task);
                    }
                }
                if wait {
                    loop {
                        let status = self.status(&id)?;
                        if status["state"] != "running" {
                            return Ok(status);
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
                self.status(&id)
            }
        }
    }
}
fn perform(
    target: &Target,
    operation: Operation,
    destination: Option<&Path>,
    workspace: &Workspace,
    contract: &Value,
) -> Result<Value, String> {
    let work = || -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        match target {
            Target::KeyHistory { .. } | Target::AccessPolicy { .. } => {
                Err("access policies use their dedicated preview/apply API".into())
            }
            Target::WorkspaceRecovery {
                database,
                signing_key,
                recipient_key,
                ..
            } => {
                if operation != Operation::Recover {
                    return Err("invalid workspace recovery job".into());
                }
                Ok(Workspace::recover(
                    database,
                    destination.ok_or("missing recovery destination")?,
                    crate::sign::Identity::load_existing(signing_key)?,
                    crate::evidence_crypto::read_private_key(recipient_key)?,
                )?)
            }
            Target::ImportRecovery {
                database,
                binding,
                plan,
                scope,
                writer,
                recipient_key,
                max_records,
                ..
            } => {
                if operation != Operation::RestoreImport {
                    return Err("invalid import recovery operation".into());
                }
                let output = destination.ok_or("missing recovery directory")?;
                let pins = crate::evidence_restore::Pins {
                    expected_plan: plan,
                    scope: fixed(scope)?,
                    writer,
                    recipient_private: crate::evidence_crypto::read_private_key(recipient_key)?,
                    max_records: *max_records,
                };
                let report = if let Some(b) = binding {
                    crate::evidence_restore::restore_proof(database, output, &pins, b)?
                } else {
                    crate::evidence_restore::restore(database, output, &pins)?
                };
                // Full per-operation provenance is in the retained report.json;
                // keep the encrypted job receipt small even for large imports.
                Ok(
                    json!({"destination":output,"plan":report["plan"],"verified_selected_file_bytes":report["verified_selected_file_bytes"],"signed_requests_verified":report["signed_requests_verified"],"proof_binding":report["proof_binding"],"files":report["files"].as_array().map(Vec::len),"report":"report.json","activation":"not-performed","independent_backup":false}),
                )
            }
            Target::Migration {
                batch, recovered, ..
            } => {
                if !matches!(operation, Operation::Import | Operation::ReconcileImport) {
                    return Err("invalid migration job".into());
                }
                let (plan, mut spool) = migration_plan(target)?;
                let expected = contract["import"]["plan"]
                    .as_str()
                    .ok_or("missing pinned import plan")?;
                if plan.id() != expected {
                    return Err("source plan changed".into());
                }
                if operation == Operation::ReconcileImport {
                    return Ok(plan.reconcile(
                        recovered
                            .as_deref()
                            .ok_or("recovery directory not configured")?,
                        &mut spool,
                    )?);
                }
                let progress = workspace.queue_import(&plan, expected, &mut spool, *batch)?;
                Ok(
                    json!({"progress":progress,"delivery":"not-performed","originals":"retained","activation":"not-performed","independent_backup":false}),
                )
            }
            Target::Operations { collection, .. } => {
                if operation != Operation::Rotate {
                    return Err("invalid operations job".into());
                }
                crate::evidence_operations_collection::rotate(collection)?;
                Ok(
                    json!({"history":"retained","generations":crate::evidence_operations_collection::generations(collection,0,50)?}),
                )
            }
            Target::Archive { root, binding, .. } => {
                let output = destination.ok_or("missing output")?;
                let database = root.join("archive.sqlite");
                let report = match (binding, operation) {
                    (None, Operation::Backup) => Ledger::open(root)?.backup(output)?,
                    (None, Operation::Recover) => {
                        RecoveryReader::open(&database)?.rebuild(output)?
                    }
                    (Some(b), Operation::Backup) if b.profile == Profile::Admitted => {
                        store::attested::Archive::open(root, b.owner_binding()?)?.backup(output)?
                    }
                    (Some(b), Operation::Recover) if b.profile == Profile::Admitted => {
                        store::attested::Recovery::open(&database, b.owner_binding()?)?
                            .rebuild(output)?
                    }
                    (Some(b), Operation::Backup) => {
                        store::copied::Archive::open(root, b.owner_binding()?)?
                            .backup(output)?
                            .contents
                    }
                    (Some(b), Operation::Recover) => {
                        store::copied::Recovery::open(&database, b.owner_binding()?)?
                            .rebuild(output)?
                            .contents
                    }
                    _ => return Err("invalid archive job".into()),
                };
                Ok(
                    json!({"destination":output,"objects":report.objects,"erased_objects":report.erased_objects,"commits":report.commits,"bytes":report.bytes,"activation":"not-performed","independent_backup":false}),
                )
            }
        }
    };
    work().map_err(|e| e.to_string())
}

fn fixed(value: &str) -> Result<[u8; 32], Failure> {
    service::unhex(value, 32)?
        .try_into()
        .map_err(|_| Failure::Invalid)
}
fn migration_plan(
    target: &Target,
) -> Result<
    (crate::evidence_import::Plan, crate::evidence_spool::Spool),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let Target::Migration {
        source,
        selection,
        source_id,
        recipient,
        spool,
        ..
    } = target
    else {
        return Err("not a migration target".into());
    };
    let mut queue = crate::evidence_spool::Spool::open(spool)?;
    let plan = crate::evidence_import::Plan::build(
        source,
        *selection,
        fixed(source_id)?,
        fixed(recipient)?,
        &mut queue,
    )?;
    Ok((plan, queue))
}
fn migration_preview(target: &Target) -> Result<Value, Failure> {
    if !matches!(target, Target::Migration { .. }) {
        return Ok(Value::Null);
    }
    let (plan, mut queue) = migration_plan(target).map_err(|_| Failure::Unavailable)?;
    let summary = plan.summary();
    let route = queue.status().map_err(|_| Failure::Unavailable)?;
    Ok(
        json!({"plan":plan.id(),"writer":route.writer,"scope":route.scope,"audience":route.audience,"files":summary["inventory"]["files"].as_array().map(Vec::len),"observed_bytes":summary["inventory"]["observed_bytes"],"selected_inventory_complete":summary["inventory"]["selected_inventory_complete"],"notice_count":summary["inventory"]["notices"].as_array().map(Vec::len),"total_operations":summary["total_operations"],"recovery_verified":false,"ready_for_cutover":false}),
    )
}

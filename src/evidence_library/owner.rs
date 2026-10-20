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
            Self::Archive { id, .. } | Self::Operations { id, .. } => id,
        }
    }
}
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Operation {
    Backup,
    Recover,
    Rotate,
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
pub struct Owner {
    _lease: std::fs::File,
    token: String,
    targets: BTreeMap<String, Target>,
    workspace: Arc<Workspace>,
    max_jobs: usize,
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
            Target::Archive { output, .. }
                if matches!(operation, Operation::Backup | Operation::Recover) =>
            {
                Some(output.join(format!("{nonce}.sqlite")))
            }
            Target::Operations { .. } if operation == Operation::Rotate => None,
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
            json!({"version":1,"owner":self.workspace.author(),"target":selected,"operation":operation,"destination":destination,"nonce":nonce,"retry_of":retry_of,
            "effect":match operation{
                Operation::Backup=>"Copy and verify the current consistent archive snapshot into a new file. Retain the source; do not activate the output. The source may grow after preview.",
                Operation::Recover=>"Rebuild derived lookups from retained evidence into a new file. Preserve source and any failed output; do not switch active services.",
                Operation::Rotate=>"Create a fresh operations generation while retaining sealed history. Active writers must stop; contention refuses rotation.",
            },
            "cancellation":"Once started, maintenance runs to its existing safe boundary. Closing this UI does not cancel or roll back writes."}),
        )
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
    pub async fn execute(self: &Arc<Self>, request: Request) -> Result<Value, Failure> {
        match request {
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
                let contract = self.contract(&target, operation, retry_of.as_deref(), &nonce)?;
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
                let contract = self.contract(&target, operation, retry_of.as_deref(), &nonce)?;
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
                            let outcome = perform(&selected, operation, destination.as_deref());
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
) -> Result<Value, String> {
    let work = || -> Result<Value, Box<dyn std::error::Error>> {
        match target {
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
                    json!({"destination":output,"objects":report.objects,"commits":report.commits,"bytes":report.bytes,"activation":"not-performed","independent_backup":false}),
                )
            }
        }
    };
    work().map_err(|e| e.to_string())
}

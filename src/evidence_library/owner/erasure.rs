//! Restartable owner authorization and archive cleanup. Secondary cleanup is
//! explicit pending work, never inferred from successful primary deletion.
use super::*;
mod publications;
use crate::{
    evidence_erasure_history as custody, evidence_store::erasure as storage, sign::Identity,
};
pub use publications::PublicationTarget;

const ATTEMPTS: usize = 32;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preview {
    pub capture: storage::Capture,
    pub recording_gap: bool,
    pub coverage: String,
    pub authorization: custody::Change,
}
fn invalid<E>(_: E) -> Failure {
    Failure::Invalid
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceTarget {
    pub database: PathBuf,
    pub signing_key: PathBuf,
    pub recipient_key: PathBuf,
}
struct Configured<'a> {
    root: &'a Path,
    history: &'a custody::Access,
    signing: &'a Path,
    issuer: &'a Path,
    keys: &'a [PathBuf],
    replicas: &'a [PathBuf],
    workspaces: &'a [WorkspaceTarget],
    spools: &'a [PathBuf],
    publications: &'a [PublicationTarget],
}
fn configured(target: &Target) -> Result<Configured<'_>, Failure> {
    match target {
        Target::CaptureErasure {
            root,
            history,
            signing_key,
            issuer_key,
            private_keys,
            replicas,
            workspaces,
            spools,
            publications,
            ..
        } => Ok(Configured {
            root,
            history,
            signing: signing_key,
            issuer: issuer_key,
            keys: private_keys,
            replicas,
            workspaces,
            spools,
            publications,
        }),
        _ => Err(Failure::Invalid),
    }
}
pub(super) fn validate_target(target: &Target) -> Result<(), Failure> {
    let Configured {
        root,
        history,
        signing,
        issuer,
        keys,
        replicas,
        workspaces,
        spools,
        publications,
    } = configured(target)?;
    private_directory(root)?;
    history.validate()?;
    if history.minimum.is_none()
        || !signing.is_absolute()
        || !issuer.is_absolute()
        || keys.is_empty()
        || keys.len() > 64
        || replicas.len() > 16
        || keys.iter().any(|p| !p.is_absolute())
        || replicas.iter().any(|p| !p.is_absolute())
        || Identity::load_existing(signing)
            .map_err(invalid)?
            .did()
            .as_str()
            != history.owner
        || Identity::load_existing(issuer)
            .map_err(invalid)?
            .did()
            .as_str()
            != history.binding.issuer
    {
        return Err(Failure::Invalid);
    }
    let mut roots = std::collections::BTreeSet::from([root.to_path_buf()]);
    for path in replicas {
        if !roots.insert(path.clone()) {
            return Err(Failure::Invalid);
        }
    }
    if spools.len() > 16
        || spools.iter().any(|p| !p.is_absolute())
        || spools
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != spools.len()
    {
        return Err(Failure::Invalid);
    }
    if workspaces.len() > 16 {
        return Err(Failure::Invalid);
    }
    let mut databases = std::collections::BTreeSet::new();
    for workspace in workspaces {
        if !workspace.database.is_absolute()
            || !workspace.signing_key.is_absolute()
            || !workspace.recipient_key.is_absolute()
            || !databases.insert(workspace.database.clone())
        {
            return Err(Failure::Invalid);
        }
    }
    // Replica absence must not prevent restart and inspection of pending cleanup.
    for path in keys {
        crate::evidence_crypto::read_private_key(path).map_err(invalid)?;
    }
    publications::validate(publications, history, &roots)?;
    Ok(())
}
fn capture(
    target: &Target,
    selected: storage::Capture,
    nonce: String,
    now: u64,
) -> Result<storage::CapturePreview, Failure> {
    let Configured {
        root,
        history,
        keys: files,
        ..
    } = configured(target)?;
    let current = history.current()?;
    current.check_archive(&root.join("archive.sqlite"), &history.binding)?;
    let keys = files
        .iter()
        .map(|p| crate::evidence_crypto::read_private_key(p).map_err(invalid))
        .collect::<Result<Vec<_>, _>>()?;
    let binding = history.binding.owner_binding()?;
    Ok(match history.binding.profile {
        Profile::Admitted => store::attested::Archive::open(root, binding)?
            .preview_capture_erasure(selected, &keys, nonce, now)?,
        Profile::Copied => store::copied::Archive::open(root, binding)?
            .preview_capture_erasure(selected, &keys, nonce, now)?,
    })
}
fn contract(target: &Target, plan: &Preview) -> Result<Value, Failure> {
    let value = json!({"version":1,"target":target,"operation":"erase-capture","plan":plan,
        "effect":"Erase this closed capture from the configured archives after publishing independent owner authorization. Preserve minimal provenance. Scan configured publication archives for source-dependent annotations and their correction/withdrawal descendants, journal exact child authorizations before cleanup, and reconcile their configured replicas and admitted queue copies. Configured stopped workspaces reconcile dependent data against current owner erasure history. Configured admitted publication queues cancel selected heads under current policy with commitment-only admission and signed completion. Blocked queues and other copy cleanup remain pending; historical backups and keys are not cryptographically erased.",
        "cancellation":"Once accepted, authorization and erasure cannot be rolled back. Resume the retained job after interruption."});
    if serde_json::to_vec(&value).map_err(invalid)?.len() > 200 * 1024 {
        return Err(Failure::Unavailable);
    }
    Ok(value)
}
fn attempt_key(id: &str, n: usize, phase: &str) -> String {
    format!("erasure:{id}:{n}:{phase}")
}
impl Owner {
    pub(super) async fn preview_erasure(
        self: &Arc<Self>,
        target: String,
        selected: storage::Capture,
    ) -> Result<Value, Failure> {
        let target = self
            .targets
            .get(&target)
            .ok_or(Failure::AccessLimited)?
            .clone();
        let permit = self
            .preparation
            .clone()
            .try_acquire_owned()
            .map_err(|_| Failure::Unavailable)?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let resolved = capture(
                &target,
                selected,
                service::hex(&rand::random::<[u8; 32]>()),
                crate::evidence_operations::now(),
            )?;
            let Configured {
                history, issuer, ..
            } = configured(&target)?;
            let signer = Identity::load_existing(issuer).map_err(invalid)?;
            let record = storage::Record::sign(resolved.plan, &signer)?;
            let plan = Preview {
                capture: resolved.capture,
                recording_gap: resolved.recording_gap,
                coverage: resolved.coverage,
                authorization: history
                    .preview(Some(record), service::hex(&rand::random::<[u8; 32]>()))?,
            };
            let c = contract(&target, &plan)?;
            Ok(json!({"target":target.id(),"digest":Self::hash(&c)?,"plan":plan,"contract":c}))
        })
        .await
        .map_err(|_| Failure::Unavailable)?
    }
    pub(super) fn erasure_status(&self, job: Value) -> Result<Value, Failure> {
        let id = job["id"].as_str().ok_or(Failure::Corrupt)?;
        let mut result = None;
        let mut attempts = 0;
        let mut interrupted = false;
        for n in 0..ATTEMPTS {
            if self
                .workspace
                .get("owner-result", &attempt_key(id, n, "started"))?
                .is_none()
            {
                break;
            }
            attempts = n + 1;
            let completed = self
                .workspace
                .get("owner-result", &attempt_key(id, n, "finished"))?;
            interrupted = completed.is_none();
            if completed.is_some() {
                result = completed;
            }
        }
        let running = self
            .active
            .lock()
            .map_err(|_| Failure::Unavailable)?
            .get(id)
            .is_some_and(|h| !h.is_finished());
        let state = if running {
            "running"
        } else if interrupted || attempts == 0 {
            "interrupted"
        } else {
            "cleanup-pending"
        };
        Ok(
            json!({"job":job,"state":state,"attempts":attempts,"result":result,"resumable":attempts<ATTEMPTS}),
        )
    }
    pub(super) async fn submit_erasure(
        self: &Arc<Self>,
        target: String,
        plan: Preview,
        expected: String,
        wait: bool,
    ) -> Result<Value, Failure> {
        let selected = self
            .targets
            .get(&target)
            .ok_or(Failure::AccessLimited)?
            .clone();
        let c = contract(&selected, &plan)?;
        let id = Self::hash(&c)?;
        if id != expected {
            return Err(Failure::Invalid);
        }
        if let Some(job) = self.workspace.get("owner-job", &id)? {
            if job["contract"] != c {
                return Err(Failure::Conflict);
            }
            return self.wait_erasure(&id, wait).await;
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
            // Recompute complete membership, including stale-frontier refusal.
            let erasure=plan.authorization.erasure.as_ref().ok_or(Failure::Invalid)?;
            let fresh=capture(&selected,plan.capture.clone(),erasure.plan.nonce.clone(),erasure.plan.recorded_at)?;
            if fresh.plan!=erasure.plan || fresh.recording_gap!=plan.recording_gap || fresh.coverage!=plan.coverage {return Err(Failure::Conflict);}
            let Configured { history, signing, .. }=configured(&selected)?;
            let current=history.current()?;
            if plan.authorization.binding!=history.binding || plan.authorization.owner!=history.owner
                || plan.authorization.previous!=current.tip || plan.authorization.sequence!=current.history.len().to_string() {return Err(Failure::Conflict);}
            fixed(&plan.authorization.nonce)?;
            let time=plan.authorization.recorded_at.parse::<u64>().map_err(invalid)?;
            if plan.authorization.version!=1 || time.to_string()!=plan.authorization.recorded_at {return Err(Failure::Invalid);}
            // Validate before retaining a job. Owner signing does not replace issuer proof.
            erasure.validate(&history.binding.owner_binding()?, &current.package()?.tip)?;
            drop(current);
            let record=custody::Record::sign(plan.authorization,&Identity::load_existing(signing).map_err(invalid)?)?;
            let mut active=owner.active.lock().map_err(|_|Failure::Unavailable)?;
            active.retain(|_,h|!h.is_finished());
            if owner.workspace.get("owner-job",&key)?.is_some() {return Ok(());}
            if !active.is_empty() || owner.workspace.owner_jobs()?.len()>=owner.max_jobs {return Err(Failure::Unavailable);}
            // Job identity includes the whole exact target configuration. Only the
            // signature is additional; no duplicate capture payload/plan is stored.
            owner.workspace.put("owner-job",&key,json!({"id":key,"contract":c,"owner_signature":record.signature,"started_at":crate::evidence_operations::now().to_string()}))?;
            owner.start_erasure(&mut active,&key,selected,record)?;
            Ok::<_,Failure>(())
        }).await.map_err(|_|Failure::Unavailable)??;
        self.wait_erasure(&id, wait).await
    }
    pub(super) async fn resume_erasure(
        self: &Arc<Self>,
        id: String,
        wait: bool,
    ) -> Result<Value, Failure> {
        fixed(&id)?;
        let job = self
            .workspace
            .get("owner-job", &id)?
            .ok_or(Failure::Missing)?;
        let c = &job["contract"];
        if c["operation"] != "erase-capture" || Self::hash(c)? != id {
            return Err(Failure::Invalid);
        }
        let target = c["target"]["id"].as_str().ok_or(Failure::Corrupt)?;
        let selected = self
            .targets
            .get(target)
            .ok_or(Failure::AccessLimited)?
            .clone();
        if serde_json::to_value(&selected).map_err(invalid)? != c["target"] {
            return Err(Failure::Conflict);
        }
        let plan: Preview = serde_json::from_value(c["plan"].clone()).map_err(invalid)?;
        let record = custody::Record {
            change: plan.authorization,
            signature: job["owner_signature"]
                .as_str()
                .ok_or(Failure::Corrupt)?
                .into(),
        };
        {
            let mut active = self.active.lock().map_err(|_| Failure::Unavailable)?;
            active.retain(|_, h| !h.is_finished());
            if !active.contains_key(&id) {
                if !active.is_empty() {
                    return Err(Failure::Unavailable);
                }
                self.start_erasure(&mut active, &id, selected, record)?;
            }
        }
        self.wait_erasure(&id, wait).await
    }
    fn start_erasure(
        self: &Arc<Self>,
        active: &mut BTreeMap<String, tokio::task::JoinHandle<()>>,
        id: &str,
        target: Target,
        record: custody::Record,
    ) -> Result<(), Failure> {
        let n = (0..ATTEMPTS)
            .find_map(|n| {
                match self
                    .workspace
                    .get("owner-result", &attempt_key(id, n, "started"))
                {
                    Ok(None) => Some(Ok(n)),
                    Ok(Some(_)) => None,
                    Err(e) => Some(Err(e)),
                }
            })
            .transpose()?
            .ok_or(Failure::Unavailable)?;
        self.workspace.put("owner-result",&attempt_key(id,n,"started"),json!({"job":id,"attempt":n,"started_at":crate::evidence_operations::now().to_string()}))?;
        let owner = self.clone();
        let key = id.to_string();
        let task = tokio::task::spawn_blocking(move || {
            let report = cleanup(&target, record, &owner.workspace, &key);
            let value = match report {
                Ok(report) => json!({"state":"cleanup-pending","report":report}),
                Err(error) => {
                    json!({"state":"cleanup-pending","error":error,"report":{"authorization":"inspect-current-custody","managed_cleanup":"pending","backup_purge":"not-performed"}})
                }
            };
            let _ = owner
                .workspace
                .put("owner-result", &attempt_key(&key, n, "finished"), value);
        });
        active.insert(id.into(), task);
        Ok(())
    }
    async fn wait_erasure(&self, id: &str, wait: bool) -> Result<Value, Failure> {
        loop {
            let status = self.status(id)?;
            if !wait || status["state"] != "running" {
                return Ok(status);
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
}
fn cleanup(
    target: &Target,
    record: custody::Record,
    journal: &Workspace,
    job: &str,
) -> Result<Value, Failure> {
    let Configured {
        root,
        history,
        replicas,
        workspaces,
        spools,
        publications,
        ..
    } = configured(target)?;
    let authorization = record.id()?;
    // Publish once, before deleting. Existing records are exact retry authority.
    history.append(record.clone())?;
    let mut archives = Vec::new();
    for path in std::iter::once(root).chain(replicas.iter().map(PathBuf::as_path)) {
        let work = || -> Result<bool, Failure> {
            private_directory(path)?;
            history.reconcile_archive(path)?;
            // Hold custody stable while reclaiming and auditing the archive.
            let current = history.current()?;
            current.check_archive(&path.join("archive.sqlite"), &history.binding)?;
            let binding = history.binding.owner_binding()?;
            Ok(match history.binding.profile {
                Profile::Admitted => {
                    store::attested::Archive::open(path, binding)?.reclaim_erased_pages()?
                }
                Profile::Copied => {
                    store::copied::Archive::open(path, binding)?.reclaim_erased_pages()?
                }
            })
        };
        archives.push(match work() {
            Ok(purged)=>json!({"root":path,"state":"payloads-erased","page_reclamation":if purged{"completed"}else{"pending"}}),
            Err(error)=>json!({"root":path,"state":"pending","error":error}),
        });
    }
    let mut queues = Vec::new();
    for database in spools {
        let work = || -> Result<Value, Failure> {
            let mut queue =
                crate::evidence_spool::Spool::open(database).map_err(|_| Failure::Unavailable)?;
            let mut result = queue.reconcile_erasure(history).map_err(|e| match e {
                crate::evidence_spool::Error::Proof(f) => f,
                crate::evidence_spool::Error::Conflict => Failure::Conflict,
                _ => Failure::Unavailable,
            })?;
            result["database"] = json!(database);
            result["page_reclamation"] = json!(if queue
                .reclaim_erased_pages()
                .map_err(|_| Failure::Unavailable)?
            {
                "completed"
            } else {
                "pending"
            });
            Ok(result)
        };
        queues.push(match work() {
            Ok(value) => value,
            Err(error) => json!({"database":database,"state":"pending","error":error}),
        });
    }
    let mut derived = Vec::new();
    // Resolve and journal publication lineage before local dependency cleanup
    // can remove the corresponding annotation declarations.
    let published = match publications::cleanup(publications, history, &record, journal, job) {
        Ok(value) => value,
        Err(error) => json!({"state":"pending","error":error}),
    };
    for workspace in workspaces {
        let work = || -> Result<Value, Failure> {
            let local = Workspace::open_for_erasure(
                &workspace.database,
                Identity::load_existing(&workspace.signing_key).map_err(invalid)?,
                crate::evidence_crypto::read_private_key(&workspace.recipient_key)
                    .map_err(invalid)?,
            )?;
            let mut removed = 0;
            let mut checkpoints = Vec::new();
            for source in std::iter::once(history).chain(publications.iter().map(|p| &p.history)) {
                let current = source.current()?;
                for record in &current.history {
                    if let Some(erasure) = &record.change.erasure {
                        if let Some(plan) =
                            local.preview_source_erasure(&source.binding, erasure, record.id()?)?
                        {
                            local.apply_erasure(&plan)?;
                            removed += plan.targets.len();
                        }
                    }
                }
                checkpoints.push(json!({"binding":source.binding,"owner_checkpoint":current.tip}));
            }
            local.reclaim_erased_pages()?;

            Ok(
                json!({"database":workspace.database,"state":"reconciled","removed_or_fenced":removed,"checkpoints":checkpoints,"page_reclamation":"completed"}),
            )
        };
        derived.push(match work() {
            Ok(value) => value,
            Err(error) => json!({"database":workspace.database,"state":"pending","error":error}),
        });
    }
    Ok(
        json!({"authorization":authorization,"archives":archives,"workspaces":derived,"spools":queues,"publications":published,"managed_cleanup":"pending-coordination",
        "remaining_preconditions":["Resolve unpublished queued derivatives and all publication copies","Reconcile every configured workspace and include all other managed workspaces","Verify enrollment and restore activation for all managed stores"],
        "backup_purge":"not-performed","activation":"not-performed"}),
    )
}

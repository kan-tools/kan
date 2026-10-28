//! Restartable owner authorization and archive cleanup. Secondary cleanup is
//! explicit pending work, never inferred from successful primary deletion.
use super::*;
mod checkpoints;
mod selections;
pub use selections::{Approval, Selector};
mod publications;
use crate::{
    evidence_erasure_history as custody, evidence_store::erasure as storage, sign::Identity,
};
pub use publications::PublicationTarget;

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
    if let Target::CaptureErasure {
        root_batch_records: Some(n),
        ..
    } = target
    {
        if *n == 0 || *n > 512 {
            return Err(Failure::Invalid);
        }
    }
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
enum Discovery {
    Pending(Value),
    Complete(Box<storage::CaptureSelection>),
}
fn discover_capture(
    journal: &Workspace,
    target: &Target,
    selected: storage::Capture,
    page_records: usize,
) -> Result<Discovery, Failure> {
    let Configured {
        root,
        history,
        keys: files,
        ..
    } = configured(target)?;
    let current = history.current()?;
    current.check_archive(&root.join("archive.sqlite"), &history.binding)?;
    let key = Owner::hash(
        &json!({"version":1,"target":target,"capture":selected,"custody":current.tip}),
    )?;
    let checkpoint = |n| format!("capture-discovery:{key}:{n}");
    let next = first_unused(|n| Ok(journal.get("owner-result", &checkpoint(n))?.is_some()))?;
    let previous = checkpoints::read(journal, &key, next)?;
    let first_sequence = previous
        .as_ref()
        .map(storage::CaptureScan::next_sequence)
        .unwrap_or(1);
    let keys = files
        .iter()
        .map(|p| crate::evidence_crypto::read_private_key(p).map_err(invalid))
        .collect::<Result<Vec<_>, _>>()?;
    let binding = history.binding.owner_binding()?;
    // Each page is durable before constructing an erasure authority. A crash or
    // stale frontier therefore continues discovery instead of restarting it.
    let retain =
        |scan: &storage::CaptureScan| checkpoints::write(journal, &key, next, scan, first_sequence);
    let resolved = match history.binding.profile {
        Profile::Admitted => {
            let archive = store::attested::Archive::open(root, binding)?;
            let scan = archive.scan_capture_erasure(
                selected,
                &keys,
                previous,
                page_records,
                16 * 1024 * 1024,
            )?;
            retain(&scan)?;
            if !scan.complete() {
                return Ok(Discovery::Pending(scan.progress()));
            }
            archive.finish_capture_selection(scan)?
        }
        Profile::Copied => {
            let archive = store::copied::Archive::open(root, binding)?;
            let scan = archive.scan_capture_erasure(
                selected,
                &keys,
                previous,
                page_records,
                16 * 1024 * 1024,
            )?;
            retain(&scan)?;
            if !scan.complete() {
                return Ok(Discovery::Pending(scan.progress()));
            }
            archive.finish_capture_selection(scan)?
        }
    };
    Ok(Discovery::Complete(Box::new(resolved)))
}
fn prepared_capture(
    journal: &Workspace,
    target: &Target,
    preview: &Preview,
) -> Result<storage::CapturePreview, Failure> {
    let erasure = preview
        .authorization
        .erasure
        .as_ref()
        .ok_or(Failure::Invalid)?;
    let expected = storage::CapturePreview {
        capture: preview.capture.clone(),
        plan: erasure.plan.clone(),
        recording_gap: preview.recording_gap,
        coverage: preview.coverage.clone(),
    };
    let value = serde_json::to_value(&expected).map_err(invalid)?;
    let receipt = format!("capture-preview:{}", Owner::hash(&value)?);
    if let Some(retained) = journal.get("owner-result", &receipt)? {
        if retained != value {
            return Err(Failure::Corrupt);
        }
        let Configured { root, history, .. } = configured(target)?;
        let current = history.current()?;
        current.check_archive(&root.join("archive.sqlite"), &history.binding)?;
        let binding = history.binding.owner_binding()?;
        let sequences = erasure
            .plan
            .targets
            .iter()
            .map(|t| t.sequence)
            .collect::<Vec<_>>();
        let fresh = match history.binding.profile {
            Profile::Admitted => store::attested::Archive::open(root, binding)?.preview_erasure(
                &sequences,
                erasure.plan.nonce.clone(),
                erasure.plan.recorded_at,
            )?,
            Profile::Copied => store::copied::Archive::open(root, binding)?.preview_erasure(
                &sequences,
                erasure.plan.nonce.clone(),
                erasure.plan.recorded_at,
            )?,
        };
        if fresh != erasure.plan {
            return Err(Failure::Conflict);
        }
        return Ok(expected);
    }
    // Older previews have no discovery receipt. Recompute their membership;
    // browser-supplied checkpoints are never trusted as selection authority.
    capture(
        target,
        preview.capture.clone(),
        erasure.plan.nonce.clone(),
        erasure.plan.recorded_at,
    )
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
        page_records: usize,
    ) -> Result<Value, Failure> {
        if page_records == 0 || page_records > 512 {
            return Err(Failure::Invalid);
        }
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
        let owner = self.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let resolved=match discover_capture(&owner.workspace,&target,selected,page_records)? {
                Discovery::Pending(progress)=>return Ok(json!({"target":target.id(),"state":"discovering","progress":progress,"effect":"Discovery only; no erasure authorization or deletion has occurred. Repeat this preview request to continue."})),
                Discovery::Complete(resolved)=>*resolved,
            };
            let Configured { root, history, issuer, .. } = configured(&target)?;
            let current = history.current()?;
            current.check_archive(&root.join("archive.sqlite"), &history.binding)?;
            let binding = history.binding.owner_binding()?;
            let nonce = service::hex(&rand::random::<[u8; 32]>());
            let now = crate::evidence_operations::now();
            let native = match history.binding.profile {
                Profile::Admitted => store::attested::Archive::open(root,binding)?.preview_erasure(&resolved.sequences,nonce,now)?,
                Profile::Copied => store::copied::Archive::open(root,binding)?.preview_erasure(&resolved.sequences,nonce,now)?,
            };
            if native.through != resolved.through || native.tip != resolved.tip { return Err(Failure::Conflict); }
            let resolved = storage::CapturePreview { capture:resolved.capture,plan:native,recording_gap:resolved.recording_gap,coverage:resolved.coverage };
            let receipt=serde_json::to_value(&resolved).map_err(invalid)?;
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
            owner.workspace.put("owner-result",&format!("capture-preview:{}",Self::hash(&receipt)?),receipt)?;
            Ok(json!({"target":target.id(),"digest":Self::hash(&c)?,"plan":plan,"contract":c}))
        })
        .await
        .map_err(|_| Failure::Unavailable)?
    }
    pub(super) fn erasure_status(&self, job: Value) -> Result<Value, Failure> {
        let id = job["id"].as_str().ok_or(Failure::Corrupt)?;
        let attempts = first_unused(|n| {
            Ok(self
                .workspace
                .get("owner-result", &attempt_key(id, n, "started"))?
                .is_some())
        })?;
        let result = if attempts == 0 {
            None
        } else {
            self.workspace
                .get("owner-result", &attempt_key(id, attempts - 1, "finished"))?
        };
        let interrupted = result.is_none();
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
        } else if result
            .as_ref()
            .is_some_and(|r| r["report"]["configured_cleanup"] == "reconciled")
        {
            "configured-cleanup-complete"
        } else {
            "cleanup-pending"
        };
        Ok(json!({"job":job,"state":state,"attempts":attempts,"result":result,"resumable":true}))
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
            let fresh=prepared_capture(&owner.workspace,&selected,&plan)?;
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
            if !active.is_empty() {return Err(Failure::Unavailable);}
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
        if c["operation"] == "erase-selection" {
            return self.resume_erasure_selection(id, wait).await;
        }
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
        let n = first_unused(|n| {
            Ok(self
                .workspace
                .get("owner-result", &attempt_key(id, n, "started"))?
                .is_some())
        })?;
        self.workspace.put("owner-result",&attempt_key(id,n,"started"),json!({"job":id,"attempt":n,"started_at":crate::evidence_operations::now().to_string()}))?;
        let owner = self.clone();
        let key = id.to_string();
        let task = tokio::task::spawn_blocking(move || {
            let report = cleanup(&target, record, &owner.workspace, &key);
            let value = match report {
                Ok(report) => {
                    json!({"state":if report["configured_cleanup"] == "reconciled" {"configured-cleanup-complete"} else {"cleanup-pending"},"report":report})
                }
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
// Read-only lineage roots, only passed after independent custody has accepted
// the exact object selection. This is not a storage deletion authority.
struct SourceSelection {
    authorization: String,
    targets: Vec<storage::Target>,
}
fn cleanup(
    target: &Target,
    record: custody::Record,
    journal: &Workspace,
    job: &str,
) -> Result<Value, Failure> {
    let Configured {
        history, signing, ..
    } = configured(target)?;
    let selected = SourceSelection {
        authorization: record.id()?,
        targets: record
            .change
            .erasure
            .as_ref()
            .ok_or(Failure::Invalid)?
            .plan
            .targets
            .clone(),
    };
    // Publish once, before deleting. Existing records are exact retry authority.
    history.append_with_checkpoint(record, &Identity::load_existing(signing).map_err(invalid)?)?;
    cleanup_selected(target, &selected, journal, job)
}
fn cleanup_selected(
    target: &Target,
    selected: &SourceSelection,
    journal: &Workspace,
    job: &str,
) -> Result<Value, Failure> {
    let Configured {
        root,
        history,
        issuer,
        replicas,
        workspaces,
        spools,
        publications,
        ..
    } = configured(target)?;
    let authorization = &selected.authorization;
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
                    let archive = store::attested::Archive::open(path, binding)?;
                    if let Some(tip) = current.storage_tip()? {
                        archive.refresh_serving_custody(
                            &Identity::load_existing(issuer).map_err(invalid)?,
                            &tip,
                        )?;
                    }
                    archive.reclaim_erased_pages()?
                }
                Profile::Copied => {
                    let archive = store::copied::Archive::open(path, binding)?;
                    if let Some(tip) = current.storage_tip()? {
                        archive.refresh_serving_custody(
                            &Identity::load_existing(issuer).map_err(invalid)?,
                            &tip,
                        )?;
                    }
                    archive.reclaim_erased_pages()?
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
    let published =
        match publications::cleanup(publications, workspaces, history, selected, journal, job) {
            Ok(value) => value,
            Err(error) => json!({"state":"pending","error":error}),
        };
    for workspace in workspaces {
        if !publications.is_empty() && published["state"] == "pending" {
            derived.push(json!({"database":workspace.database,"state":"pending","reason":"publication-lineage-plan-not-retained"}));
            continue;
        }
        let work = || -> Result<Value, Failure> {
            let local = Workspace::open_for_erasure(
                &workspace.database,
                Identity::load_existing(&workspace.signing_key).map_err(invalid)?,
                crate::evidence_crypto::read_private_key(&workspace.recipient_key)
                    .map_err(invalid)?,
            )?;
            let mut removed = 0;
            let mut pending = false;
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
                            pending |= local
                                .preview_source_erasure(&source.binding, erasure, record.id()?)?
                                .is_some();
                        }
                    }
                }
                checkpoints.push(json!({"binding":source.binding,"owner_checkpoint":current.tip}));
            }
            local.reclaim_erased_pages()?;

            Ok(
                json!({"database":workspace.database,"state":if pending {"pending-batches"}else{"reconciled"},"removed_or_fenced":removed,"checkpoints":checkpoints,"page_reclamation":"completed"}),
            )
        };
        derived.push(match work() {
            Ok(value) => value,
            Err(error) => json!({"database":workspace.database,"state":"pending","error":error}),
        });
    }
    let complete = archives
        .iter()
        .all(|v| v["state"] == "payloads-erased" && v["page_reclamation"] == "completed")
        && derived
            .iter()
            .all(|v| v["state"] == "reconciled" && v["page_reclamation"] == "completed")
        && queues.iter().all(|v| {
            v["state"] == "admitted-erasure-reconciled" && v["page_reclamation"] == "completed"
        })
        && publications::reconciled(&published);
    let mut remaining = Vec::new();
    if !complete {
        remaining.push(
            "Reconcile the reported pending archives, queues, workspaces or publication prefixes",
        );
    }
    remaining.push("Verify that every managed process and restored host launches with independently current custody; unregistered and off-host copies are outside this job's configuration");
    remaining.push("Historical backup purge is separate and has not been performed");
    Ok(
        json!({"authorization":authorization,"archives":archives,"workspaces":derived,"spools":queues,"publications":published,
        "scope":"owner-target-configuration","configured_cleanup":if complete {"reconciled"} else {"pending"},
        "managed_cleanup":if complete {"configured-scope-reconciled"} else {"pending-coordination"},
        "enrollment":"operator-verification-required","remaining_preconditions":remaining,
        "backup_purge":"not-performed","activation":"not-performed"}),
    )
}

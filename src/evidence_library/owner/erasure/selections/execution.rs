//! A signed complete consent is executed through bounded native authorizations.
//! Every exact batch is journaled before publishing independent custody.
use super::*;
fn reconcile(
    root: &Path,
    history: &custody::Access,
    current: &custody::Snapshot,
    issuer: &Path,
) -> Result<(), Failure> {
    let package = current.package()?;
    if let Some(tip) = &package.tip {
        let binding = history.binding.owner_binding()?;
        match history.binding.profile {
            Profile::Admitted => {
                let mut archive = store::attested::Archive::open(root, binding)?;
                archive.reconcile_erasure(&package, tip)?;
                archive.refresh_serving_custody(
                    &Identity::load_existing(issuer).map_err(invalid)?,
                    tip,
                )?;
            }
            Profile::Copied => {
                let mut archive = store::copied::Archive::open(root, binding)?;
                archive.reconcile_erasure(&package, tip)?;
                archive.refresh_serving_custody(
                    &Identity::load_existing(issuer).map_err(invalid)?,
                    tip,
                )?;
            }
        }
    }
    current.check_archive(&root.join("archive.sqlite"), &history.binding)
}
fn remaining<'a>(
    manifest: &Manifest,
    selected: &'a [storage::Target],
    current: &custody::Snapshot,
) -> Result<Vec<&'a storage::Target>, Failure> {
    if !current
        .history
        .iter()
        .any(|r| r.id().ok().as_ref() == Some(&manifest.custody))
    {
        return Err(Failure::AccessLimited);
    }
    let mut erased = BTreeMap::new();
    for record in &current.history {
        if let Some(record) = &record.change.erasure {
            for target in &record.plan.targets {
                if erased
                    .insert(target.sequence, target)
                    .is_some_and(|old| old != target)
                {
                    return Err(Failure::Corrupt);
                }
            }
        }
    }
    let mut pending = Vec::new();
    for target in selected {
        match erased.get(&target.sequence) {
            Some(old) if *old == target => (),
            Some(_) => return Err(Failure::Corrupt),
            None => pending.push(target),
        }
    }
    Ok(pending)
}
pub(super) fn verify_job(
    journal: &Workspace,
    target: &Target,
    id: &str,
) -> Result<(Manifest, Vec<storage::Target>), Failure> {
    let job = journal.get("owner-job", id)?.ok_or(Failure::Missing)?;
    let c = &job["contract"];
    if c["operation"] != "erase-selection" || Owner::hash(c)? != id {
        return Err(Failure::Corrupt);
    }
    let reference: Reference = serde_json::from_value(c["plan"].clone()).map_err(invalid)?;
    let (manifest, pages) = pages::read(journal, &reference.selection)?;
    pages::check_target(target, &manifest)?;
    if contract(target, &reference, &manifest)? != *c {
        return Err(Failure::Conflict);
    }
    let signature = service::unhex(job["owner_signature"].as_str().ok_or(Failure::Corrupt)?, 64)?;
    if signature.len() != 64 || !crate::sign::verify(&manifest.owner, &signed_bytes(c)?, &signature)
    {
        return Err(Failure::Corrupt);
    }
    Ok((
        manifest,
        pages.into_iter().flat_map(|p| p.targets).collect(),
    ))
}
fn execute(target: &Target, journal: &Workspace, id: &str) -> Result<Value, Failure> {
    let (manifest, selected) = verify_job(journal, target, id)?;
    let batch = match target {
        Target::CaptureErasure {
            root_batch_records, ..
        } => root_batch_records.unwrap_or(PAGE),
        _ => return Err(Failure::Invalid),
    };
    let Configured {
        root,
        history,
        issuer,
        signing,
        ..
    } = configured(target)?;
    let needed = {
        let current = history.current()?;
        // Recover any prior batch whose independent custody commit outlived the
        // worker before touching later batches or derived evidence.
        reconcile(root, history, &current, issuer)?;
        let sequences = selected.iter().map(|t| t.sequence).collect::<Vec<_>>();
        let actual = inspect(
            target,
            Some(&sequences),
            Some((manifest.through, &manifest.tip)),
        )?;
        if actual.targets != selected {
            return Err(Failure::Conflict);
        }
        remaining(&manifest, &selected, &current)?.len()
    };
    if needed > 0 {
        history.append_prepared_with_checkpoint(
            &Identity::load_existing(signing).map_err(invalid)?,
            |current| {
                // Rebase only chain coordinates under exclusive custody. Every
                // payload coordinate still comes from the signed complete consent.
                reconcile(root, history, current, issuer)?;
                let selected = remaining(&manifest, &selected, current)?
                    .into_iter()
                    .take(batch)
                    .cloned()
                    .collect::<Vec<_>>();
                if selected.is_empty() {
                    return Err(Failure::Conflict);
                }
                let sequences = selected.iter().map(|t| t.sequence).collect::<Vec<_>>();
                let actual = inspect(
                    target,
                    Some(&sequences),
                    Some((manifest.through, &manifest.tip)),
                )?;
                if actual.targets != selected {
                    return Err(Failure::Conflict);
                }
                let nonce = service::hex(&rand::random::<[u8; 32]>());
                let now = crate::evidence_operations::now();
                let binding = history.binding.owner_binding()?;
                let plan = match history.binding.profile {
                    Profile::Admitted => store::attested::Archive::open(root, binding)?
                        .preview_erasure(&sequences, nonce, now)?,
                    Profile::Copied => store::copied::Archive::open(root, binding)?
                        .preview_erasure(&sequences, nonce, now)?,
                };
                if plan.targets != selected {
                    return Err(Failure::Conflict);
                }
                let erasure = storage::Record::sign(
                    plan,
                    &Identity::load_existing(issuer).map_err(invalid)?,
                )?;
                let change = custody::Change {
                    version: 1,
                    binding: history.binding.clone(),
                    owner: history.owner.clone(),
                    sequence: current.history.len().to_string(),
                    previous: current.tip.clone(),
                    nonce: service::hex(&rand::random::<[u8; 32]>()),
                    recorded_at: now.to_string(),
                    erasure: Some(erasure),
                };
                let record = custody::Record::sign(
                    change,
                    &Identity::load_existing(signing).map_err(invalid)?,
                )?;
                journal.put(
                    "owner-result",
                    &format!("erasure:{id}:root-intent:{}", record.id()?),
                    json!({"consent":id,"record":record}),
                )?;
                Ok(record)
            },
        )?;
        let current = history.current()?;
        reconcile(root, history, &current, issuer)?;
    }
    let left = {
        let current = history.current()?;
        remaining(&manifest, &selected, &current)?.len()
    };
    let progress = json!({"selected":selected.len(),"fenced":selected.len()-left,"remaining":left,"per_attempt":batch,"selection_prefix":manifest.through.to_string()});
    if left > 0 {
        return Ok(
            json!({"authorization":id,"configured_cleanup":"pending","managed_cleanup":"pending-root-batches","root_erasure":progress,"backup_purge":"not-performed"}),
        );
    }
    let mut report = cleanup_selected(
        target,
        &SourceSelection {
            authorization: id.into(),
            targets: selected,
        },
        journal,
        id,
    )?;
    report["root_erasure"] = progress;
    Ok(report)
}
impl Owner {
    pub(in crate::evidence_library::owner) async fn submit_erasure_selection(
        self: &Arc<Self>,
        target: String,
        reference: Reference,
        expected: String,
        wait: bool,
    ) -> Result<Value, Failure> {
        fixed(&expected)?;
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
        let id = expected.clone();
        tokio::task::spawn_blocking(move|| {
            let _permit=permit;
            let (manifest,pages)=pages::read(&owner.workspace,&reference.selection)?;
            pages::check_target(&target,&manifest)?;
            let c=contract(&target,&reference,&manifest)?;
            if Owner::hash(&c)?!=expected {return Err(Failure::Invalid);}
            let mut active=owner.active.lock().map_err(|_|Failure::Unavailable)?;
            active.retain(|_,h|!h.is_finished());
            if let Some(job)=owner.workspace.get("owner-job",&expected)? {
                if job["contract"]!=c {return Err(Failure::Conflict);}
                return Ok(());
            }
            if !active.is_empty() {return Err(Failure::Unavailable);}
            let Configured {root,history,signing,..}=configured(&target)?;
            let current=history.current()?;
            if current.tip.as_ref()!=Some(&manifest.custody) {return Err(Failure::Conflict);}
            current.check_archive(&root.join("archive.sqlite"),&history.binding)?;
            let targets=pages.into_iter().flat_map(|p|p.targets).collect::<Vec<_>>();
            let sequences=targets.iter().map(|t|t.sequence).collect::<Vec<_>>();
            let actual=inspect(&target,Some(&sequences),Some((manifest.through,&manifest.tip)))?;
            if actual.targets!=targets || actual.through!=manifest.through || actual.tip!=manifest.tip {return Err(Failure::Conflict);}
            // Only approval creates owner-signed execution consent. No raw
            // client coordinates or unsigned preview signatures are authority.
            let signature=service::hex(&Identity::load_existing(signing).map_err(invalid)?.sign(&signed_bytes(&c)?).map_err(invalid)?);
            owner.workspace.put("owner-job",&expected,json!({"id":expected,"contract":c,"owner_signature":signature,"started_at":crate::evidence_operations::now().to_string()}))?;
            drop(current);
            owner.start_erasure_selection(&mut active,&expected,target)?;
            Ok::<_,Failure>(())
        }).await.map_err(|_|Failure::Unavailable)??;
        self.wait_erasure(&id, wait).await
    }
    pub(in crate::evidence_library::owner) async fn resume_erasure_selection(
        self: &Arc<Self>,
        id: String,
        wait: bool,
    ) -> Result<Value, Failure> {
        fixed(&id)?;
        let job = self
            .workspace
            .get("owner-job", &id)?
            .ok_or(Failure::Missing)?;
        let target = job["contract"]["target"]["id"]
            .as_str()
            .ok_or(Failure::Corrupt)?;
        let target = self
            .targets
            .get(target)
            .ok_or(Failure::AccessLimited)?
            .clone();
        {
            let mut active = self.active.lock().map_err(|_| Failure::Unavailable)?;
            active.retain(|_, h| !h.is_finished());
            if !active.contains_key(&id) {
                if !active.is_empty() {
                    return Err(Failure::Unavailable);
                }
                self.start_erasure_selection(&mut active, &id, target)?;
            }
        }
        self.wait_erasure(&id, wait).await
    }
    fn start_erasure_selection(
        self: &Arc<Self>,
        active: &mut BTreeMap<String, tokio::task::JoinHandle<()>>,
        id: &str,
        target: Target,
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
            let value = match execute(&target, &owner.workspace, &key) {
                Ok(report) => {
                    json!({"state":if report["configured_cleanup"]=="reconciled" {"configured-cleanup-complete"}else{"cleanup-pending"},"report":report})
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
}

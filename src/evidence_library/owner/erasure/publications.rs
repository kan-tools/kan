//! Bounded full-prefix publication discovery. Exact child authorizations are
//! encrypted in the owner journal before any publication payload is removed.
use super::*;
mod discovery;
mod queues;
mod seeds;
use crate::{
    evidence_library::proof::knowledge,
    evidence_store::inventory::{self, Availability, Budget, Inventory, PageBudget, Source},
};
use std::{
    collections::{BTreeSet, VecDeque},
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationTarget {
    pub root: PathBuf,
    pub history: custody::Access,
    pub signing_key: PathBuf,
    pub issuer_key: PathBuf,
    pub private_keys: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<crate::evidence_policy::Access>,
    #[serde(default)]
    pub replicas: Vec<PathBuf>,
    #[serde(default)]
    pub spools: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery_page_records: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery_pages: Option<usize>,
}
pub(super) fn validate(
    targets: &[PublicationTarget],
    primary: &custody::Access,
    roots: &BTreeSet<PathBuf>,
) -> Result<(), Failure> {
    if targets.len() > 16 {
        return Err(Failure::Invalid);
    }
    let mut paths = roots.clone();
    let mut bindings = BTreeSet::from([serde_json::to_string(&primary.binding).map_err(invalid)?]);
    let mut histories = BTreeSet::from([primary.directory.clone()]);
    let mut queues = BTreeSet::new();
    for t in targets {
        t.history.validate()?;
        if let Some(policy) = &t.policy {
            policy.validate()?;
            if policy.minimum.is_none()
                || policy.binding != t.history.binding
                || policy.owner != t.history.owner
            {
                return Err(Failure::Invalid);
            }
        }
        if t.discovery_page_records.is_some_and(|n| n == 0 || n > 40)
            || t.discovery_pages.is_some_and(|n| n == 0 || n > 4)
            || t.history.minimum.is_none()
            || !t.root.is_absolute()
            || !t.signing_key.is_absolute()
            || !t.issuer_key.is_absolute()
            || t.private_keys.is_empty()
            || t.private_keys.len() > 64
            || t.private_keys.iter().any(|p| !p.is_absolute())
            || t.replicas.len() > 16
            || t.spools.len() > 16
            || !bindings.insert(serde_json::to_string(&t.history.binding).map_err(invalid)?)
            || !histories.insert(t.history.directory.clone())
            || Identity::load_existing(&t.signing_key)
                .map_err(invalid)?
                .did()
                .as_str()
                != t.history.owner
            || Identity::load_existing(&t.issuer_key)
                .map_err(invalid)?
                .did()
                .as_str()
                != t.history.binding.issuer
        {
            return Err(Failure::Invalid);
        }
        for p in std::iter::once(&t.root).chain(&t.replicas) {
            if !p.is_absolute() || !paths.insert(p.clone()) {
                return Err(Failure::Invalid);
            }
        }
        for p in &t.spools {
            if !p.is_absolute() || !queues.insert(p.clone()) {
                return Err(Failure::Invalid);
            }
        }
        for p in &t.private_keys {
            crate::evidence_crypto::read_private_key(p).map_err(invalid)?;
        }
    }
    Ok(())
}
fn coordinate(binding: &Binding, sequence: &str, manifest: &str) -> Result<String, Failure> {
    serde_json::to_string(&(binding, sequence, manifest)).map_err(invalid)
}
fn identity_key(author: &str, id: &str, subject: &str) -> (String, String, String) {
    // Keep subject equality for correction lineage without retaining an erased
    // annotation's potentially sensitive subject text in the owner journal.
    let mut hash = Sha256::new();
    hash.update(b"tools.kan.annotation.subject.v1\0");
    hash.update(subject.as_bytes());
    (author.into(), id.into(), service::hex(&hash.finalize()))
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Node {
    destination: usize,
    sequence: u64,
    coordinate: String,
    identity: (String, String, String),
    cites: Vec<String>,
    parents: Vec<(String, String, String)>,
}
struct Scan {
    frontier: crate::evidence_attestation::Frontier,
    nodes: Vec<Node>,
}
const MAX_SELECTED: usize = 512;
const MAX_PLAN_BYTES: usize = 250 * 1024;
type Keys = BTreeMap<Vec<u8>, [u8; 32]>;
fn keyring(target: &PublicationTarget) -> Result<Keys, Failure> {
    target
        .private_keys
        .iter()
        .map(|p| {
            let key = crate::evidence_crypto::read_private_key(p).map_err(invalid)?;
            let public = crate::evidence_crypto::public_key(&key).map_err(invalid)?;
            Ok((Sha256::digest(public).to_vec(), key))
        })
        .collect::<Result<BTreeMap<_, _>, Failure>>()
}
struct Lineage {
    identity: (String, String, String),
    cites: Vec<String>,
    parents: Vec<(String, String, String)>,
}
fn decode(raw: &[u8], binding: &Binding, keys: &Keys) -> Result<Option<Lineage>, Failure> {
    let signed = service::SignedRequest::decode(raw)?;
    let writer = &signed.request.principal;
    if signed.request.scope != binding.scope {
        return Err(Failure::AccessLimited);
    }
    let service::Command::Append { ciphertext, .. } = signed.request.command else {
        return Err(Failure::Corrupt);
    };
    let encrypted = service::unhex(&ciphertext, service::MAX_PAYLOAD)?;
    let recipient = crate::evidence_crypto::recipient_id(&encrypted).map_err(invalid)?;
    let key = keys.get(recipient).ok_or(Failure::AccessLimited)?;
    let plaintext = crate::evidence_crypto::open(key, &binding.owner_binding()?.scope, &encrypted)
        .map_err(invalid)?;
    // Capture frames and opaque payloads have no annotation envelope.
    // Malformed JSON or unknown annotation versions cannot establish a
    // complete negative classification and therefore refuse this scan.
    if plaintext.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{') {
        return Ok(None);
    }
    let envelope: Value = serde_json::from_slice(&plaintext).map_err(invalid)?;
    if !envelope["format"]
        .as_str()
        .is_some_and(|f| f.starts_with("kan-annotation/"))
    {
        return Ok(None);
    }
    let (declaration, draft) = knowledge::decode_publication(&plaintext, writer)?;
    let id = declaration["id"].as_str().ok_or(Failure::Corrupt)?;
    let mut cites = Vec::new();
    for cite in &draft.cites {
        let (source, selected) = cite.selection.attributed_source()?;
        cites.push(coordinate(
            source,
            &selected.through,
            selected.manifest.as_deref().ok_or(Failure::Corrupt)?,
        )?);
    }
    let parents = draft
        .supersedes
        .iter()
        .chain(draft.withdraws.iter())
        .map(|id| identity_key(writer, id, &draft.subject))
        .collect();
    Ok(Some(Lineage {
        identity: identity_key(writer, id, &draft.subject),
        cites,
        parents,
    }))
}
fn budget(deadline: Instant) -> Result<Budget, Failure> {
    let duration = deadline
        .checked_duration_since(Instant::now())
        .ok_or(Failure::Unavailable)?;
    Ok(Budget {
        items: u64::MAX,
        metadata_bytes: u64::MAX,
        duration,
        cancelled: Arc::new(AtomicBool::new(false)),
    })
}
fn closure(
    nodes: &[Node],
    seeds: &BTreeSet<String>,
    identities: &BTreeSet<(String, String, String)>,
) -> BTreeSet<usize> {
    let mut by_coordinate = BTreeMap::<&str, Vec<usize>>::new();
    let mut by_parent = BTreeMap::<&(String, String, String), Vec<usize>>::new();
    for (n, node) in nodes.iter().enumerate() {
        for cite in &node.cites {
            by_coordinate.entry(cite).or_default().push(n);
        }
        for parent in &node.parents {
            by_parent.entry(parent).or_default().push(n);
        }
    }
    let mut selected = BTreeSet::new();
    let mut pending = VecDeque::new();
    pending.extend(
        nodes
            .iter()
            .enumerate()
            .filter_map(|(n, node)| identities.contains(&node.identity).then_some(n)),
    );
    // Parents can already be erased in an earlier pass; their retained opaque
    // identity must still select new correction/withdrawal descendants.
    for identity in identities {
        if let Some(children) = by_parent.get(identity) {
            pending.extend(children.iter().copied());
        }
    }
    for seed in seeds {
        if let Some(children) = by_coordinate.get(seed.as_str()) {
            pending.extend(children.iter().copied());
        }
    }
    while let Some(n) = pending.pop_front() {
        if !selected.insert(n) {
            continue;
        }
        let node = &nodes[n];
        if let Some(children) = by_coordinate.get(node.coordinate.as_str()) {
            pending.extend(children.iter().copied());
        }
        if let Some(children) = by_parent.get(&node.identity) {
            pending.extend(children.iter().copied());
        }
    }
    selected
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    binding: Binding,
    frontier: crate::evidence_proof_service::Coordinate,
    authorization: Option<custody::Record>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    version: u8,
    job: String,
    parent: String,
    destinations: Vec<Selection>,
    #[serde(default)]
    identities: BTreeSet<(String, String, String)>,
    // Cumulative opaque source coordinates through the preceding pass. Presence
    // permits bounded replay of the latest plan; old plans are upgraded once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prior_coordinates: Option<BTreeSet<String>>,
    #[serde(default)]
    more: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    seed_pages: Option<usize>,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Seeds {
    coordinates: BTreeSet<String>,
    identities: BTreeSet<(String, String, String)>,
}
impl Seeds {
    fn include(&mut self, record: &custody::Record) -> Result<(), Failure> {
        let erasure = record.change.erasure.as_ref().ok_or(Failure::Corrupt)?;
        for target in &erasure.plan.targets {
            self.coordinates.insert(coordinate(
                &record.change.binding,
                &target.sequence.to_string(),
                &target.manifest,
            )?);
        }
        Ok(())
    }
}
enum Planning {
    Pending(Value),
    Ready(Box<Plan>),
}
fn plan(
    targets: &[PublicationTarget],
    workspaces: &[WorkspaceTarget],
    primary: &custody::Access,
    parent: &SourceSelection,
    retained: &Seeds,
    cache: &discovery::Cache<'_>,
) -> Result<Planning, Failure> {
    let job = cache.job;
    let mut scans = Vec::new();
    let mut nodes = Vec::new();
    for (n, target) in targets.iter().enumerate() {
        match discovery::scan(target, n, Instant::now() + Duration::from_secs(120), cache)? {
            discovery::Outcome::Pending(progress) => return Ok(Planning::Pending(progress)),
            discovery::Outcome::Complete(scan) => {
                let scan = *scan;
                nodes.extend(scan.nodes);
                scans.push(scan.frontier);
            }
        }
    }
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut identities = retained.identities.clone();
    for workspace in workspaces {
        if Instant::now() >= deadline || !workspace.database.is_file() {
            return Err(Failure::Unavailable);
        }
        let local = Workspace::open(
            &workspace.database,
            Identity::load_existing(&workspace.signing_key).map_err(invalid)?,
            crate::evidence_crypto::read_private_key(&workspace.recipient_key).map_err(invalid)?,
        )?;
        for mut declaration in
            local.source_selection_annotations(&primary.binding, &parent.targets)?
        {
            if Instant::now() >= deadline {
                return Err(Failure::Unavailable);
            }
            declaration
                .as_object_mut()
                .ok_or(Failure::Corrupt)?
                .remove("recovered_from");
            let author = declaration["author"]
                .as_str()
                .ok_or(Failure::Corrupt)?
                .to_string();
            let encoded =
                serde_json::to_vec(&json!({"format":"kan-annotation/1","declaration":declaration}))
                    .map_err(invalid)?;
            let (declaration, draft) = knowledge::decode_publication(&encoded, &author)?;
            identities.insert(identity_key(
                &author,
                declaration["id"].as_str().ok_or(Failure::Corrupt)?,
                &draft.subject,
            ));
        }
    }
    let selected = closure(&nodes, &retained.coordinates, &identities);
    let mut more = selected.len() > MAX_SELECTED;
    // Authorize one bounded batch. Retained identities select the rest on resume.
    let selected = selected
        .into_iter()
        .take(MAX_SELECTED)
        .collect::<BTreeSet<_>>();
    let mut destinations = Vec::new();
    for (n, target) in targets.iter().enumerate() {
        let sequences = selected
            .iter()
            .filter_map(|i| (nodes[*i].destination == n).then_some(nodes[*i].sequence))
            .collect::<Vec<_>>();
        let authorization = if sequences.is_empty() {
            let latest = match target.history.binding.profile {
                Profile::Admitted => {
                    store::attested::Archive::open(
                        &target.root,
                        target.history.binding.owner_binding()?,
                    )?
                    .verify()?
                    .through
                }
                Profile::Copied => {
                    store::copied::Archive::open(
                        &target.root,
                        target.history.binding.owner_binding()?,
                    )?
                    .verify()?
                    .contents
                    .snapshot
                    .through
                }
            };
            if latest < scans[n].through {
                return Err(Failure::Conflict);
            }
            more |= latest > scans[n].through;
            None
        } else {
            let current = target.history.current()?;
            current.check_archive(&target.root.join("archive.sqlite"), &target.history.binding)?;
            let binding = target.history.binding.owner_binding()?;
            let nonce = service::hex(&rand::random::<[u8; 32]>());
            let now = crate::evidence_operations::now();
            let erase = match target.history.binding.profile {
                Profile::Admitted => store::attested::Archive::open(&target.root, binding)?
                    .preview_erasure(&sequences, nonce, now)?,
                Profile::Copied => store::copied::Archive::open(&target.root, binding)?
                    .preview_erasure(&sequences, nonce, now)?,
            };
            if erase.through < scans[n].through
                || (erase.through == scans[n].through
                    && Some(erase.tip.clone())
                        != scans[n].manifest.as_ref().map(ToString::to_string))
            {
                return Err(Failure::Conflict);
            }
            more |= erase.through > scans[n].through;
            let record = storage::Record::sign(
                erase,
                &Identity::load_existing(&target.issuer_key).map_err(invalid)?,
            )?;
            let change = target
                .history
                .preview(Some(record), service::hex(&rand::random::<[u8; 32]>()))?;
            Some(custody::Record::sign(
                change,
                &Identity::load_existing(&target.signing_key).map_err(invalid)?,
            )?)
        };
        destinations.push(Selection {
            binding: target.history.binding.clone(),
            frontier: crate::evidence_proof_service::Coordinate::from_frontier(&scans[n]),
            authorization,
        });
    }
    identities.extend(selected.iter().map(|i| nodes[*i].identity.clone()));
    Ok(Planning::Ready(Box::new(Plan {
        version: 1,
        job: job.into(),
        parent: parent.authorization.clone(),
        destinations,
        identities,
        prior_coordinates: Some(retained.coordinates.clone()),
        more,
        seed_pages: None,
    })))
}
pub(super) fn cleanup(
    targets: &[PublicationTarget],
    workspaces: &[WorkspaceTarget],
    primary: &custody::Access,
    parent: &SourceSelection,
    journal: &Workspace,
    job: &str,
) -> Result<Value, Failure> {
    if targets.is_empty() {
        return Ok(json!({"state":"not-configured"}));
    }
    let (mut retained, seed_pages) = Seeds::load(journal, job)?;
    for target in &parent.targets {
        retained.coordinates.insert(coordinate(
            &primary.binding,
            &target.sequence.to_string(),
            &target.manifest,
        )?);
    }
    queues::include_retained(journal, job, &mut retained)?;
    // Every new plan is written only after its predecessor's primary custody
    // and archive reconciliation succeed. Its cumulative seeds let a restart
    // replay just the newest authorization, without a lifetime retry ceiling.
    let plan_key = |n| {
        if n == 0 {
            format!("erasure:{job}:publication-plan")
        } else {
            format!("erasure:{job}:publication-plan:{n}")
        }
    };
    let round = first_unused(|n| Ok(journal.get("owner-result", &plan_key(n))?.is_some()))?;
    let key = plan_key(round);
    let mut begin = round.saturating_sub(1);
    if round > 0 {
        let latest: Plan = serde_json::from_value(
            journal
                .get("owner-result", &plan_key(begin))?
                .ok_or(Failure::Corrupt)?,
        )
        .map_err(invalid)?;
        if latest.prior_coordinates.is_none() {
            // Earlier versions could create at most 32 non-cumulative plans.
            if round > 32 {
                return Err(Failure::Corrupt);
            }
            begin = 0;
        }
    }
    for n in begin..round {
        let previous: Plan = serde_json::from_value(
            journal
                .get("owner-result", &plan_key(n))?
                .ok_or(Failure::Corrupt)?,
        )
        .map_err(invalid)?;
        if previous
            .seed_pages
            .is_some_and(|required| required > seed_pages)
            || previous.version != 1
            || previous.job != job
            || previous.parent != parent.authorization
            || previous.destinations.len() != targets.len()
        {
            return Err(Failure::Corrupt);
        }
        retained.identities.extend(previous.identities);
        if let Some(coordinates) = previous.prior_coordinates {
            retained.coordinates.extend(coordinates);
        }
        for (target, selection) in targets.iter().zip(previous.destinations) {
            if selection.binding != target.history.binding {
                return Err(Failure::Corrupt);
            }
            if let Some(record) = selection.authorization {
                retained.include(&record)?;
                target.history.append(record)?;
            }
            target.history.reconcile_archive(&target.root)?;
        }
    }
    let cache = discovery::Cache {
        journal,
        job,
        round,
    };
    let mut plan = match plan(targets, workspaces, primary, parent, &retained, &cache)? {
        Planning::Pending(progress) => {
            return Ok(
                json!({"state":"pending","reason":"publication-discovery","progress":progress,"pass":round}),
            )
        }
        Planning::Ready(plan) => *plan,
    };
    // Persist cumulative lineage in bounded immutable pages before removing any
    // source. The authority record carries only a required page count, not an
    // ever-growing copy of every earlier identity and coordinate.
    retained
        .identities
        .extend(std::mem::take(&mut plan.identities));
    retained
        .coordinates
        .extend(plan.prior_coordinates.take().unwrap_or_default());
    for selection in &plan.destinations {
        if let Some(record) = &selection.authorization {
            retained.include(record)?;
        }
    }
    plan.seed_pages = Some(retained.persist(journal, job)?);
    plan.prior_coordinates = Some(BTreeSet::new());
    let value = serde_json::to_value(&plan).map_err(invalid)?;
    if serde_json::to_vec(&value).map_err(invalid)?.len() > MAX_PLAN_BYTES {
        return Err(Failure::Unavailable);
    }
    journal.put("owner-result", &key, value)?;
    let mut reports = Vec::new();
    for (target, selection) in targets.iter().zip(plan.destinations) {
        if selection.binding != target.history.binding {
            return Err(Failure::Corrupt);
        }
        let result = || -> Result<Value, Failure> {
            if let Some(record) = selection.authorization {
                target.history.append(record)?;
            }
            // Queue planning must see the published-copy authorization already
            // reconciled locally; replicas are reconciled after cancellations.
            target.history.reconcile_archive(&target.root)?;
            let mut queues = Vec::new();
            for path in &target.spools {
                let reconcile = || -> Result<Value, Failure> {
                    let mut spool = crate::evidence_spool::Spool::open(path)
                        .map_err(|_| Failure::Unavailable)?;
                    let report = match spool.reconcile_erasure(&target.history) {
                        Ok(report) => report,
                        Err(crate::evidence_spool::Error::Conflict) => {
                            json!({"state":"awaiting-cancellation-completion"})
                        }
                        Err(_) => return Err(Failure::Unavailable),
                    };
                    let cancellation = queues::cancel(
                        target,
                        path,
                        &mut spool,
                        &retained.coordinates,
                        &retained.identities,
                        journal,
                        job,
                    )?;
                    let purged = spool
                        .reclaim_erased_pages()
                        .map_err(|_| Failure::Unavailable)?;
                    Ok(
                        json!({"database":path,"result":report,"cancellation":cancellation,"page_reclamation":if purged{"completed"}else{"pending"}}),
                    )
                };
                queues.push(match reconcile() {
                    Ok(value) => value,
                    Err(error) => json!({"database":path,"state":"pending","error":error}),
                });
            }
            let mut archives = Vec::new();
            for root in std::iter::once(&target.root).chain(&target.replicas) {
                let reconcile = || -> Result<bool, Failure> {
                    private_directory(root)?;
                    target.history.reconcile_archive(root)?;
                    let current = target.history.current()?;
                    current.check_archive(&root.join("archive.sqlite"), &target.history.binding)?;
                    let binding = target.history.binding.owner_binding()?;
                    Ok(match target.history.binding.profile {
                        Profile::Admitted => {
                            let archive = store::attested::Archive::open(root, binding)?;
                            if let Some(tip) = current.storage_tip()? {
                                archive.refresh_serving_custody(
                                    &Identity::load_existing(&target.issuer_key)
                                        .map_err(invalid)?,
                                    &tip,
                                )?;
                            }
                            archive.reclaim_erased_pages()?
                        }
                        Profile::Copied => {
                            let archive = store::copied::Archive::open(root, binding)?;
                            if let Some(tip) = current.storage_tip()? {
                                archive.refresh_serving_custody(
                                    &Identity::load_existing(&target.issuer_key)
                                        .map_err(invalid)?,
                                    &tip,
                                )?;
                            }
                            archive.reclaim_erased_pages()?
                        }
                    })
                };
                archives.push(match reconcile() {
                    Ok(purged)=>json!({"root":root,"state":"reconciled","page_reclamation":if purged{"completed"}else{"pending"}}),
                    Err(error)=>json!({"root":root,"state":"pending","error":error}),
                });
            }
            Ok(
                json!({"binding":selection.binding,"coverage":"selected-prefix","frontier":selection.frontier,"archives":archives,"spools":queues}),
            )
        };
        reports.push(match result() {
            Ok(value) => value,
            Err(error) => json!({"binding":target.history.binding,"state":"pending","error":error}),
        });
    }
    Ok(
        json!({"state":"selected-prefix-planned","pass":round,"discovery":if plan.more {"pending"}else{"complete"},"destinations":reports,"remaining":"Each resume replays retained authorizations and scans current prefixes for later publications. Blocked queues, unavailable lineage and unconfigured copies remain pending; this is not global erasure completion."}),
    )
}

/// Completion is scoped to this pass's declared destinations and frontiers.
/// Empty/unconfigured destinations make no statement about undiscovered copies.
pub(super) fn reconciled(report: &Value) -> bool {
    if report["state"] == "not-configured" {
        return true;
    }
    if report["state"] != "selected-prefix-planned" || report["discovery"] == "pending" {
        return false;
    }
    report["destinations"]
        .as_array()
        .is_some_and(|destinations| {
            destinations.iter().all(|d| {
                d["coverage"] == "selected-prefix"
                    && d["archives"].as_array().is_some_and(|archives| {
                        !archives.is_empty()
                            && archives.iter().all(|a| {
                                a["state"] == "reconciled" && a["page_reclamation"] == "completed"
                            })
                    })
                    && d["spools"].as_array().is_some_and(|spools| {
                        spools.iter().all(|s| {
                            s["cancellation"]["state"] == "queue-empty"
                                && s["page_reclamation"] == "completed"
                        })
                    })
            })
        })
}

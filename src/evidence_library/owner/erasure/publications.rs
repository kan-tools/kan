//! Bounded full-prefix publication discovery. Exact child authorizations are
//! encrypted in the owner journal before any publication payload is removed.
use super::*;
mod queues;
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
        if t.history.minimum.is_none()
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
    (author.into(), id.into(), subject.into())
}
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
        items: 100_000,
        metadata_bytes: 256 * 1024 * 1024,
        duration,
        cancelled: Arc::new(AtomicBool::new(false)),
    })
}
fn scan(
    target: &PublicationTarget,
    destination: usize,
    deadline: Instant,
    spent: &mut usize,
) -> Result<Scan, Failure> {
    let current = target.history.current()?;
    let binding = &target.history.binding;
    let path = target.root.join("archive.sqlite");
    current.check_archive(&path, binding)?;
    let keys = keyring(target)?;
    let inventory = Inventory::open(
        &path,
        binding.profile.inventory(),
        binding.owner_binding()?,
        budget(deadline)?,
    )?;
    let frontier = inventory.frontier().clone();
    let mut cursor = None;
    let mut nodes = Vec::new();
    loop {
        let page = inventory.page(
            cursor.as_ref(),
            PageBudget {
                rows: 40,
                record_bytes: 8 * 1024 * 1024,
                payload_bytes: 40 * store::MAX_CHUNK,
            },
            budget(deadline)?,
        )?;
        for item in page.records {
            if item.availability == Availability::Erased {
                continue;
            }
            let Source::Available { bytes, .. } = inventory::source(
                &path,
                binding.profile.inventory(),
                binding.owner_binding()?,
                &item.selection,
                service::MAX_REQUEST,
                budget(deadline)?,
            )?
            else {
                return Err(Failure::Missing);
            };
            *spent = spent.checked_add(bytes.len()).ok_or(Failure::Unavailable)?;
            if *spent > 256 * 1024 * 1024 {
                return Err(Failure::Unavailable);
            }
            let Some(lineage) = decode(&bytes, binding, &keys)? else {
                continue;
            };
            nodes.push(Node {
                destination,
                sequence: item.record.sequence,
                coordinate: coordinate(
                    binding,
                    &item.record.sequence.to_string(),
                    &item.record.manifest.cid().to_string(),
                )?,
                identity: lineage.identity,
                cites: lineage.cites,
                parents: lineage.parents,
            });
            if nodes.len() > 4096 {
                return Err(Failure::Unavailable);
            }
        }
        cursor = page.next;
        if cursor.is_none() {
            break;
        }
    }
    Ok(Scan { frontier, nodes })
}
fn closure(nodes: &[Node], seeds: &BTreeSet<String>) -> BTreeSet<usize> {
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
}
fn plan(
    targets: &[PublicationTarget],
    primary: &custody::Access,
    parent: &custody::Record,
    job: &str,
) -> Result<Plan, Failure> {
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut spent = 0;
    let mut scans = Vec::new();
    let mut nodes = Vec::new();
    for (n, target) in targets.iter().enumerate() {
        let scan = scan(target, n, deadline, &mut spent)?;
        nodes.extend(scan.nodes);
        if nodes.len() > 4096 {
            return Err(Failure::Unavailable);
        }
        scans.push(scan.frontier);
    }
    let erased = parent.change.erasure.as_ref().ok_or(Failure::Invalid)?;
    let seeds = erased
        .plan
        .targets
        .iter()
        .map(|t| coordinate(&primary.binding, &t.sequence.to_string(), &t.manifest))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let selected = closure(&nodes, &seeds);
    // A bounded immutable journal record must fit before any child erasure.
    if selected.len() > 512 {
        return Err(Failure::Unavailable);
    }
    let mut destinations = Vec::new();
    for (n, target) in targets.iter().enumerate() {
        let sequences = selected
            .iter()
            .filter_map(|i| (nodes[*i].destination == n).then_some(nodes[*i].sequence))
            .collect::<Vec<_>>();
        let authorization = if sequences.is_empty() {
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
            if erase.through != scans[n].through
                || Some(erase.tip.clone()) != scans[n].manifest.as_ref().map(ToString::to_string)
            {
                return Err(Failure::Conflict);
            }
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
    Ok(Plan {
        version: 1,
        job: job.into(),
        parent: parent.id()?,
        destinations,
        identities: selected
            .iter()
            .map(|i| nodes[*i].identity.clone())
            .collect(),
    })
}
pub(super) fn cleanup(
    targets: &[PublicationTarget],
    primary: &custody::Access,
    parent: &custody::Record,
    journal: &Workspace,
    job: &str,
) -> Result<Value, Failure> {
    if targets.is_empty() {
        return Ok(json!({"state":"not-configured"}));
    }
    let key = format!("erasure:{job}:publication-plan");
    let plan: Plan = if let Some(value) = journal.get("owner-result", &key)? {
        serde_json::from_value(value).map_err(invalid)?
    } else {
        let plan = plan(targets, primary, parent, job)?;
        let value = serde_json::to_value(&plan).map_err(invalid)?;
        if serde_json::to_vec(&value).map_err(invalid)?.len() > 250 * 1024 {
            return Err(Failure::Unavailable);
        }
        journal.put("owner-result", &key, value)?;
        plan
    };
    if plan.version != 1
        || plan.job != job
        || plan.parent != parent.id()?
        || plan.destinations.len() != targets.len()
    {
        return Err(Failure::Corrupt);
    }
    let mut seeds = parent
        .change
        .erasure
        .as_ref()
        .ok_or(Failure::Corrupt)?
        .plan
        .targets
        .iter()
        .map(|t| coordinate(&primary.binding, &t.sequence.to_string(), &t.manifest))
        .collect::<Result<BTreeSet<_>, _>>()?;
    for selection in &plan.destinations {
        if let Some(record) = &selection.authorization {
            for t in &record
                .change
                .erasure
                .as_ref()
                .ok_or(Failure::Corrupt)?
                .plan
                .targets
            {
                seeds.insert(coordinate(
                    &selection.binding,
                    &t.sequence.to_string(),
                    &t.manifest,
                )?);
            }
        }
    }
    let mut reports = Vec::new();
    for (target, selection) in targets.iter().zip(plan.destinations) {
        if selection.binding != target.history.binding {
            return Err(Failure::Corrupt);
        }
        let result = || -> Result<Value, Failure> {
            if let Some(record) = selection.authorization {
                target.history.append(record)?;
            }
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
                        &seeds,
                        &plan.identities,
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
                            store::attested::Archive::open(root, binding)?.reclaim_erased_pages()?
                        }
                        Profile::Copied => {
                            store::copied::Archive::open(root, binding)?.reclaim_erased_pages()?
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
        json!({"state":"selected-prefix-planned","destinations":reports,"remaining":"Blocked queues, analysis-job-only dependencies, later publications and unconfigured copies require coordinated cleanup; this is not global erasure completion."}),
    )
}

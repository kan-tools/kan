//! Encrypted metadata-only discovery pages. Raw requests are never journaled.
use super::*;
use crate::evidence_proof_service::Coordinate;
pub(super) struct Cache<'a> {
    pub journal: &'a Workspace,
    pub job: &'a str,
    pub round: usize,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    snapshot: Coordinate,
    next: Coordinate,
    nodes: Vec<u64>,
}
pub(super) enum Outcome {
    Pending(Value),
    Complete(Box<Scan>),
}
pub(super) fn scan(
    target: &PublicationTarget,
    destination: usize,
    deadline: Instant,
    cache: &Cache<'_>,
) -> Result<Outcome, Failure> {
    let current = target.history.current()?;
    let binding = &target.history.binding;
    let path = target.root.join("archive.sqlite");
    current.check_archive(&path, binding)?;
    let context = Owner::hash(
        &json!({"version":1,"job":cache.job,"pass":cache.round,"destination":destination,"target":target,"custody":current.tip}),
    )?;
    let page_key = |n| format!("publication-discovery:{context}:page:{n}");
    let node_key = |sequence| format!("publication-discovery:{context}:node:{sequence}");
    let mut count =
        first_unused(|n| Ok(cache.journal.get("owner-result", &page_key(n))?.is_some()))?;
    let previous = if count == 0 {
        None
    } else {
        Some(
            serde_json::from_value::<Page>(
                cache
                    .journal
                    .get("owner-result", &page_key(count - 1))?
                    .ok_or(Failure::Corrupt)?,
            )
            .map_err(invalid)?,
        )
    };
    let inventory = if let Some(page) = &previous {
        Inventory::open_at(
            &path,
            binding.profile.inventory(),
            binding.owner_binding()?,
            &page.snapshot.frontier(binding)?,
            budget(deadline)?,
        )?
    } else {
        Inventory::open(
            &path,
            binding.profile.inventory(),
            binding.owner_binding()?,
            budget(deadline)?,
        )?
    };
    let frontier = inventory.frontier().clone();
    let snapshot = Coordinate::from_frontier(&frontier);
    let mut next = previous.map(|p| p.next).unwrap_or_else(|| snapshot.clone());
    let keys = keyring(target)?;
    // Bound payload work per resume; previously completed pages remain useful.
    let work_deadline = (Instant::now() + Duration::from_secs(5)).min(deadline);
    let mut bytes = 0usize;
    for page_number in 0..target.discovery_pages.unwrap_or(4) {
        if next.through == "0" {
            break;
        }
        if page_number > 0 && (Instant::now() >= work_deadline || bytes >= 16 * 1024 * 1024) {
            break;
        }
        let page = inventory.page_from(
            &next.frontier(binding)?,
            PageBudget {
                rows: target.discovery_page_records.unwrap_or(40),
                record_bytes: 8 * 1024 * 1024,
                payload_bytes: 40 * store::MAX_CHUNK,
            },
            budget(deadline)?,
        )?;
        let mut nodes = Vec::new();
        let mut after = next.clone();
        for item in page.records {
            after = Coordinate::from_frontier(item.proof.previous());
            if item.availability == Availability::Erased {
                continue;
            }
            let Source::Available { bytes: raw, .. } = inventory::source(
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
            bytes = bytes.checked_add(raw.len()).ok_or(Failure::Unavailable)?;
            let Some(lineage) = decode(&raw, binding, &keys)? else {
                continue;
            };
            let sequence = item.record.sequence;
            let node = Node {
                destination,
                sequence,
                coordinate: coordinate(
                    binding,
                    &sequence.to_string(),
                    &item.record.manifest.cid().to_string(),
                )?,
                identity: lineage.identity,
                cites: lineage.cites,
                parents: lineage.parents,
            };
            cache.journal.put(
                "owner-result",
                &node_key(sequence),
                serde_json::to_value(node).map_err(invalid)?,
            )?;
            nodes.push(sequence);
        }
        if after == next {
            return Err(Failure::Corrupt);
        }
        cache.journal.put(
            "owner-result",
            &page_key(count),
            serde_json::to_value(Page {
                snapshot: snapshot.clone(),
                next: after.clone(),
                nodes,
            })
            .map_err(invalid)?,
        )?;
        next = after;
        count += 1;
    }
    if next.through != "0" {
        return Ok(Outcome::Pending(
            json!({"binding":binding,"frontier":snapshot,"remaining_through":next.through,"retained_pages":count,"effect":"Discovery only; publication erasure waits for a complete pinned-prefix plan."}),
        ));
    }
    let mut nodes = Vec::new();
    for n in 0..count {
        let page: Page = serde_json::from_value(
            cache
                .journal
                .get("owner-result", &page_key(n))?
                .ok_or(Failure::Corrupt)?,
        )
        .map_err(invalid)?;
        if page.snapshot != snapshot {
            return Err(Failure::Corrupt);
        }
        for sequence in page.nodes {
            let node: Node = serde_json::from_value(
                cache
                    .journal
                    .get("owner-result", &node_key(sequence))?
                    .ok_or(Failure::Corrupt)?,
            )
            .map_err(invalid)?;
            if node.destination != destination || node.sequence != sequence {
                return Err(Failure::Corrupt);
            }
            nodes.push(node);
        }
    }
    Ok(Outcome::Complete(Box::new(Scan { frontier, nodes })))
}

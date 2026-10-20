//! Typed dependency closure over authenticated workspace rows. Snapshot tips,
//! arbitrary text and unrelated CIDs are not dependency edges.
use super::*;
use crate::{
    evidence_proof_service::Binding, evidence_reader::proof::Token, evidence_store::erasure::Record,
};
use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

struct Entry {
    kind: String,
    id: String,
    value: Value,
    affected: bool,
}

fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key].as_str().ok_or(Failure::Corrupt)
}
type Node = (String, String);
const EDGE_CACHE: usize = 65_536;
type EdgeVisitor<'a> = dyn FnMut(Node, Node) -> Result<()> + 'a;

/// Cache a bounded reverse adjacency map for the common case. Larger graphs
/// use repeated passes over retained metadata, rather than refusing at a
/// lifetime edge count or retaining an unbounded second copy of the graph.
/// The caller's snapshot must remain fixed through every pass.
fn reachable(
    mut visit: impl FnMut(&mut EdgeVisitor<'_>) -> Result<()>,
    mut seen: BTreeSet<Node>,
    markers: &BTreeSet<Node>,
    deadline: Instant,
) -> Result<BTreeSet<Node>> {
    let mut edges = Some(BTreeMap::<Node, Vec<Node>>::new());
    let mut count = 0usize;
    visit(&mut |parent, child| {
        if Instant::now() >= deadline {
            return Err(Failure::Unavailable);
        }
        if markers.contains(&(parent.0.clone(), Workspace::id(&parent.0, &parent.1))) {
            seen.insert(parent.clone());
        }
        if count == EDGE_CACHE {
            edges = None;
        } else {
            count += 1;
        }
        if let Some(edges) = &mut edges {
            edges.entry(parent).or_default().push(child);
        }
        Ok(())
    })?;
    if let Some(edges) = edges {
        let mut queue = seen.iter().cloned().collect::<VecDeque<_>>();
        while let Some(node) = queue.pop_front() {
            if Instant::now() >= deadline {
                return Err(Failure::Unavailable);
            }
            if let Some(children) = edges.get(&node) {
                for child in children {
                    if seen.insert(child.clone()) {
                        queue.push_back(child.clone());
                    }
                }
            }
        }
    } else {
        loop {
            let before = seen.len();
            visit(&mut |parent, child| {
                if Instant::now() >= deadline {
                    return Err(Failure::Unavailable);
                }
                if seen.contains(&parent) {
                    seen.insert(child);
                }
                Ok(())
            })?;
            if seen.len() == before {
                break;
            }
        }
    }
    Ok(seen)
}
fn parent(v: &Value, field: &str) -> Result<Option<String>> {
    match v.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        _ => Err(Failure::Corrupt),
    }
}
fn selections(v: &Value, binding: &Binding, targets: &BTreeSet<(String, String)>) -> Result<bool> {
    let items = v.as_array().ok_or(Failure::Corrupt)?;
    let mut found = false;
    for value in items {
        let token: Token = serde_json::from_value(value.clone()).map_err(invalid)?;
        let (source, coordinate) = token.attributed_source()?;
        found |= source == binding
            && targets.contains(&(
                coordinate.through.clone(),
                coordinate.manifest.clone().ok_or(Failure::Corrupt)?,
            ));
    }
    Ok(found)
}
fn cites(v: &Value, binding: &Binding, targets: &BTreeSet<(String, String)>) -> Result<bool> {
    let cites = v.as_array().ok_or(Failure::Corrupt)?;
    if cites.is_empty() {
        return Err(Failure::Corrupt);
    }
    selections(
        &Value::Array(cites.iter().map(|c| c["selection"].clone()).collect()),
        binding,
        targets,
    )
}
fn directly_affected(
    kind: &str,
    value: &Value,
    binding: &Binding,
    targets: &BTreeSet<(String, String)>,
) -> Result<bool> {
    match kind {
        "annotation" | "analysis-job" | "analysis-input" => {
            cites(&value["draft"]["cites"], binding, targets)
        }
        "search-page" => {
            if value["version"] != 3 {
                return Err(Failure::Corrupt);
            }
            let docs = value["documents"].as_array().ok_or(Failure::Corrupt)?;
            selections(
                &Value::Array(
                    docs.iter()
                        .map(|d| d["record"]["selection"].clone())
                        .collect(),
                ),
                binding,
                targets,
            )
        }
        "view" if value["kind"] == "import" => {
            let records = value["records"].as_array().ok_or(Failure::Corrupt)?;
            let mut yes = selections(
                &Value::Array(records.iter().map(|r| r["selection"].clone()).collect()),
                binding,
                targets,
            )?;
            if let Some(controls) = value["query"]["view"].get("controls") {
                for control in controls.as_array().ok_or(Failure::Corrupt)? {
                    for part in control["parts"].as_array().ok_or(Failure::Corrupt)? {
                        yes |= selections(&part["selections"], binding, targets)?;
                    }
                }
            }
            Ok(yes)
        }
        _ => Ok(false),
    }
}
impl Workspace {
    /// Read-only dependency discovery over owner-verified selection coordinates;
    /// these coordinates are not accepted by any deletion operation.
    /// Visit one declaration at a time while retaining the authenticated read
    /// snapshot. The visitor must not reenter this workspace. Publication
    /// planning needs identities, not a retained copy of every selected body.
    pub(crate) fn visit_source_selection_annotations(
        &self,
        binding: &Binding,
        coordinates: &[crate::evidence_store::erasure::Target],
        mut visit: impl FnMut(Value) -> Result<()>,
    ) -> Result<()> {
        let conn = self.conn.lock().map_err(invalid)?;
        let tx = conn.unchecked_transaction().map_err(invalid)?;
        let selected = self.selection_dependency_ids(&tx, binding, coordinates)?;
        for (kind, id) in selected {
            if kind != "annotation" {
                continue;
            }
            let body: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT body FROM entries WHERE kind=? AND id=?",
                    params![kind, id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(invalid)?;
            if let Some(body) = body {
                visit(self.unseal(&kind, &id, &body)?)?;
            }
        }
        Ok(())
    }
    /// Resolve direct citations and transitive correction, promotion, retry and
    /// trigger edges under exclusive maintenance. The caller must independently
    /// authorize the record; its issuer signature alone is not owner consent.
    /// None means no retained matching dependencies, not global erasure complete.
    pub fn preview_source_erasure(
        &self,
        binding: &Binding,
        record: &Record,
        authorization: String,
    ) -> Result<Option<Plan>> {
        if !self.erasure_maintenance {
            return Err(Failure::Unavailable);
        }
        fixed(&authorization)?;
        let ids = {
            let conn = self.conn.lock().map_err(invalid)?;
            self.erasure_dependency_ids(&conn, binding, record)?
        };
        if ids.is_empty() {
            return Ok(None);
        }
        let mut ids = ids;
        ids.sort_by_key(|(kind, id)| (kind == "analysis-job", kind.clone(), id.clone()));
        let selected = {
            let conn = self.conn.lock().map_err(invalid)?;
            let mut total = 0usize;
            let mut selected = Vec::new();
            for (kind, id) in ids {
                let size: Option<i64> = conn
                    .query_row(
                        "SELECT length(body) FROM entries WHERE kind=? AND id=?",
                        params![kind, id],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(invalid)?;
                let size = usize::try_from(size.unwrap_or(0)).map_err(invalid)?;
                if selected.len() == 4096 || total + size > 64 * 1024 * 1024 {
                    break;
                }
                total += size;
                selected.push((kind, id));
            }
            selected
        };
        self.preview_erasure_ids(&selected, authorization).map(Some)
    }
    pub(in crate::evidence_workspace) fn erasure_dependency_ids(
        &self,
        conn: &Connection,
        binding: &Binding,
        record: &Record,
    ) -> Result<Vec<(String, String)>> {
        record.validate(&binding.owner_binding()?, &record.plan.previous)?;
        self.selection_dependency_ids(conn, binding, &record.plan.targets)
    }
    fn selection_dependency_ids(
        &self,
        conn: &Connection,
        binding: &Binding,
        coordinates: &[crate::evidence_store::erasure::Target],
    ) -> Result<Vec<(String, String)>> {
        let deadline = Instant::now() + Duration::from_secs(120);
        let targets = coordinates
            .iter()
            .map(|t| (t.sequence.to_string(), t.manifest.clone()))
            .collect::<BTreeSet<_>>();
        let mut markers = BTreeSet::new();
        let mut selected = BTreeSet::new();
        let entries = {
            let mut q = conn
                .prepare("SELECT kind,id,body FROM entries ORDER BY kind,id")
                .map_err(invalid)?;
            let rows = q
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                    ))
                })
                .map_err(invalid)?;
            let mut entries = Vec::new();
            for row in rows {
                if Instant::now() >= deadline {
                    return Err(Failure::Unavailable);
                }
                let (kind, id, bytes) = row.map_err(invalid)?;
                if !allowed(&kind) && kind != "erasure" {
                    continue;
                }
                if kind == "erasure" {
                    let value = self.unseal(&kind, &id, &bytes)?;
                    let target_kind = text(&value, "kind")?;
                    let target_id = text(&value, "id")?;
                    if id != marker_id(target_kind, target_id)
                        || !erased(self, conn, target_kind, target_id)?
                    {
                        return Err(Failure::Corrupt);
                    }
                    markers.insert((target_kind.to_string(), target_id.to_string()));
                    continue;
                }
                // Reintroduced raw bytes under a tombstone are corruption, never
                // treated as an empty/clean destination by the coordinator.
                if erased(self, conn, &kind, &id)? {
                    return Err(Failure::Corrupt);
                }
                let value = self.unseal(&kind, &id, &bytes)?;
                let affected = directly_affected(&kind, &value, binding, &targets)?;
                if affected {
                    selected.insert((kind.clone(), id.clone()));
                }
                // Cache text, model inputs/outputs and note bodies cannot add
                // graph edges. Drop them after checking their typed citations.
                if matches!(kind.as_str(), "search-page" | "view" | "analysis-input") {
                    continue;
                }
                let value = serde_json::json!({
                    "id":value.get("id"), "version":value.get("version"),
                    "manifest":value.get("manifest"), "annotation":value.get("annotation"), "job":value.get("job"),
                    "draft": {
                        "supersedes":value["draft"].get("supersedes"), "withdraws":value["draft"].get("withdraws"),
                        "derived_from":value["draft"].get("derived_from").cloned().unwrap_or_else(||serde_json::json!([])),
                        "retry_of":value["draft"].get("retry_of"), "trigger_annotation":value["draft"].get("trigger_annotation")
                    }
                });
                entries.push(Entry {
                    value,
                    kind,
                    id,
                    affected,
                });
            }
            entries
        };
        let mut annotations = BTreeSet::new();
        let mut jobs = BTreeSet::new();
        let mut annotation_entries = BTreeMap::new();
        let mut job_entries = BTreeMap::new();
        for e in &entries {
            let affected = match e.kind.as_str() {
                "annotation" => {
                    let id = text(&e.value, "id")?;
                    if e.id != Self::id("annotation", id) {
                        return Err(Failure::Corrupt);
                    }
                    annotation_entries.insert(id.to_string(), e);
                    let yes = e.affected;
                    if yes {
                        annotations.insert(id.to_string());
                    }
                    yes
                }
                "analysis-job" => {
                    let id = text(&e.value, "id")?;
                    if e.id != Self::id("analysis-job", id) {
                        return Err(Failure::Corrupt);
                    }
                    job_entries.insert(id.to_string(), e);
                    let yes = e.affected;
                    if yes {
                        jobs.insert(id.to_string());
                    }
                    yes
                }
                _ => false,
            };
            if affected {
                selected.insert((e.kind.clone(), e.id.clone()));
            }
        }
        // A result contains model output without its input citations. Missing
        // job provenance must not turn it into an unrelated/clean output.
        let result_ids = job_entries
            .keys()
            .map(|id| Self::id("analysis-result", id))
            .collect::<BTreeSet<_>>();
        for e in &entries {
            if e.kind == "analysis-result" && !result_ids.contains(&e.id) {
                return Err(Failure::Corrupt);
            }
            if e.kind == "analysis-event" {
                let id = text(&e.value, "job")?;
                if markers.contains(&("analysis-job".into(), Self::id("analysis-job", id))) {
                    jobs.insert(id.into());
                } else if !job_entries.contains_key(id) {
                    return Err(Failure::Corrupt);
                }
            }
            if e.kind == "analysis-trigger" {
                let id = text(&e.value, "annotation")?;
                if markers.contains(&("annotation".into(), Self::id("annotation", id))) {
                    annotations.insert(id.into());
                } else if !annotation_entries.contains_key(id) {
                    return Err(Failure::Corrupt);
                }
            }
        }
        let roots = annotations
            .iter()
            .map(|id| ("annotation".into(), id.clone()))
            .chain(jobs.iter().map(|id| ("analysis-job".into(), id.clone())))
            .collect::<BTreeSet<Node>>();
        let seen = reachable(
            |add| {
                for (id, e) in &annotation_entries {
                    let d = &e.value["draft"];
                    let child = ("annotation".into(), id.clone());
                    for field in ["supersedes", "withdraws"] {
                        if let Some(p) = parent(d, field)? {
                            add(("annotation".into(), p), child.clone())?;
                        }
                    }
                    if let Some(parents) = d.get("derived_from") {
                        for p in parents.as_array().ok_or(Failure::Corrupt)? {
                            add(
                                (
                                    "analysis-job".into(),
                                    p.as_str().ok_or(Failure::Corrupt)?.into(),
                                ),
                                child.clone(),
                            )?;
                        }
                    }
                }
                for (id, e) in &job_entries {
                    let d = &e.value["draft"];
                    let child = ("analysis-job".into(), id.clone());
                    if let Some(p) = parent(d, "retry_of")? {
                        add(("analysis-job".into(), p), child.clone())?;
                    }
                    if let Some(p) = parent(d, "trigger_annotation")? {
                        add(("annotation".into(), p), child)?;
                    }
                }
                Ok(())
            },
            roots,
            &markers,
            deadline,
        )?;
        for (kind, id) in seen {
            match kind.as_str() {
                "annotation" => {
                    annotations.insert(id);
                }
                "analysis-job" => {
                    jobs.insert(id);
                }
                _ => return Err(Failure::Corrupt),
            }
        }
        for id in &annotations {
            selected.insert(("annotation".into(), Self::id("annotation", id)));
        }
        for id in &jobs {
            for kind in ["analysis-job", "analysis-input", "analysis-result"] {
                selected.insert((kind.into(), Self::id(kind, id)));
            }
            for n in 1..=2 {
                selected.insert((
                    "analysis-event".into(),
                    Self::id("analysis-event", &format!("{id}/{n}")),
                ));
            }
        }
        for e in &entries {
            if e.kind == "annotation-publication" {
                let manifest = text(&e.value, "manifest")?;
                let annotation = text(&e.value, "annotation")?;
                if e.value["version"] != 1 || e.id != Self::id("annotation-publication", manifest) {
                    return Err(Failure::Corrupt);
                }
                if annotations.contains(annotation)
                    || markers.contains(&("annotation".into(), Self::id("annotation", annotation)))
                {
                    selected.insert((e.kind.clone(), e.id.clone()));
                }
            }
            if e.kind == "analysis-trigger" && annotations.contains(text(&e.value, "annotation")?) {
                selected.insert((e.kind.clone(), e.id.clone()));
            }
            if e.kind == "analysis-event" && jobs.contains(text(&e.value, "job")?) {
                selected.insert((e.kind.clone(), e.id.clone()));
            }
        }
        selected.retain(|id| !markers.contains(id));
        Ok(selected.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(kind: &str, id: &str) -> Node {
        (kind.into(), id.into())
    }
    fn large_graph(add: &mut EdgeVisitor<'_>) -> Result<()> {
        // These retained declarations do not depend on the erased source.
        for n in 0..=EDGE_CACHE {
            add(
                node("analysis-job", "unrelated"),
                node("annotation", &format!("other-{n}")),
            )?;
        }
        // Reverse order forces more than one pass. The cycle must converge.
        add(
            node("annotation", "promotion"),
            node("annotation", "withdrawal"),
        )?;
        add(
            node("analysis-job", "retry"),
            node("annotation", "promotion"),
        )?;
        add(
            node("annotation", "withdrawal"),
            node("analysis-job", "retry"),
        )?;
        add(node("annotation", "erased"), node("analysis-job", "retry"))?;
        Ok(())
    }
    fn erased_marker() -> BTreeSet<Node> {
        BTreeSet::from([("annotation".into(), Workspace::id("annotation", "erased"))])
    }
    #[test]
    fn large_dependency_graph_preserves_tombstone_descendants_and_excludes_unrelated_edges() {
        let selected = reachable(
            large_graph,
            BTreeSet::new(),
            &erased_marker(),
            Instant::now() + Duration::from_secs(30),
        )
        .unwrap();
        assert_eq!(
            selected,
            BTreeSet::from([
                node("annotation", "erased"),
                node("analysis-job", "retry"),
                node("annotation", "promotion"),
                node("annotation", "withdrawal")
            ])
        );
    }
    #[test]
    fn fallback_failure_and_expired_work_never_return_partial_dependency_closure() {
        let mut passes = 0;
        let result = reachable(
            |add| {
                passes += 1;
                if passes == 2 {
                    return Err(Failure::Corrupt);
                }
                large_graph(add)
            },
            BTreeSet::new(),
            &erased_marker(),
            Instant::now() + Duration::from_secs(30),
        );
        assert!(matches!(result, Err(Failure::Corrupt)));
        assert_eq!(passes, 2);
        assert!(matches!(
            reachable(
                large_graph,
                BTreeSet::new(),
                &erased_marker(),
                Instant::now() - Duration::from_secs(1)
            ),
            Err(Failure::Unavailable)
        ));
    }
    #[test]
    fn cached_and_uncached_graphs_have_identical_dependency_closure() {
        let edges = [
            (node("annotation", "child"), node("analysis-job", "retry")),
            (node("analysis-job", "root"), node("annotation", "child")),
            (node("analysis-job", "retry"), node("annotation", "child")),
        ];
        let roots = BTreeSet::from([node("analysis-job", "root")]);
        let run = |repeat| {
            reachable(
                |add| {
                    for _ in 0..repeat {
                        for (parent, child) in &edges {
                            add(parent.clone(), child.clone())?;
                        }
                    }
                    Ok(())
                },
                roots.clone(),
                &BTreeSet::new(),
                Instant::now() + Duration::from_secs(30),
            )
            .unwrap()
        };
        let expected = BTreeSet::from([
            node("analysis-job", "root"),
            node("annotation", "child"),
            node("analysis-job", "retry"),
        ]);
        assert_eq!(run(1), expected);
        assert_eq!(run(EDGE_CACHE / 3 + 1), expected);
    }
}

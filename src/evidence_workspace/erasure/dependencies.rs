//! Typed dependency closure over authenticated workspace rows. Snapshot tips,
//! arbitrary text and unrelated CIDs are not dependency edges.
use super::*;
use crate::{
    evidence_proof_service::Binding, evidence_reader::proof::Token, evidence_store::erasure::Record,
};
use std::collections::{BTreeMap, VecDeque};

struct Entry {
    kind: String,
    id: String,
    value: Value,
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key].as_str().ok_or(Failure::Corrupt)
}
type Node = (String, String);
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
impl Workspace {
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
        self.preview_erasure_ids(&ids, authorization).map(Some)
    }
    pub(in crate::evidence_workspace) fn erasure_dependency_ids(
        &self,
        conn: &Connection,
        binding: &Binding,
        record: &Record,
    ) -> Result<Vec<(String, String)>> {
        record.validate(&binding.owner_binding()?, &record.plan.previous)?;
        let targets = record
            .plan
            .targets
            .iter()
            .map(|t| (t.sequence.to_string(), t.manifest.clone()))
            .collect::<BTreeSet<_>>();
        let mut markers = BTreeSet::new();
        let entries = {
            let mut q = conn
                .prepare("SELECT kind,id,body FROM entries ORDER BY kind,id LIMIT 16385")
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
            let mut total = 0usize;
            for (n, row) in rows.enumerate() {
                if n >= 16384 {
                    return Err(Failure::Unavailable);
                }
                let (kind, id, bytes) = row.map_err(invalid)?;
                if !allowed(&kind) && kind != "erasure" {
                    continue;
                }
                total = total.checked_add(bytes.len()).ok_or(Failure::Unavailable)?;
                if total > 64 * 1024 * 1024 {
                    return Err(Failure::Unavailable);
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
                entries.push(Entry {
                    value: self.unseal(&kind, &id, &bytes)?,
                    kind,
                    id,
                });
            }
            entries
        };
        let mut selected = BTreeSet::new();
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
                    let yes = cites(&e.value["draft"]["cites"], binding, &targets)?;
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
                    let yes = cites(&e.value["draft"]["cites"], binding, &targets)?;
                    if yes {
                        jobs.insert(id.to_string());
                    }
                    yes
                }
                // Inputs can survive a crash before the job declaration. Their
                // exact hashed entry is still removed based on their own draft.
                "analysis-input" => cites(&e.value["draft"]["cites"], binding, &targets)?,
                "search-page" => {
                    if e.value["version"] != 3 {
                        return Err(Failure::Corrupt);
                    }
                    let docs = e.value["documents"].as_array().ok_or(Failure::Corrupt)?;
                    selections(
                        &Value::Array(
                            docs.iter()
                                .map(|d| d["record"]["selection"].clone())
                                .collect(),
                        ),
                        binding,
                        &targets,
                    )?
                }
                "view" if e.value["kind"] == "import" => {
                    let records = e.value["records"].as_array().ok_or(Failure::Corrupt)?;
                    let mut yes = selections(
                        &Value::Array(records.iter().map(|r| r["selection"].clone()).collect()),
                        binding,
                        &targets,
                    )?;
                    if let Some(controls) = e.value["query"]["view"].get("controls") {
                        for control in controls.as_array().ok_or(Failure::Corrupt)? {
                            for part in control["parts"].as_array().ok_or(Failure::Corrupt)? {
                                yes |= selections(&part["selections"], binding, &targets)?;
                            }
                        }
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
        // Reverse declared edges give linear traversal, including descendants
        // of minimal tombstones retained by an earlier cleanup attempt.
        let mut edges: BTreeMap<Node, Vec<Node>> = BTreeMap::new();
        let mut edge_count = 0usize;
        let mut add = |kind: &str, id: String, child: Node| -> Result<()> {
            edge_count += 1;
            if edge_count > 65536 {
                return Err(Failure::Unavailable);
            }
            edges.entry((kind.into(), id)).or_default().push(child);
            Ok(())
        };
        for (id, e) in &annotation_entries {
            let d = &e.value["draft"];
            let child = ("annotation".into(), id.clone());
            for field in ["supersedes", "withdraws"] {
                if let Some(p) = parent(d, field)? {
                    add("annotation", p, child.clone())?;
                }
            }
            if let Some(parents) = d.get("derived_from") {
                for p in parents.as_array().ok_or(Failure::Corrupt)? {
                    add(
                        "analysis-job",
                        p.as_str().ok_or(Failure::Corrupt)?.into(),
                        child.clone(),
                    )?;
                }
            }
        }
        for (id, e) in &job_entries {
            let d = &e.value["draft"];
            let child = ("analysis-job".into(), id.clone());
            if let Some(p) = parent(d, "retry_of")? {
                add("analysis-job", p, child.clone())?;
            }
            if let Some(p) = parent(d, "trigger_annotation")? {
                add("annotation", p, child)?;
            }
        }
        let mut seen = annotations
            .iter()
            .map(|id| ("annotation".into(), id.clone()))
            .chain(jobs.iter().map(|id| ("analysis-job".into(), id.clone())))
            .collect::<BTreeSet<Node>>();
        for node in edges.keys() {
            if markers.contains(&(node.0.clone(), Self::id(&node.0, &node.1))) {
                seen.insert(node.clone());
            }
        }
        let mut queue = seen.iter().cloned().collect::<VecDeque<_>>();
        while let Some(node) = queue.pop_front() {
            if let Some(children) = edges.get(&node) {
                for child in children {
                    if seen.insert(child.clone()) {
                        queue.push_back(child.clone());
                    }
                }
            }
        }
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

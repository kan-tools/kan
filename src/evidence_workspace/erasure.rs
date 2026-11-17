//! Owner-side exact workspace cleanup. A coordinator must resolve dependencies
//! and authorize the selection before calling this API. Tombstones retain no
//! removed values and fence future writes, including not-yet-produced results.
mod dependencies;
pub(super) use dependencies::project_annotations;
mod enrollment;
use super::*;
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub kind: String,
    pub id: String,
    pub ciphertext_digest: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub version: u8,
    pub author: String,
    pub scope: String,
    /// Independently retained owner authorization record ID, not a content body.
    pub authorization: String,
    pub targets: Vec<Target>,
}
impl Plan {
    pub fn digest(&self) -> Result<String> {
        Ok(evidence_service::hex(&Sha256::digest(
            serde_json::to_vec(self).map_err(invalid)?,
        )))
    }
}
fn fixed(s: &str) -> Result<()> {
    if s.len() != 64 || evidence_service::unhex(s, 32)?.len() != 32 {
        return Err(Failure::Invalid);
    }
    Ok(())
}
fn allowed(kind: &str) -> bool {
    matches!(
        kind,
        "search-page"
            | "view"
            | "annotation"
            | "annotation-publication"
            | "analysis-job"
            | "analysis-input"
            | "analysis-result"
            | "analysis-event"
            | "analysis-trigger"
    )
}
fn marker_id(kind: &str, id: &str) -> String {
    Workspace::id("erasure", &format!("{kind}:{id}"))
}
fn body(conn: &Connection, kind: &str, id: &str) -> Result<Option<Vec<u8>>> {
    conn.query_row(
        "SELECT body FROM entries WHERE kind=? AND id=?",
        params![kind, id],
        |r| r.get(0),
    )
    .optional()
    .map_err(invalid)
}
fn marker(plan: &Plan, target: &Target, digest: &str) -> Value {
    serde_json::json!({"version":1,"plan":digest,"authorization":plan.authorization,"kind":target.kind,"id":target.id})
}
// Derive scope while authenticated rows still exist, including ordinary
// correction/withdrawal ancestors. Unknown or bounded-out history must retain
// the legacy conservative behavior, never manufacture a complete collection.
fn authored_collections(
    workspace: &Workspace,
    conn: &Connection,
    value: Value,
    deadline: std::time::Instant,
) -> Result<Option<Vec<String>>> {
    let mut pending = vec![value];
    let mut seen = BTreeSet::new();
    let mut scopes = BTreeSet::new();
    let mut ancestry_bytes = 0usize;
    for _ in 0..256 {
        if std::time::Instant::now() >= deadline {
            return Ok(None);
        }
        let Some(value) = pending.pop() else {
            return Ok((scopes.len() <= 256).then(|| scopes.into_iter().collect()));
        };
        let Ok(draft) = serde_json::from_value::<crate::evidence_library::AnnotationDraft>(
            value["draft"].clone(),
        ) else {
            return Ok(None);
        };
        if let Some(batch) = draft.authored {
            let Some(author) = value["author"].as_str() else {
                return Ok(None);
            };
            if batch.decoded(author).is_err() {
                return Ok(None);
            }
            scopes.insert(workspace.authored_collection_commitment(&batch.source)?);
        }
        for parent in [draft.supersedes, draft.withdraws].into_iter().flatten() {
            if !seen.insert(parent.clone()) {
                continue;
            }
            let id = Workspace::id("annotation", &parent);
            if erased(workspace, conn, "annotation", &id)? {
                let marker_key = marker_id("annotation", &id);
                let bytes = body(conn, "erasure", &marker_key)?.ok_or(Failure::Corrupt)?;
                let marker = workspace.unseal("erasure", &marker_key, &bytes)?;
                let Some(known) = marker.get("authored_collections") else {
                    return Ok(None);
                };
                let known = known.as_array().ok_or(Failure::Corrupt)?;
                if known.len() > 256 {
                    return Err(Failure::Corrupt);
                }
                for scope in known {
                    let scope = scope.as_str().ok_or(Failure::Corrupt)?;
                    fixed(scope)?;
                    scopes.insert(scope.to_owned());
                }
            } else {
                let Some(bytes) = body(conn, "annotation", &id)? else {
                    return Ok(None);
                };
                ancestry_bytes = ancestry_bytes.saturating_add(bytes.len());
                if ancestry_bytes > 4 * 1024 * 1024 {
                    return Ok(None);
                }
                pending.push(workspace.unseal("annotation", &id, &bytes)?);
            }
        }
    }
    Ok(None)
}
/// A valid tombstone hides even a reintroduced payload; damaged authority fails
/// closed rather than exposing the row. Ordinary workspace writes cannot create it.
pub(super) fn erased(
    workspace: &Workspace,
    conn: &Connection,
    kind: &str,
    id: &str,
) -> Result<bool> {
    if kind == "erasure" {
        return Ok(false);
    }
    let key = marker_id(kind, id);
    let Some(bytes) = body(conn, "erasure", &key)? else {
        return Ok(false);
    };
    let value = workspace.unseal("erasure", &key, &bytes)?;
    if value["version"] != 1 || value["kind"] != kind || value["id"] != id {
        return Err(Failure::Corrupt);
    }
    fixed(value["plan"].as_str().ok_or(Failure::Corrupt)?)?;
    fixed(value["authorization"].as_str().ok_or(Failure::Corrupt)?)?;
    Ok(true)
}
impl Workspace {
    /// Erasure requires all workspace users (including older binaries) to stop.
    /// The exclusive maintenance lease is held for this handle's entire lifetime.
    pub fn open_for_erasure(path: &Path, signer: Identity, private_key: [u8; 32]) -> Result<Self> {
        private(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .ok_or(Failure::Invalid)?,
            true,
        )?;
        private(path, false)?;
        let maintenance = MaintenanceLease::acquire(path, true)?;
        let mut workspace = Self::open_locked(path, signer, private_key, maintenance, false)?;
        workspace.erasure_maintenance = true;
        Ok(workspace)
    }

    /// Select known logical keys, including absent outputs that must never appear.
    /// This does not discover the capture's complete dependency/copy cascade.
    pub fn preview_erasure(
        &self,
        keys: &[(String, String)],
        authorization: String,
    ) -> Result<Plan> {
        if keys
            .iter()
            .any(|(kind, key)| !allowed(kind) || key.len() > 4096)
        {
            return Err(Failure::Invalid);
        }
        let ids = keys
            .iter()
            .map(|(kind, key)| (kind.clone(), Self::id(kind, key)))
            .collect::<Vec<_>>();
        self.preview_erasure_ids(&ids, authorization)
    }
    fn preview_erasure_ids(&self, ids: &[(String, String)], authorization: String) -> Result<Plan> {
        fixed(&authorization)?;
        if ids.is_empty() || ids.len() > 4096 {
            return Err(Failure::Invalid);
        }
        let conn = self.conn.lock().map_err(invalid)?;
        let tx = conn.unchecked_transaction().map_err(invalid)?;
        let mut targets = Vec::new();
        let mut selected = BTreeSet::new();
        let mut total = 0usize;
        for (kind, id) in ids {
            if !allowed(kind) {
                return Err(Failure::Invalid);
            }
            fixed(id)?;
            if !selected.insert((kind, id.clone())) || erased(self, &tx, kind, id)? {
                return Err(Failure::Conflict);
            }
            let bytes = body(&tx, kind, id)?;
            if let Some(bytes) = &bytes {
                total = total.checked_add(bytes.len()).ok_or(Failure::Invalid)?;
                if total > 64 * 1024 * 1024 {
                    return Err(Failure::Unavailable);
                }
                self.unseal(kind, id, bytes)?;
            }
            targets.push(Target {
                kind: kind.clone(),
                id: id.clone(),
                ciphertext_digest: bytes.map(|b| evidence_service::hex(&Sha256::digest(b))),
            });
        }
        targets.sort_by(|a, b| (&a.kind, &a.id).cmp(&(&b.kind, &b.id)));
        tx.commit().map_err(invalid)?;
        Ok(Plan {
            version: 1,
            author: self.author(),
            scope: evidence_service::hex(&self.scope),
            authorization,
            targets,
        })
    }
    /// Reclaim SQLite pages while all workspace users are stopped. Filesystem
    /// snapshots and independent backups remain outside this operation.
    pub fn reclaim_erased_pages(&self) -> Result<()> {
        if !self.erasure_maintenance {
            return Err(Failure::Unavailable);
        }
        let conn = self.conn.lock().map_err(invalid)?;
        conn.execute_batch("PRAGMA secure_delete=ON; VACUUM;")
            .map_err(invalid)?;
        Ok(())
    }
    /// Atomic ciphertext removal and persistent no-recreation fences. The caller
    /// is a trusted owner coordinator; this is not a browser authority endpoint.
    pub fn apply_erasure(&self, plan: &Plan) -> Result<Value> {
        if !self.erasure_maintenance {
            return Err(Failure::Unavailable);
        }
        fixed(&plan.authorization)?;
        if plan.version != 1
            || plan.author != self.author()
            || plan.scope != evidence_service::hex(&self.scope)
            || plan.targets.is_empty()
            || plan.targets.len() > 4096
        {
            return Err(Failure::Invalid);
        }
        let digest = plan.digest()?;
        let mut conn = self.conn.lock().map_err(invalid)?;
        conn.execute_batch("PRAGMA secure_delete=ON;")
            .map_err(invalid)?;
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(invalid)?;
        let mut prior = None;
        let mut writes = Vec::new();
        let mut total = 0usize;
        let scope_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        for target in &plan.targets {
            if !allowed(&target.kind) {
                return Err(Failure::Invalid);
            }
            fixed(&target.id)?;
            if let Some(d) = &target.ciphertext_digest {
                fixed(d)?;
            }
            let coordinate = (&target.kind, &target.id);
            if prior.is_some_and(|p| p >= coordinate) {
                return Err(Failure::Invalid);
            }
            prior = Some(coordinate);
            let id = marker_id(&target.kind, &target.id);
            let mut value = marker(plan, target, &digest);
            if let Some(existing) = body(&tx, "erasure", &id)? {
                let mut existing = self.unseal("erasure", &id, &existing)?;
                // Exact retry preserves its already authenticated scope witness;
                // the erased payload is no longer available for recomputation.
                if let Some(scopes) = existing
                    .as_object_mut()
                    .ok_or(Failure::Corrupt)?
                    .remove("authored_collections")
                {
                    let scopes = scopes.as_array().ok_or(Failure::Corrupt)?;
                    if target.kind != "annotation"
                        || scopes.len() > 256
                        || scopes
                            .iter()
                            .any(|v| v.as_str().is_none_or(|s| fixed(s).is_err()))
                    {
                        return Err(Failure::Corrupt);
                    }
                }
                if existing != value {
                    return Err(Failure::Conflict);
                }
            } else {
                let current = body(&tx, &target.kind, &target.id)?;
                if let Some(bytes) = &current {
                    total = total.checked_add(bytes.len()).ok_or(Failure::Invalid)?;
                    if total > 64 * 1024 * 1024 {
                        return Err(Failure::Unavailable);
                    }
                    let original = self.unseal(&target.kind, &target.id, bytes)?;
                    let scopes = if target.kind == "annotation" {
                        authored_collections(self, &tx, original, scope_deadline)?
                    } else {
                        None
                    };
                    if let Some(scopes) = scopes {
                        value["authored_collections"] = serde_json::json!(scopes);
                    }
                }
                if current.map(|b| evidence_service::hex(&Sha256::digest(b)))
                    != target.ciphertext_digest
                {
                    return Err(Failure::Conflict);
                }
                writes.push((
                    id,
                    self.seal("erasure", &marker_id(&target.kind, &target.id), value)?,
                ));
            }
        }
        // Older binaries refuse profile 2 rather than silently recreating erased rows.
        // surface-write: evidence-workspace-erasure:profile
        crate::persistence::initialize_workspace_erasure(
            crate::persistence::SurfaceWrite::EvidenceWorkspaceErasure,
            &tx,
        )
        .map_err(invalid)?;
        for (id, bytes) in writes {
            // surface-write: evidence-workspace-erasure:entries
            crate::persistence::insert_workspace_erasure(
                crate::persistence::SurfaceWrite::EvidenceWorkspaceErasure,
                &tx,
                &id,
                &bytes,
            )
            .map_err(invalid)?;
        }
        for target in &plan.targets {
            // surface-write: evidence-workspace-erasure:entries
            crate::persistence::delete_workspace_erased_entry(
                crate::persistence::SurfaceWrite::EvidenceWorkspaceErasure,
                &tx,
                &target.kind,
                &target.id,
            )
            .map_err(invalid)?;
        }
        tx.commit().map_err(invalid)?;
        Ok(
            serde_json::json!({"state":"workspace-entries-erased","plan":digest,"targets":plan.targets.len(),"page_reclamation":"pending","backup_purge":"not-performed"}),
        )
    }
}

#[cfg(all(test, unix))]
#[path = "../../tests/support/workspace_erasure_unit.rs"]
mod tests;

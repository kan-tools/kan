//! A bounded, source-only repository view. HEAD chooses the root; a CAR header
//! or a newer-looking historical commit never substitutes for a missing HEAD.
use super::{bounded, invalid, ContentError, Value, View};
use crate::{claim::v1::AuthorId, store::log::StoredClaim};
use atproto_dasl::Cid;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct Repository {
    pub value: Value,
    pub notice: &'static str,
    members: Option<BTreeMap<String, Vec<String>>>,
}
impl Repository {
    pub fn membership(&self, cid: &str) -> Value {
        match &self.members {
            Some(members) => match members.get(cid) {
                Some(paths) => json!({"state":"reachable","paths":paths}),
                None => json!({"state":"not-a-current-record"}),
            },
            None => json!({"state":"unknown"}),
        }
    }
}
fn unavailable(state: &str, reason: &str, head: Option<&(Vec<u8>, Vec<Value>)>) -> Repository {
    Repository {
        value: json!({"state":state,"reason":reason,"head_sources":head.map(|h|&h.1),"fold":null}),
        notice: "Repository membership is unknown. Individually verified blocks remain inspectable; no HEAD is inferred from CAR roots or historical commits.",
        members: None,
    }
}
struct Walk<'a> {
    blocks: &'a BTreeMap<String, (&'a [u8], usize)>,
    visited: BTreeSet<String>,
    entries: Vec<(String, Cid)>,
}
impl Walk<'_> {
    fn node(&mut self, cid: &Cid, depth: usize) -> Result<(), &'static str> {
        if depth > 32 || self.visited.len() >= 8192 {
            return Err("MST traversal limit");
        }
        if !self.visited.insert(cid.to_string()) {
            return Err("MST repeats a subtree");
        }
        let (bytes, _) = self
            .blocks
            .get(&cid.to_string())
            .ok_or("MST node missing")?;
        let node: crate::mst::MstNode = bounded(bytes).map_err(|_| "Invalid MST node")?;
        if node.entries.len() > 4096 {
            return Err("MST record limit");
        }
        let keys = node.keys().map_err(|_| "Invalid MST key compression")?;
        if let Some(left) = &node.left {
            self.node(left, depth + 1)?;
        }
        for (key, entry) in keys.into_iter().zip(&node.entries) {
            if self.entries.len() >= 4096 {
                return Err("Repository view record limit (4096)");
            }
            crate::mst::validate_key(&key).map_err(|_| "Invalid MST key")?;
            if self.entries.last().is_some_and(|(last, _)| last >= &key) {
                return Err("MST keys are not strictly ordered");
            }
            if !self.blocks.contains_key(&entry.value.to_string()) {
                return Err("Repository record block missing");
            }
            self.entries.push((key, entry.value.clone()));
            if let Some(right) = &entry.tree {
                self.node(right, depth + 1)?;
            }
        }
        Ok(())
    }
}
fn legacy(bytes: &[u8]) -> Option<StoredClaim> {
    use crate::claim::codec::{decode_record, DecodedClaim, SupportedClaim, VerificationContext};
    if let Ok(record) = decode_record(bytes, VerificationContext::StaticDidKey) {
        return match record.claim {
            DecodedClaim::Supported(SupportedClaim::V1(claim)) => Some(StoredClaim {
                claim,
                rev: record.rev,
            }),
            _ => None,
        };
    }
    if let Ok(record) = bounded::<crate::at_claim::Record>(bytes) {
        let rev = record.rev.clone();
        if let Ok(claim) = record.verify() {
            return Some(StoredClaim { claim, rev });
        }
    }
    let record = bounded::<StoredClaim>(bytes).ok()?;
    let id = crate::cid::content_cid(&record.claim.content).ok()?;
    crate::sign::verify(
        &record.claim.content.author.did,
        &id.to_bytes(),
        &record.claim.sig,
    )
    .then_some(record)
}
pub(super) fn inspect(
    bytes: &[u8],
    ranges: &[(usize, usize, usize)],
    head: Option<&(Vec<u8>, Vec<Value>)>,
    view: &View,
    car_complete: bool,
    controls: &[super::current::Control],
) -> Result<Repository, ContentError> {
    if !car_complete {
        return Ok(unavailable(
            "car-incomplete",
            "The selected CAR does not pass its complete block scan.",
            head,
        ));
    }
    let Some((head_bytes, _)) = head else {
        return Ok(unavailable(
            "head-unavailable",
            "Select every part of the sibling HEAD file from this same import plan.",
            head,
        ));
    };
    let head_text = std::str::from_utf8(head_bytes).ok().map(str::trim);
    let head_cid = match head_text.and_then(|s| s.parse::<Cid>().ok()) {
        Some(cid) if Some(cid.to_string().as_str()) == head_text => cid,
        _ => {
            return Ok(unavailable(
                "head-invalid",
                "The exact imported HEAD is not a canonical CID.",
                head,
            ))
        }
    };
    let mut blocks = BTreeMap::new();
    for (index, &(start, body, end)) in ranges.iter().enumerate() {
        let cid = Cid::from_bytes(&bytes[start..body]).map_err(|_| invalid())?;
        if let Some((previous, _)) = blocks.insert(cid.to_string(), (&bytes[body..end], index)) {
            if previous != &bytes[body..end] {
                return Err(invalid());
            }
        }
    }
    let Some((commit_bytes, commit_index)) = blocks.get(&head_cid.to_string()) else {
        return Ok(unavailable(
            "head-missing",
            "HEAD names a commit absent from the selected CAR.",
            head,
        ));
    };
    let commit: atproto_repo::repo::Commit = match bounded(commit_bytes) {
        Ok(c) => c,
        Err(_) => {
            return Ok(unavailable(
                "commit-invalid",
                "HEAD does not name a supported repository commit.",
                head,
            ))
        }
    };
    if commit.version != 3 || commit.validate().is_err() {
        return Ok(unavailable(
            "commit-invalid",
            "The repository commit structure is invalid.",
            head,
        ));
    }
    let signature = if commit.did.starts_with("did:key:") {
        if !crate::sign::verify(
            &commit.did,
            &commit.signing_bytes().map_err(|_| invalid())?,
            &commit.sig,
        ) {
            return Ok(unavailable(
                "commit-invalid",
                "The repository commit signature does not verify.",
                head,
            ));
        }
        "valid-static-did-key"
    } else {
        "identity-resolution-required"
    };
    let mut walk = Walk {
        blocks: &blocks,
        visited: BTreeSet::new(),
        entries: Vec::new(),
    };
    if let Err(reason) = walk.node(&commit.data, 0) {
        return Ok(unavailable("membership-incomplete", reason, head));
    }
    let mut current = super::current::inspect(&walk.entries, &blocks, controls, view)?;
    if !current["uri"].is_null() {
        current["uri"]["repository_head"] = json!(head_cid.to_string());
    }
    let mut members = BTreeMap::<String, Vec<String>>::new();
    let mut records = BTreeMap::<String, (Cid, StoredClaim)>::new();
    let mut positions = BTreeMap::<String, Value>::new();
    let mut authors = BTreeMap::<String, AuthorId>::new();
    let mut uninterpreted = 0;
    for (path, cid) in &walk.entries {
        members
            .entry(cid.to_string())
            .or_default()
            .push(path.clone());
        let (body, index) = blocks[&cid.to_string()];
        // Other collections are still members, but must not acquire claim semantics.
        if !path.starts_with("tools.kan.claim/") && !path.starts_with("dev.kan.claim/") {
            uninterpreted += 1;
            continue;
        }
        let Some(record) = legacy(body) else {
            uninterpreted += 1;
            continue;
        };
        let id = crate::cid::content_cid(&record.claim.content).map_err(|_| invalid())?;
        let key = id.to_string();
        if let Some((_, previous)) = records.get(&key) {
            if previous != &record {
                return Ok(unavailable(
                    "claim-conflict",
                    "The same claim appears with different retained revisions.",
                    head,
                ));
            }
        }
        authors.insert(
            serde_json::to_string(&record.claim.content.author).map_err(|_| invalid())?,
            record.claim.content.author.clone(),
        );
        positions.insert(key.clone(), json!({"block":cid.to_string(),"after":index}));
        records.insert(key, (id, record));
    }
    if authors.len() > 128 {
        return Ok(unavailable(
            "view-limited",
            "Repository view author limit (128)",
            head,
        ));
    }
    let trust = crate::fold::TrustBase::local(view.trust.clone());
    let claims = records.into_values().collect::<Vec<_>>();
    if current["uri"]["state"] == "not-found-at-selected-evidence" {
        use crate::claim::{
            codec::{DecodedClaim, DecodedRecord, SupportedClaim},
            view::{self as projection, ClaimTrustBase},
        };
        let legacy_views = projection::project(
            claims.iter().map(|(_, record)| DecodedRecord {
                rev: record.rev.clone(),
                claim: DecodedClaim::Supported(SupportedClaim::V1(record.claim.clone())),
            }),
            &ClaimTrustBase::from_v1(&trust),
            |_| unreachable!("legacy records only"),
        )
        .map_err(|_| invalid())?;
        let scopes = current["scopes"].as_array().ok_or_else(invalid)?;
        let resolved = super::uri::resolve(view, &legacy_views, scopes, &positions)?;
        if resolved["state"] == "resolved" {
            if crate::uri::ResolutionRequest::parse(view.uri.as_deref().ok_or_else(invalid)?)
                .map_err(|_| invalid())?
                .evaluation()
                .trust
                .is_some()
            {
                return Err(invalid()); // legacy agent/role trust needs the original context
            }
            current["uri"] = resolved;
            current["uri"]["repository_head"] = json!(head_cid.to_string());
            current["uri"]["legacy_trust"] = json!(view.trust);
        }
    }
    let excluded = crate::fold::excluded_by_trust(&claims, &trust);
    let classes = crate::fold::fold(claims.clone(), &trust).classes;
    let total = classes.len();
    let mut displayed = Vec::new();
    let mut output = 0;
    for class in classes.into_iter().skip(view.subjects_after).take(100) {
        let state = crate::fold::state::classify(&class.claims, &[]);
        let status = match &state {
            crate::fold::state::StateView::Unclassified => json!({"kind":"unclassified"}),
            crate::fold::state::StateView::Settled { value, .. } => {
                json!({"kind":"settled","value":value})
            }
            crate::fold::state::StateView::Confirmed { value, .. } => {
                json!({"kind":"confirmed","value":value})
            }
            crate::fold::state::StateView::Contested { .. } => json!({"kind":"contested"}),
        };
        let mut live = state
            .live_cids()
            .into_iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>();
        live.sort();
        let value = json!({"subjects":class.subjects,"status":status,"live_status_claims":live,"flagged_oversized":class.flagged_oversized,
            "claims":class.claims.iter().map(|(id,c)|json!({"id":id.to_string(),"author":c.content.author,"body":c.content.body,"cites":c.content.cites,"source":positions[&id.to_string()]})).collect::<Vec<_>>(),
            "witnesses":class.witnesses.iter().map(|w|json!({"claim":w.claim_cid.to_string(),"author":w.author,"from":w.from,"to":w.to,"source":positions.get(&w.claim_cid.to_string())})).collect::<Vec<_>>()});
        output += serde_json::to_vec(&value).map_err(|_| invalid())?.len();
        if output > 2 * 1024 * 1024 {
            if displayed.is_empty() {
                return Ok(unavailable(
                    "view-limited",
                    "One subject exceeds the 2 MiB fold presentation bound.",
                    head,
                ));
            }
            break;
        }
        displayed.push(value);
    }
    let next = view.subjects_after + displayed.len();
    let mut exclusions = excluded
        .into_iter()
        .map(|(subject, count)| json!({"subject":subject,"claims":count}))
        .collect::<Vec<_>>();
    exclusions.sort_by_cached_key(Value::to_string);
    Ok(Repository {
        notice: "Reachability is checked against the exact imported HEAD. Commit signatures, individual claim validity, selected view trust and current access remain separate. Local subjects are confined to this imported repository.",
        members: Some(members),
        value: json!({"current":current,"state":"membership-verified","head":head_cid.to_string(),"head_sources":head.map(|h|&h.1),"commit":{"did":commit.did,"revision":commit.rev,"signature":signature,"after":commit_index},"records":walk.entries.len(),"authors":authors.into_values().collect::<Vec<_>>(),
            "fold":{"version":"kan-v1-fold/1","trust":view.trust,"coverage":"Verified reachable v1 claim records only; current identity-governed and unsupported records remain outside this legacy fold. Explicit trust is an interpretation choice, not permission or repository ownership. No Git ancestry provider is consulted.","verified_claims":claims.len(),"uninterpreted_members":uninterpreted,"excluded_by_trust":exclusions,"classes":displayed,"total_classes":total,"next":(next<total).then_some(next)}}),
    })
}

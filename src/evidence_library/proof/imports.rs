//! Read-only import reconstruction. Reuses the recovery validator and CAR
//! scanner. Repository membership and the selected trust fold remain separate
//! from individual signatures, source capture and current access grants.
use super::Readers;
use crate::{
    evidence_content::ContentError,
    evidence_reader::proof::{Occurrence, Pin, Source, Token},
    evidence_restore as restore,
    evidence_service::{self as service, Failure},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
mod current;
mod repository;
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlEvidence {
    pub parts: Vec<super::knowledge::Citation>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct View {
    #[serde(default)]
    pub trust: Vec<crate::claim::v1::AuthorId>,
    #[serde(default)]
    pub subjects_after: usize,
    #[serde(default)]
    pub principals: Vec<String>,
    #[serde(default)]
    pub controls: Vec<ControlEvidence>,
    #[serde(default)]
    pub current_after: usize,
}

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

struct Frame {
    header: restore::Header,
    offset: usize,
    bytes: Vec<u8>,
    record: Occurrence,
}
fn digest(bytes: &[u8]) -> String {
    service::hex(&Sha256::digest(bytes))
}
fn invalid() -> ContentError {
    Failure::Invalid.into()
}
fn operation(plan: &str, ordinal: usize) -> String {
    let mut h = Sha256::new();
    h.update(b"tools.kan.import.operation.v1\0");
    h.update(plan.as_bytes());
    h.update((ordinal as u64).to_be_bytes());
    service::hex(&h.finalize()[..16])
}
fn cite(frame: &Frame, start: usize, end: usize) -> Value {
    json!({"record":frame.record,"bytes":[(frame.offset+start).to_string(),(frame.offset+end).to_string()]})
}
impl Readers {
    // One request preserves explicit source, pin, selection and presentation bounds.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn import_content(
        &self,
        source: &str,
        pin: &Pin,
        selections: &[Token],
        plan_id: &str,
        file: Option<usize>,
        after: usize,
        view: View,
    ) -> Result<Value, ContentError> {
        if selections.is_empty()
            || selections.len() > 1024
            || plan_id.len() != 64
            || !plan_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || after > 100_000
            || view.subjects_after > 4096
            || view.trust.len() > 128
            || view.principals.len() > 128
            || view.principals.iter().any(|p| p.len() > 256)
            || view.controls.len() > 128
            || view
                .controls
                .iter()
                .any(|c| c.parts.is_empty() || c.parts.len() > 4)
            || view.current_after > 4096
            || view
                .trust
                .iter()
                .any(|a| a.did.len() > 256 || a.agent.as_ref().is_some_and(|k| k.len() > 256))
        {
            return Err(invalid());
        }
        let _permit = self
            .workers
            .clone()
            .try_acquire_owned()
            .map_err(|_| ContentError::Busy)?;
        let reader = self.selected(source)?;
        tokio::time::timeout(std::time::Duration::from_secs(120), async {
            let mut controls=Vec::new();
            let mut control_bytes=0usize;
            for evidence in &view.controls {
                let mut bytes=Vec::new();let mut binding=None;let mut sources=Vec::new();
                for (index,part) in evidence.parts.iter().enumerate() {
                    let source_reader=self.selected(&part.source)?;
                    let Source::Available {record,writer,plaintext,..}=source_reader.cited_source(&part.pin,&part.selection).await? else {return Err(Failure::Missing.into());};
                    let offset=if plaintext.starts_with(b"KANI") {
                        let (header,offset)=restore::decode_frame(&plaintext).map_err(|_|invalid())?;
                        let identity=(header.plan,header.file,writer);
                        if header.kind!="data" || header.part!=index || header.parts!=evidence.parts.len() || binding.as_ref().is_some_and(|b|b!=&identity) {return Err(invalid());}
                        binding=Some(identity);offset
                    } else {if evidence.parts.len()!=1 {return Err(invalid());}0};
                    bytes.extend_from_slice(&plaintext[offset..]);
                    if bytes.len()>262144 {return Err(ContentError::Limited);}
                    sources.push(json!({"source":part.source,"record":record,"bytes":[offset.to_string(),plaintext.len().to_string()]}));
                }
                control_bytes+=bytes.len();if control_bytes>4*1024*1024 {return Err(ContentError::Limited);}
                bounded::<atproto_dasl::Ipld>(&bytes).map_err(|_|invalid())?;
                let preserved=crate::identity::control::decode_preserving(&bytes).map_err(|_|invalid())?;
                controls.push(current::Control {preserved,sources});
            }
            let mut frames = BTreeMap::new();
            let mut unavailable = Vec::new();
            let mut total = 0usize;
            let mut offset = 0;
            let mut writer = None;
            let mut recipient = None;
            let mut seen = std::collections::BTreeSet::new();
            while offset < selections.len() {
                let end = (offset + crate::evidence_proof_service::READ_BATCH_LIMIT)
                    .min(selections.len());
                let values = reader.sources_prefix(pin, &selections[offset..end]).await?;
                offset += values.len();
                for value in values {
                    match value {
                        Source::Available {
                            record,
                            writer: author,
                            plaintext,
                            operation: op,
                            recipient: epoch,
                        } => {
                            if !seen.insert(record.sequence.clone()) {
                                return Err(invalid());
                            }
                            total = total
                                .checked_add(plaintext.len())
                                .ok_or(ContentError::Limited)?;
                            if total > 40 * 1024 * 1024 {
                                return Err(ContentError::Limited);
                            }
                            let (header, body) =
                                restore::decode_frame(&plaintext).map_err(|_| invalid())?;
                            if header.plan != plan_id
                                || operation(plan_id, header.ordinal) != op
                                || writer.as_ref().is_some_and(|w| w != &author)
                                || recipient.as_ref().is_some_and(|r| r != &epoch)
                            {
                                return Err(invalid());
                            }
                            writer = Some(author);
                            recipient = Some(epoch);
                            let ordinal = header.ordinal;
                            if frames
                                .insert(
                                    ordinal,
                                    Frame {
                                        header,
                                        offset: body,
                                        bytes: plaintext,
                                        record,
                                    },
                                )
                                .is_some()
                            {
                                return Err(invalid());
                            }
                        }
                        Source::KeyUnavailable { record, .. }
                        | Source::Erased { record }
                        | Source::Missing { record }
                        | Source::Corrupt { record } => {
                            if !seen.insert(record.sequence.clone()) {
                                return Err(invalid());
                            }
                            unavailable.push(record);
                        }
                    }
                }
            }
            let records=frames.values().map(|f|f.record.clone()).chain(unavailable.iter().cloned()).collect::<Vec<_>>();
            let scope = reader.binding().scope.clone();
            let recipient = recipient.unwrap_or_default();
            let id = plan_id.to_owned();
            let control_selections=view.controls.clone();
            let mut value = tokio::task::spawn_blocking(move || {
                let _permit = _permit;
                inspect(
                    &frames,
                    &id,
                    &scope,
                    writer.as_deref().unwrap_or(""),
                    &recipient,
                    file,
                    after,
                    &view,
                    &controls,
                )
            })
            .await
            .map_err(|_| Failure::Unavailable)??;
            // The last read is a fresh authorization check, not reliance on a pin.
            reader.page(pin, None, 1).await?;
            for evidence in &control_selections {for part in &evidence.parts {self.selected(&part.source)?.check_citation_access(&part.pin,&part.selection).await?;}}
            value["source"] = json!(source);
            value["pin"] = json!(pin);
            value["unavailable"] = json!(unavailable);
            value["records"] = json!(records);
            Ok(value)
        })
        .await
        .map_err(|_| ContentError::Limited)?
    }
}
#[allow(clippy::too_many_arguments)]
fn inspect(
    frames: &BTreeMap<usize, Frame>,
    id: &str,
    scope: &str,
    writer: &str,
    recipient: &str,
    selected: Option<usize>,
    after: usize,
    view_options: &View,
    controls: &[current::Control],
) -> Result<Value, ContentError> {
    let coverage="Selected import frames only. File hashes and individually supported claim signatures are verified; Repository membership is evaluated only with the exact sibling HEAD and complete selected CAR; trust folding is explicitly selected and does not certify migration completeness or cutover. Original files and claim citations remain distinct from v2 annotations.";
    let mut result = json!({"version":"kan-import-content/1","plan":id,"state":"inventory-incomplete","coverage":coverage,"files":[],"inventory_cites":[],"file":null});
    let Some(first) = frames.get(&0) else {
        return Ok(result);
    };
    if first.header.kind != "inventory" || first.header.part != 0 {
        return Err(invalid());
    }
    let parts = first.header.parts;
    let mut document = Vec::new();
    let mut inventory_cites = Vec::new();
    for i in 0..parts {
        let Some(f) = frames.get(&i) else {
            return Ok(result);
        };
        if f.header.kind != "inventory" || f.header.part != i || f.header.parts != parts {
            return Err(invalid());
        }
        let body = &f.bytes[f.offset..];
        if body.is_empty() || (i + 1 < parts && body.len() != crate::evidence_import::CHUNK) {
            return Err(invalid());
        }
        document.extend_from_slice(body);
        inventory_cites.push(cite(f, 0, body.len()));
    }
    let plan = restore::validate_document(&document, id, scope, writer, recipient)
        .map_err(|_| invalid())?;
    // All selected frames must agree with the committed layout and audience.
    let mut ordinal = parts;
    let mut files = Vec::new();
    let mut selected_file = None;
    for (index, f) in plan.files.iter().enumerate() {
        let mut present = 0;
        for (part, chunk) in f.chunks.iter().enumerate() {
            if let Some(frame) = frames.get(&(ordinal + part)) {
                let h = &frame.header;
                if h.kind != "data"
                    || h.file != Some(index)
                    || h.part != part
                    || h.parts != f.chunks.len()
                    || frame.bytes.len() - frame.offset != chunk.length
                    || digest(&frame.bytes[frame.offset..]) != chunk.sha256
                {
                    return Err(invalid());
                }
                present += 1;
            }
        }
        files.push(json!({"index":index,"path":f.path,"length":f.length.to_string(),"sha256":f.sha256,"parts":f.chunks.len(),"present_parts":present}));
        if selected == Some(index) {
            selected_file = Some((f, ordinal, present));
        }
        ordinal += f.chunks.len();
    }
    for (&n, f) in frames {
        if n > ordinal || f.record.receipt_issuer != plan.route.audience {
            return Err(invalid());
        }
    }
    let complete = if let Some(f) = frames.get(&ordinal) {
        if f.header.kind!="complete" || f.bytes[f.offset..]!=serde_json::to_vec(&json!({"plan":id,"observation":"selected-snapshot-queued","recovery_verified":false,"independent_backup":false,"ready_for_cutover":false})).map_err(|_|invalid())? {return Err(invalid());}
        Some(cite(f, 0, f.bytes.len() - f.offset))
    } else {
        None
    };
    result["state"] = json!("inventory-verified");
    result["files"] = json!(files);
    result["inventory_cites"] = json!(inventory_cites);
    result["source_id"] = json!(plan.source_id);
    result["writer"] = json!(writer);
    result["inventory"] = plan.inventory;
    result["completion_observation"] = json!(complete);
    if selected.is_some() && selected_file.is_none() {
        return Err(invalid());
    }
    if let Some((file, start, present)) = selected_file {
        if present != file.chunks.len() {
            result["file"] = json!({"state":"incomplete","index":selected,"path":file.path,"present_parts":present,"parts":file.chunks.len()});
        } else {
            let mut bytes = Vec::new();
            let mut sources = Vec::new();
            let mut spans = Vec::new();
            for part in 0..file.chunks.len() {
                let frame = &frames[&(start + part)];
                let body = &frame.bytes[frame.offset..];
                spans.push((bytes.len(), bytes.len() + body.len(), frame));
                bytes.extend_from_slice(body);
                sources.push(cite(frame, 0, body.len()));
            }
            if digest(&bytes) != file.sha256 {
                return Err(invalid());
            }
            let mut view = json!({"state":"verified","index":selected,"path":file.path,"length":bytes.len().to_string(),"sha256":file.sha256,"sources":sources});
            if file.path.ends_with(".car") {
                let parent = std::path::Path::new(&file.path)
                    .parent()
                    .ok_or_else(invalid)?;
                let head_path = parent.join("HEAD").to_string_lossy().into_owned();
                let mut head_start = parts;
                let mut head = None;
                for candidate in &plan.files {
                    if candidate.path == head_path {
                        if candidate.length > 256 {
                            return Err(invalid());
                        }
                        let mut content = Vec::new();
                        let mut cites = Vec::new();
                        for part in 0..candidate.chunks.len() {
                            let Some(frame) = frames.get(&(head_start + part)) else {
                                break;
                            };
                            let body = &frame.bytes[frame.offset..];
                            content.extend_from_slice(body);
                            cites.push(cite(frame, 0, body.len()));
                        }
                        if cites.len() == candidate.chunks.len() {
                            if digest(&content) != candidate.sha256 {
                                return Err(invalid());
                            }
                            head = Some((content, cites));
                        }
                        break;
                    }
                    head_start += candidate.chunks.len();
                }
                view["car"] = car(&bytes, after, &spans, head.as_ref(), view_options, controls)?;
            } else {
                if bounded::<atproto_dasl::Ipld>(&bytes).is_ok() {
                    if let Ok(control) = crate::identity::control::decode_preserving(&bytes) {
                        view["control"] = json!({"logical_id":control.logical_cid().map_err(|_|invalid())?.to_string(),"proved_id":control.proved_cid().map_err(|_|invalid())?.to_string(),"supported":control.is_supported(),"raw":control.raw(),"interpretation":"Selected control evidence is resolved with the other explicitly selected events; this file alone does not establish authority."});
                    }
                }
                let end = bytes.len().min(65536);
                view["preview"] = json!(std::str::from_utf8(&bytes[..end]).ok());
                view["preview_bytes"] = json!(end.to_string());
                view["truncated"] = json!(end < bytes.len());
            }
            result["file"] = view;
        }
    }
    Ok(result)
}
fn car(
    bytes: &[u8],
    after: usize,
    spans: &[(usize, usize, &Frame)],
    head: Option<&(Vec<u8>, Vec<Value>)>,
    view: &View,
    controls: &[current::Control],
) -> Result<Value, ContentError> {
    let mut scan = crate::migration_preflight::CarScan {
        roots: vec![],
        verified_blocks: 0,
        unsupported_blocks: 0,
        error: None,
    };
    let mut ranges = Vec::new();
    if let Err(e) = crate::migration_preflight::scan_car_stream(
        &mut std::io::Cursor::new(bytes),
        bytes.len() as u64,
        &mut scan,
        |start, body, end| {
            if ranges.len() >= 100_000 {
                return Err(std::io::Error::other("CAR browsing block limit"));
            }
            ranges.push((start as usize, body as usize, end as usize));
            Ok(())
        },
    ) {
        scan.error = Some(e.to_string());
    }
    let repository = repository::inspect(
        bytes,
        &ranges,
        head,
        view,
        scan.error.is_none() && scan.unsupported_blocks == 0,
        controls,
    )?;
    // A corrupt tail never silently turns a verified prefix into a valid CAR.
    let mut records = Vec::new();
    let mut next = after;
    let mut output = 0;
    for &(start, body, end) in ranges.iter().skip(after).take(100) {
        let cid = atproto_dasl::Cid::from_bytes(&bytes[start..body]).map_err(|_| invalid())?;
        let mut value = if end - body > 1_000_000 {
            json!({"state":"record-over-presentation-limit"})
        } else {
            claim(&bytes[body..end])
        };
        value["membership"] = repository.membership(&cid.to_string());
        value["block"] = json!(cid.to_string());
        value["file_bytes"] = json!([body.to_string(), end.to_string()]);
        value["sources"] = json!(spans
            .iter()
            .filter_map(|(a, b, f)| {
                let low = body.max(*a);
                let high = end.min(*b);
                (low < high).then(|| cite(f, low - a, high - a))
            })
            .collect::<Vec<_>>());
        output += serde_json::to_vec(&value).map_err(|_| invalid())?.len();
        if output > 4 * 1024 * 1024 {
            break;
        }
        records.push(value);
        next += 1;
    }
    Ok(
        json!({"scan":scan,"records":records,"after":after,"next":(next<ranges.len()).then_some(next),"membership":repository.notice,"repository":repository.value}),
    )
}
fn claim(bytes: &[u8]) -> Value {
    use crate::claim::codec::{self, DecodedClaim, SupportedClaim, VerificationContext};
    if let Ok(record) = codec::decode_record(bytes, VerificationContext::StaticDidKey) {
        return match record.claim {
            DecodedClaim::Supported(SupportedClaim::V1(c)) => {
                json!({"state":"verified-claim","codec":"kan-claim-v1","id":crate::cid::content_cid(&c.content).ok().map(|c|c.to_string()),"claim":c,"revision":record.rev})
            }
            DecodedClaim::Supported(SupportedClaim::Claim(c)) => {
                json!({"state":"verified-claim","codec":codec::V2_CODEC,"id":c.id().ok().map(|c|c.to_string()),"claim":c.content(),"revision":record.rev})
            }
            DecodedClaim::Unsupported(c) => {
                json!({"state":"unsupported-claim","codec":c.codec(),"id":c.claim_id().to_string()})
            }
        };
    }
    if let Ok(record) = bounded::<crate::at_claim::Record>(bytes) {
        if let Ok(c) = record.verify() {
            return json!({"state":"verified-claim","codec":"legacy-at-claim","id":crate::cid::content_cid(&c.content).ok().map(|c|c.to_string()),"claim":c});
        }
    }
    if let Ok(record) = bounded::<crate::store::log::StoredClaim>(bytes) {
        if let Ok(id) = crate::cid::content_cid(&record.claim.content) {
            if crate::sign::verify(
                &record.claim.content.author.did,
                &id.to_bytes(),
                &record.claim.sig,
            ) {
                return json!({"state":"verified-claim","codec":"legacy-stored-claim","id":id.to_string(),"claim":record.claim,"revision":record.rev});
            }
        }
    }
    json!({"state":"uninterpreted-block","notice":"Not a verified supported claim. It may be structural, malformed, unsigned, or require identity evidence unavailable in this view."})
}

fn bounded<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, atproto_dasl::DecodeError> {
    atproto_dasl::drisl::from_slice_with_config(
        bytes,
        atproto_dasl::drisl::DecodeConfig {
            max_depth: 32,
            max_alloc: 2 * 1024 * 1024,
            max_array_elements: 100_000,
            max_map_entries: 100_000,
            ..Default::default()
        },
    )
}

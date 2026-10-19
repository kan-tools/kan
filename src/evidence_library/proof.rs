//! Explicit mixed-source presentation; proof sources never fall back to legacy.
use super::{query, Query};
use crate::{
    evidence_content::{self as content, ContentError},
    evidence_proof_service as wire,
    evidence_reader::{self as legacy, proof},
    evidence_service::{self as service, Failure},
};
use serde_json::{json, Value};
use std::{collections::BTreeMap, time::Duration};

pub struct Readers {
    legacy: Option<legacy::Reader>,
    proof: BTreeMap<String, proof::Reader>,
}
impl Readers {
    pub fn new(
        legacy: Option<legacy::Reader>,
        proofs: Vec<proof::Reader>,
    ) -> Result<Self, Failure> {
        let count = legacy.as_ref().map_or(0, |r| r.configured_scopes().len()) + proofs.len();
        if count == 0 || count > 16 {
            return Err(Failure::Invalid);
        }
        let mut selected = BTreeMap::new();
        for reader in proofs {
            let binding = reader.binding();
            let id = format!(
                "proof:{}:{}:{}:{}",
                match binding.profile {
                    wire::Profile::Admitted => "admitted",
                    wire::Profile::Copied => "copied",
                },
                binding.archive,
                binding.scope,
                binding.issuer
            );
            if selected.insert(id, reader).is_some() {
                return Err(Failure::Invalid);
            }
        }
        Ok(Self {
            legacy,
            proof: selected,
        })
    }
    fn selected(&self, id: &str) -> Result<&proof::Reader, Failure> {
        self.proof.get(id).ok_or(Failure::AccessLimited)
    }
    async fn entry(&self, id: Option<&String>) -> Option<Result<Value, Failure>> {
        let id = id?;
        Some(tokio::time::timeout(Duration::from_secs(5), async {
            if let Some(reader) = self.proof.get(id) {
                let pin = reader.snapshot().await?;
                Ok(json!({"id":id,"scope":reader.binding().scope,"binding":reader.binding(),
                    "protocol":wire::PROTOCOL,"pin":pin,
                    "capabilities":["snapshot-inventory","source-ranges","provenance","payload-availability"]}))
            } else {
                let reader = self.legacy.as_ref().ok_or(Failure::Invalid)?;
                let pin = reader.snapshot(id).await?;
                Ok(json!({"id":id,"scope":id,"protocol":"legacy","pin_wire":content::pin_wire(&pin)?,"pin":pin,
                    "capabilities":["snapshot-inventory","source-ranges","provenance","content-inspection"]}))
            }
        }).await.unwrap_or(Err(Failure::Unavailable)))
    }
    pub(super) async fn query(&self, request: Query) -> Result<Vec<u8>, ContentError> {
        let value = match request {
            Query::Catalog if !self.proof.is_empty() => {
                let mut configured = self
                    .legacy
                    .as_ref()
                    .map_or(Vec::new(), |r| r.configured_scopes());
                configured.extend(self.proof.keys().cloned());
                let mut scopes = Vec::new();
                let mut partial = false;
                for group in configured.chunks(4) {
                    let results = tokio::join!(
                        self.entry(group.first()),
                        self.entry(group.get(1)),
                        self.entry(group.get(2)),
                        self.entry(group.get(3))
                    );
                    for result in [results.0, results.1, results.2, results.3]
                        .into_iter()
                        .flatten()
                    {
                        match result {
                            Ok(entry) => scopes.push(entry),
                            Err(Failure::AccessLimited) => {}
                            Err(_) => partial = true,
                        }
                    }
                }
                json!({"version":2,"scopes":scopes,"coverage":if partial {"partial"} else {"complete"},
                    "capabilities":["snapshot-inventory","source-ranges","provenance","payload-availability"],
                    "unavailable":["semantic-search","normalized-sessions","annotations","saved-views","analysis","administrative-jobs"]})
            }
            Query::ProofSnapshot { source } => {
                json!({"pin":self.selected(&source)?.snapshot().await?})
            }
            Query::ProofPage {
                source,
                pin,
                cursor,
                limit,
            } => {
                let reader = self.selected(&source)?;
                let page = reader.page(&pin, cursor.as_ref(), limit).await?;
                // Reader::page verified this exact signed snapshot before use.
                let wire::Output::Snapshot { frontier, .. } =
                    &pin.reply.reply.result.as_ref().map_err(Clone::clone)?
                else {
                    return Err(Failure::Corrupt.into());
                };
                json!({"records":page.records,"next":page.next,"through":frontier.through,
                    "coverage":"Issuer-attested metadata · payload availability sampled per read"})
            }
            Query::ProofSource {
                source,
                pin,
                selection,
                offset,
                length,
            } => {
                let offset =
                    usize::try_from(content::coordinate(&offset)?).map_err(|_| Failure::Invalid)?;
                let length =
                    usize::try_from(content::coordinate(&length)?).map_err(|_| Failure::Invalid)?;
                if length == 0 || length > legacy::RANGE_LIMIT {
                    return Err(Failure::Invalid.into());
                }
                let reader = self.selected(&source)?;
                let result = reader.source(&pin, &selection).await?;
                source_value(reader.binding(), result, offset, length)?
            }
            other => {
                return query(self.legacy.as_ref().ok_or(Failure::AccessLimited)?, other).await
            }
        };
        serde_json::to_vec(&value).map_err(|_| Failure::Invalid.into())
    }
}
fn source_value(
    binding: &wire::Binding,
    value: proof::Source,
    offset: usize,
    length: usize,
) -> Result<Value, Failure> {
    let (record, writer, plaintext, availability) = match value {
        proof::Source::Available {
            record,
            writer,
            plaintext,
        } => (record, Some(writer), Some(plaintext), "available"),
        proof::Source::Missing { record } => (record, None, None, "missing"),
        proof::Source::Corrupt { record } => (record, None, None, "corrupt"),
    };
    let mut result = json!({"scope":binding.scope,"archive":binding.archive,"profile":binding.profile,
        "record":record,"writer":writer,"service_issuer":binding.issuer,"availability":availability,
        "signature":if plaintext.is_some() {"Retained writer signature verified on this read"} else {"Writer signature cannot be rechecked without valid retained source"},
        "admission":"Issuer-attested metadata; proof purpose shown separately",
        "content_trust":"Untrusted retained content; speaker and outcome claims are not authenticated facts"});
    if let Some(bytes) = plaintext {
        if offset > bytes.len() {
            return Err(Failure::Invalid);
        }
        let end = offset.saturating_add(length).min(bytes.len());
        let range = &bytes[offset..end];
        let fields = json!({"total_bytes":bytes.len().to_string(),"offset":offset.to_string(),
            "next":(end < bytes.len()).then(||end.to_string()),"bytes_hex":service::hex(range),
            "utf8":std::str::from_utf8(range).ok()});
        result
            .as_object_mut()
            .ok_or(Failure::Invalid)?
            .extend(fields.as_object().ok_or(Failure::Invalid)?.clone());
    }
    Ok(result)
}

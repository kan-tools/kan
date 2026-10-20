//! Proof-aware reads with locally authenticated continuation and selection tokens.
use crate::{
    evidence::{self, Decoded},
    evidence_attestation::{self as attestation, Frontier, Purpose},
    evidence_copy_plan::Plan,
    evidence_crypto, evidence_http, evidence_proof_service as wire,
    evidence_service::{self as service, Failure},
    evidence_store::Committed,
    sign::{self, Identity},
};
use atproto_dasl::Ipld;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

type Result<T> = std::result::Result<T, Failure>;
const TOKEN_DOMAIN: &[u8] = b"tools.kan.reader.proof-continuation.v1\0";
pub struct Access {
    pub binding: wire::Binding,
    pub endpoint: String,
    pub private_key: [u8; 32],
}
pub struct Reader {
    signer: Identity,
    access: Access,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    pub request: String,
    pub reply: wire::SignedReply,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum TokenPurpose {
    Page,
    Source,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenBody {
    pin: String,
    binding: wire::Binding,
    principal: String,
    purpose: TokenPurpose,
    coordinate: wire::Coordinate,
}
/// Untrusted after deserialization until Reader checks its local signature.
/// Certifies prior chain verification only; never grants current remote access.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Token {
    body: TokenBody,
    signature: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Occurrence {
    pub sequence: String,
    pub manifest: String,
    pub receipt: String,
    pub attestation: String,
    pub purpose: String,
    pub issued_at: String,
    pub receipt_issuer: String,
    pub availability: wire::Availability,
    pub selection: Token,
}
#[derive(Debug, Serialize)]
pub struct Page {
    pub records: Vec<Occurrence>,
    pub next: Option<Token>,
}
pub enum Source {
    Available {
        record: Occurrence,
        writer: String,
        plaintext: Vec<u8>,
        operation: String,
    },
    Missing {
        record: Occurrence,
    },
    Corrupt {
        record: Occurrence,
    },
}
struct CheckedPin {
    frontier: Frontier,
    plan: Option<Plan>,
    fingerprint: String,
}
fn json(value: &impl Serialize) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| Failure::Invalid)
}
fn token_preimage(body: &TokenBody) -> Result<Vec<u8>> {
    let mut bytes = TOKEN_DOMAIN.to_vec();
    bytes.extend_from_slice(&Sha256::digest(json(body)?));
    Ok(bytes)
}
impl Reader {
    pub(crate) fn recipient_public(&self) -> Result<String> {
        crate::evidence_crypto::public_key(&self.access.private_key)
            .map(|key| service::hex(&key))
            .map_err(|_| Failure::Invalid)
    }
    pub fn binding(&self) -> &wire::Binding {
        &self.access.binding
    }
    pub fn new(signer: Identity, access: Access) -> Result<Self> {
        access.binding.owner_binding()?;
        if signer.did().as_str() == access.binding.issuer {
            return Err(Failure::Invalid);
        }
        Ok(Self { signer, access })
    }
    async fn call(&self, command: wire::Command) -> Result<(Vec<u8>, wire::SignedReply)> {
        let bytes = wire::SignedRequest::sign(
            wire::Request {
                version: 2,
                binding: self.access.binding.clone(),
                principal: self.signer.did().to_string(),
                expires: crate::evidence_operations::now().saturating_add(60),
                command,
            },
            &self.signer,
        )?
        .bytes()?;
        let reply = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            evidence_http::send_proof(&self.access.endpoint, &self.access.binding.issuer, &bytes),
        )
        .await
        .map_err(|_| Failure::Unavailable)?
        .map_err(|failure| match failure {
            // An unverified transport denial is not a valid service grant result.
            Failure::AccessLimited => Failure::Corrupt,
            other => other,
        })?;
        reply
            .verify(&bytes, &self.access.binding.issuer)
            .map_err(|_| Failure::Corrupt)?;
        Ok((bytes, reply))
    }
    fn compatible_operations(operations: &[String]) -> bool {
        operations == ["capabilities", "snapshot", "page", "read"]
            || operations == ["capabilities", "snapshot", "page", "read", "read-batch"]
    }
    /// Returns a nonempty ordered prefix (at most READ_BATCH_LIMIT inputs).
    /// Batch support is negotiated, never assumed from an old pin. Each call
    /// checks current authorization; older services use the single-read path.
    pub async fn sources_prefix(&self, pin: &Pin, selections: &[Token]) -> Result<Vec<Source>> {
        if selections.is_empty() || selections.len() > wire::READ_BATCH_LIMIT {
            return Err(Failure::Invalid);
        }
        let checked = self.check_pin(pin)?;
        let expected = selections
            .iter()
            .map(|selection| self.check_token(&checked, selection, TokenPurpose::Source))
            .collect::<Result<Vec<_>>>()?;
        let (_, capabilities) = self.call(wire::Command::Capabilities).await?;
        let wire::Output::Capabilities {
            protocol,
            operations,
        } = capabilities.reply.result?
        else {
            return Err(Failure::Corrupt);
        };
        if protocol != wire::PROTOCOL || !Self::compatible_operations(&operations) {
            return Err(Failure::Corrupt);
        }
        if !operations.iter().any(|operation| operation == "read-batch") {
            return Ok(vec![self.source(pin, &selections[0]).await?]);
        }
        let (_, reply) = self
            .call(wire::Command::ReadBatch {
                pin: wire::Coordinate::from_frontier(&checked.frontier),
                selections: expected
                    .iter()
                    .map(wire::Coordinate::from_frontier)
                    .collect(),
            })
            .await?;
        let wire::Output::EvidenceBatch { records } = reply.reply.result? else {
            return Err(Failure::Corrupt);
        };
        if records.is_empty() || records.len() > selections.len() {
            return Err(Failure::Corrupt);
        }
        records
            .into_iter()
            .zip(&expected)
            .map(|(row, expected)| self.decode_source(&checked, expected, row.record, row.source))
            .collect()
    }
    pub async fn snapshot(&self) -> Result<Pin> {
        let (_, capability) = self.call(wire::Command::Capabilities).await?;
        let wire::Output::Capabilities {
            protocol,
            operations,
        } = capability.reply.result?
        else {
            return Err(Failure::Corrupt);
        };
        if protocol != wire::PROTOCOL || !Self::compatible_operations(&operations) {
            return Err(Failure::Corrupt);
        }
        let (request, reply) = self.call(wire::Command::Snapshot).await?;
        let pin = Pin {
            request: service::hex(&request),
            reply,
        };
        self.check_pin(&pin)?;
        Ok(pin)
    }
    fn check_pin(&self, pin: &Pin) -> Result<CheckedPin> {
        let bytes = service::unhex(&pin.request, wire::MAX_REQUEST)?;
        let request = wire::SignedRequest::decode(&bytes)?;
        if request.request.binding != self.access.binding
            || request.request.principal != self.signer.did().as_str()
            || !matches!(request.request.command, wire::Command::Snapshot)
        {
            return Err(Failure::AccessLimited);
        }
        pin.reply.bytes()?;
        let reply = pin.reply.verify(&bytes, &self.access.binding.issuer)?;
        let wire::Output::Snapshot {
            frontier,
            plan,
            recipe_metadata_match,
        } = reply.result.as_ref().map_err(Clone::clone)?
        else {
            return Err(Failure::Corrupt);
        };
        let frontier = frontier.frontier(&self.access.binding)?;
        let plan = match self.access.binding.profile {
            wire::Profile::Admitted => {
                if plan.is_some() || recipe_metadata_match.is_some() {
                    return Err(Failure::Corrupt);
                }
                None
            }
            wire::Profile::Copied => {
                let plan = Plan::decode(&service::unhex(
                    plan.as_ref().ok_or(Failure::Corrupt)?,
                    crate::evidence_copy_plan::MAX_PLAN_BYTES,
                )?)
                .map_err(|_| Failure::Corrupt)?;
                let binding = self.access.binding.owner_binding()?;
                if plan.archive_id() != binding.archive
                    || plan.target().scope != binding.scope
                    || plan.target().issuer != binding.issuer
                    || recipe_metadata_match.is_none()
                    || (frontier.through < plan.source().through
                        && *recipe_metadata_match != Some(false))
                    || ((frontier.through > plan.source().through
                        || (frontier.through > 0 && frontier.through == plan.source().through))
                        && *recipe_metadata_match != Some(true))
                {
                    return Err(Failure::Corrupt);
                }
                Some(plan)
            }
        };
        Ok(CheckedPin {
            frontier,
            plan,
            fingerprint: service::hex(&Sha256::digest(json(pin)?)),
        })
    }
    fn token(&self, pin: &CheckedPin, frontier: &Frontier, purpose: TokenPurpose) -> Result<Token> {
        let body = TokenBody {
            pin: pin.fingerprint.clone(),
            binding: self.access.binding.clone(),
            principal: self.signer.did().to_string(),
            purpose,
            coordinate: wire::Coordinate::from_frontier(frontier),
        };
        let signature = self
            .signer
            .sign(&token_preimage(&body)?)
            .map_err(|_| Failure::Unavailable)?;
        Ok(Token {
            body,
            signature: service::hex(&signature),
        })
    }
    fn check_token(
        &self,
        pin: &CheckedPin,
        token: &Token,
        purpose: TokenPurpose,
    ) -> Result<Frontier> {
        if token.body.pin != pin.fingerprint
            || token.body.binding != self.access.binding
            || token.body.principal != self.signer.did().as_str()
            || token.body.purpose != purpose
        {
            return Err(Failure::AccessLimited);
        }
        let next = token.body.coordinate.frontier(&self.access.binding)?;
        if next.through == 0 || next.through > pin.frontier.through {
            return Err(Failure::Invalid);
        }
        let signature = service::unhex(&token.signature, 64)?;
        if signature.len() != 64
            || !sign::verify(
                self.signer.did().as_str(),
                &token_preimage(&token.body)?,
                &signature,
            )
        {
            return Err(Failure::AccessLimited);
        }
        Ok(next)
    }
    fn verify_row(
        &self,
        pin: &CheckedPin,
        expected: &Frontier,
        row: &wire::RecordView,
    ) -> Result<(Committed, attestation::Verified)> {
        if row.sequence != expected.through.to_string() || expected.through == 0 {
            return Err(Failure::Corrupt);
        }
        let decode =
            |text: &str| match evidence::decode(&service::unhex(text, evidence::MAX_RECORD_BYTES)?)
            {
                Ok(Decoded::Known(record)) => Ok(record),
                _ => Err(Failure::Corrupt),
            };
        let manifest = decode(&row.manifest)?;
        let receipt = decode(&row.receipt)?;
        let binding = self.access.binding.owner_binding()?;
        let verified = attestation::verify_at(
            &service::unhex(&row.proof, attestation::MAX_ENVELOPE_BYTES)?,
            &attestation::Context {
                issuer: &binding.issuer,
                archive: binding.archive,
                scope: binding.scope,
            },
            &manifest,
            &receipt,
            expected,
        )
        .map_err(|_| Failure::Corrupt)?;
        let receipt_issuer = match verified.purpose() {
            Purpose::Admitted => {
                if pin
                    .plan
                    .as_ref()
                    .is_some_and(|p| expected.through <= p.source().through)
                {
                    return Err(Failure::Corrupt);
                }
                &binding.issuer
            }
            Purpose::RetainedVerified => {
                let plan = pin.plan.as_ref().ok_or(Failure::Corrupt)?;
                if expected.through > plan.source().through {
                    return Err(Failure::Corrupt);
                }
                &plan.source().historical_issuer
            }
        };
        if receipt.body()["issuer"] != service::author(receipt_issuer)? {
            return Err(Failure::Corrupt);
        }
        let Some(Ipld::List(entries)) = manifest.body().get("entries") else {
            return Err(Failure::Corrupt);
        };
        if entries.len() != 1 {
            return Err(Failure::Corrupt);
        }
        let Ipld::Map(entry) = &entries[0] else {
            return Err(Failure::Corrupt);
        };
        let Some(Ipld::Integer(length)) = entry.get("length") else {
            return Err(Failure::Corrupt);
        };
        if *length <= 0 || *length > service::MAX_REQUEST as i128 {
            return Err(Failure::Corrupt);
        }
        Ok((
            Committed {
                sequence: expected.through,
                manifest,
                receipt,
                duplicate: false,
            },
            verified,
        ))
    }
    fn occurrence(
        &self,
        pin: &CheckedPin,
        record: &Committed,
        proof: &attestation::Verified,
        availability: wire::Availability,
    ) -> Result<Occurrence> {
        let receipt_issuer = match proof.purpose() {
            Purpose::Admitted => self.access.binding.issuer.clone(),
            Purpose::RetainedVerified => pin
                .plan
                .as_ref()
                .ok_or(Failure::Corrupt)?
                .source()
                .historical_issuer
                .clone(),
        };
        Ok(Occurrence {
            sequence: record.sequence.to_string(),
            manifest: record.manifest.cid().to_string(),
            receipt: record.receipt.cid().to_string(),
            attestation: proof
                .frontier()
                .attestation
                .as_ref()
                .ok_or(Failure::Corrupt)?
                .to_string(),
            purpose: proof.purpose().as_str().into(),
            issued_at: proof.issued_at().to_string(),
            receipt_issuer,
            availability,
            selection: self.token(pin, proof.frontier(), TokenPurpose::Source)?,
        })
    }
    pub async fn page(&self, pin: &Pin, cursor: Option<&Token>, limit: usize) -> Result<Page> {
        if limit == 0 || limit > wire::PAGE_LIMIT {
            return Err(Failure::Invalid);
        }
        let checked = self.check_pin(pin)?;
        let mut expected = if let Some(cursor) = cursor {
            self.check_token(&checked, cursor, TokenPurpose::Page)?
        } else {
            checked.frontier.clone()
        };
        let (_, reply) = self
            .call(wire::Command::Page {
                pin: wire::Coordinate::from_frontier(&checked.frontier),
                next: wire::Coordinate::from_frontier(&expected),
                limit,
            })
            .await?;
        let wire::Output::Page { records, next } = reply.reply.result? else {
            return Err(Failure::Corrupt);
        };
        if records.len() > limit || (records.is_empty() && expected.through > 0) {
            return Err(Failure::Corrupt);
        }
        let mut output = Vec::new();
        for row in &records {
            let (record, proof) = self.verify_row(&checked, &expected, row)?;
            output.push(self.occurrence(&checked, &record, &proof, row.availability)?);
            expected = proof.previous().clone();
        }
        let wanted = (expected.through > 0).then(|| wire::Coordinate::from_frontier(&expected));
        if next != wanted {
            return Err(Failure::Corrupt);
        }
        let next = if expected.through > 0 {
            Some(self.token(&checked, &expected, TokenPurpose::Page)?)
        } else {
            None
        };
        Ok(Page {
            records: output,
            next,
        })
    }
    pub async fn source(&self, pin: &Pin, selection: &Token) -> Result<Source> {
        let checked = self.check_pin(pin)?;
        let expected = self.check_token(&checked, selection, TokenPurpose::Source)?;
        let (_, reply) = self
            .call(wire::Command::Read {
                pin: wire::Coordinate::from_frontier(&checked.frontier),
                selected: wire::Coordinate::from_frontier(&expected),
            })
            .await?;
        let wire::Output::Evidence {
            record: row,
            source,
        } = reply.reply.result?
        else {
            return Err(Failure::Corrupt);
        };
        self.decode_source(&checked, &expected, row, source)
    }
    fn decode_source(
        &self,
        checked: &CheckedPin,
        expected: &Frontier,
        row: wire::RecordView,
        source: wire::Source,
    ) -> Result<Source> {
        let (record, proof) = self.verify_row(checked, expected, &row)?;
        let occurrence = self.occurrence(checked, &record, &proof, row.availability)?;
        match source {
            wire::Source::Missing if row.availability == wire::Availability::Missing => {
                Ok(Source::Missing { record: occurrence })
            }
            wire::Source::Corrupt if row.availability == wire::Availability::Corrupt => {
                Ok(Source::Corrupt { record: occurrence })
            }
            wire::Source::Available {
                signed_request,
                writer,
            } if row.availability == wire::Availability::Available => {
                let bytes = service::unhex(&signed_request, service::MAX_REQUEST)?;
                let signed = service::verify_retained_request(&record, &bytes)?;
                if signed.request.principal != writer
                    || signed.request.scope != self.access.binding.scope
                    || signed.request.audience != occurrence.receipt_issuer
                {
                    return Err(Failure::Corrupt);
                }
                let service::Command::Append { ciphertext, id, .. } = signed.request.command else {
                    return Err(Failure::Corrupt);
                };
                let ciphertext = service::unhex(&ciphertext, service::MAX_PAYLOAD)?;
                let binding = self.access.binding.owner_binding()?;
                let plaintext =
                    evidence_crypto::open(&self.access.private_key, &binding.scope, &ciphertext)
                        .map_err(|_| Failure::Corrupt)?;
                Ok(Source::Available {
                    record: occurrence,
                    writer,
                    plaintext,
                    operation: id,
                })
            }
            _ => Err(Failure::Corrupt),
        }
    }
}

//! Bounded, explicitly authorized reads. No plaintext persistence or mutation API.
use crate::{
    evidence_crypto, evidence_http,
    evidence_service::{
        self as service, Command, Failure, Output, RecordView, Request, SignedReply, SignedRequest,
    },
    sign::Identity,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Occurrence {
    pub sequence: u64,
    pub manifest: String,
    pub receipt: String,
}
fn decode_record(
    view: &RecordView,
    access: &ScopeAccess,
) -> Result<crate::evidence_store::Committed, Failure> {
    use crate::evidence::{self, Decoded};
    let decode =
        |bytes: &str| match evidence::decode(&service::unhex(bytes, evidence::MAX_RECORD_BYTES)?) {
            Ok(Decoded::Known(record)) => Ok(record),
            _ => Err(Failure::Corrupt),
        };
    let manifest = decode(&view.manifest)?;
    let receipt = decode(&view.receipt)?;
    if !evidence::binds(&receipt, &manifest)
        || manifest.body()["scopeToken"] != atproto_dasl::Ipld::Bytes(access.scope.to_vec())
        || receipt.body()["issuer"] != service::author(&access.issuer)?
    {
        return Err(Failure::Corrupt);
    }
    Ok(crate::evidence_store::Committed {
        sequence: view.sequence,
        manifest,
        receipt,
        duplicate: false,
    })
}
fn occurrence(record: &crate::evidence_store::Committed) -> Occurrence {
    Occurrence {
        sequence: record.sequence,
        manifest: record.manifest.cid().to_string(),
        receipt: record.receipt.cid().to_string(),
    }
}
pub const PAGE_LIMIT: usize = 40;
pub const RANGE_LIMIT: usize = 256 * 1024;
/// Configuration is operator-supplied, never taken from captured content or a URL.
pub struct ScopeAccess {
    pub scope: [u8; 32],
    pub endpoint: String,
    pub issuer: String,
    pub private_key: [u8; 32],
}
pub struct Reader {
    signer: Identity,
    scopes: BTreeMap<String, ScopeAccess>,
}
/// The original signed snapshot reply and request are the snapshot evidence.
/// A pin is not a grant: every subsequent read contacts the authorized service.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    pub request: String,
    pub reply: SignedReply,
}
#[derive(Debug, Serialize)]
pub struct Inventory {
    pub scope: String,
    pub through: u64,
    pub tip: Option<String>,
    pub records: Vec<Occurrence>,
    pub next: Option<u64>,
    pub coverage: &'static str,
}
#[derive(Debug, Serialize)]
pub struct Source {
    pub scope: String,
    pub record: Occurrence,
    pub writer: String,
    pub service_issuer: String,
    pub signature: &'static str,
    pub admission: &'static str,
    pub content_trust: &'static str,
    pub total_bytes: usize,
    pub offset: usize,
    pub next: Option<usize>,
    pub bytes_hex: String,
    pub utf8: Option<String>,
}
impl Reader {
    pub fn new(signer: Identity, scopes: Vec<ScopeAccess>) -> Result<Self, Failure> {
        if scopes.is_empty() || scopes.len() > 16 {
            return Err(Failure::Invalid);
        }
        let mut selected = BTreeMap::new();
        for scope in scopes {
            // Validate the identity/scope pair without writing or sending anything.
            SignedRequest::sign(
                Request {
                    version: 1,
                    scope: service::hex(&scope.scope),
                    principal: signer.did().to_string(),
                    audience: scope.issuer.clone(),
                    expires: Some(1),
                    command: Command::Snapshot,
                },
                &signer,
            )?;
            if selected.insert(service::hex(&scope.scope), scope).is_some() {
                return Err(Failure::Invalid);
            }
        }
        Ok(Self {
            signer,
            scopes: selected,
        })
    }
    fn access(&self, scope: &str) -> Result<&ScopeAccess, Failure> {
        self.scopes.get(scope).ok_or(Failure::AccessLimited)
    }
    /// Configured selection, not proof of a currently valid remote grant.
    pub fn configured_scopes(&self) -> Vec<String> {
        self.scopes.keys().cloned().collect()
    }
    async fn call(
        &self,
        access: &ScopeAccess,
        command: Command,
    ) -> Result<(Vec<u8>, SignedReply), Failure> {
        let request = SignedRequest::sign(
            Request {
                version: 1,
                scope: service::hex(&access.scope),
                principal: self.signer.did().to_string(),
                audience: access.issuer.clone(),
                expires: Some(crate::evidence_operations::now().saturating_add(60)),
                command,
            },
            &self.signer,
        )?
        .bytes()?;
        let reply = evidence_http::send(&access.endpoint, &access.issuer, &request).await?;
        reply.verify(&request, &access.issuer)?;
        Ok((request, reply))
    }
    pub async fn snapshot(&self, scope: &str) -> Result<Pin, Failure> {
        let access = self.access(scope)?;
        let (request, reply) = self.call(access, Command::Snapshot).await?;
        let pin = Pin {
            request: service::hex(&request),
            reply,
        };
        self.check_pin(&pin)?;
        Ok(pin)
    }
    fn check_pin(&self, pin: &Pin) -> Result<(&ScopeAccess, u64, Option<String>), Failure> {
        let bytes = service::unhex(&pin.request, 4096)?;
        let signed = SignedRequest::decode(&bytes)?;
        let access = self.access(&signed.request.scope)?;
        if signed.request.principal != self.signer.did().as_str()
            || signed.request.audience != access.issuer
            || !matches!(signed.request.command, Command::Snapshot)
        {
            return Err(Failure::AccessLimited);
        }
        let reply = pin.reply.verify(&bytes, &access.issuer)?;
        let Output::Snapshot { through, tip } = reply.result.as_ref().map_err(Clone::clone)? else {
            return Err(Failure::Invalid);
        };
        // Reuse the service's page-shape contract for empty/tip consistency.
        service::validate_shape(&Request {
            version: 1,
            scope: signed.request.scope,
            principal: signed.request.principal,
            audience: signed.request.audience,
            expires: Some(1),
            command: Command::Page {
                through: *through,
                tip: tip.clone(),
                after: 0,
                limit: 1,
            },
        })?;
        Ok((access, *through, tip.clone()))
    }
    pub async fn page(&self, pin: &Pin, after: u64, limit: usize) -> Result<Inventory, Failure> {
        if limit == 0 || limit > PAGE_LIMIT {
            return Err(Failure::Invalid);
        }
        let (access, through, tip) = self.check_pin(pin)?;
        if after > through {
            return Err(Failure::Invalid);
        }
        let (_, reply) = self
            .call(
                access,
                Command::Page {
                    through,
                    tip: tip.clone(),
                    after,
                    limit,
                },
            )
            .await?;
        let Output::Page { records, complete } = reply.reply.result? else {
            return Err(Failure::Invalid);
        };
        if records.len() > limit {
            return Err(Failure::Invalid);
        }
        let mut last = after;
        let mut occurrences = Vec::new();
        for row in &records {
            if row.sequence != last.checked_add(1).ok_or(Failure::Invalid)?
                || row.sequence > through
            {
                return Err(Failure::Invalid);
            }
            let record = decode_record(row, access)?;
            if row.sequence == through && Some(record.manifest.cid().to_string()) != tip {
                return Err(Failure::Corrupt);
            }
            occurrences.push(occurrence(&record));
            last = row.sequence;
        }
        if complete != (last == through) || (!complete && records.is_empty()) {
            return Err(Failure::Invalid);
        }
        Ok(Inventory { scope: service::hex(&access.scope), through, tip, records: occurrences,
            next: (!complete).then_some(last), coverage: "selected scope at authenticated snapshot; committed occurrences, not normalized sessions" })
    }
    pub async fn source(
        &self,
        pin: &Pin,
        sequence: u64,
        offset: usize,
        length: usize,
    ) -> Result<Source, Failure> {
        if sequence == 0 || length == 0 || length > RANGE_LIMIT {
            return Err(Failure::Invalid);
        }
        let (access, through, _) = self.check_pin(pin)?;
        if sequence > through {
            return Err(Failure::Missing);
        }
        // Verify current permission and membership at the selected snapshot,
        // not merely membership in a newer, differently pinned archive.
        let mut membership = self.page(pin, sequence - 1, 1).await?;
        let expected = membership.records.pop().ok_or(Failure::Missing)?;
        let (_, reply) = self.call(access, Command::Read { sequence }).await?;
        let Output::Evidence {
            record,
            signed_request,
        } = reply.reply.result?
        else {
            return Err(Failure::Invalid);
        };
        let committed = decode_record(&record, access)?;
        let record = occurrence(&committed);
        if record != expected {
            return Err(Failure::Corrupt);
        }
        let bytes = service::unhex(&signed_request, service::MAX_REQUEST)?;
        let signed = service::verify_retained_request(&committed, &bytes)?;
        if signed.request.scope != service::hex(&access.scope)
            || signed.request.audience != access.issuer
        {
            return Err(Failure::Corrupt);
        }
        let Command::Append { ciphertext, .. } = signed.request.command else {
            return Err(Failure::Corrupt);
        };
        let ciphertext = service::unhex(&ciphertext, service::MAX_PAYLOAD)?;
        let plaintext = evidence_crypto::open(&access.private_key, &access.scope, &ciphertext)
            .map_err(|_| Failure::Corrupt)?;
        if offset > plaintext.len() {
            return Err(Failure::Invalid);
        }
        let end = offset.saturating_add(length).min(plaintext.len());
        let slice = &plaintext[offset..end];
        Ok(Source {
            scope: service::hex(&access.scope),
            record,
            writer: signed.request.principal,
            service_issuer: access.issuer.clone(),
            signature: "retained writer signature and manifest verified",
            admission: "signed service response; membership verified at selected snapshot",
            content_trust:
                "untrusted observed bytes; writer identity does not establish the claimed speaker",
            total_bytes: plaintext.len(),
            offset,
            next: (end < plaintext.len()).then_some(end),
            bytes_hex: service::hex(slice),
            utf8: std::str::from_utf8(slice).ok().map(str::to_owned),
        })
    }
}

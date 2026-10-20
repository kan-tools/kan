//! Compose encryption, durable local admission and exact-byte network delivery.
use crate::{
    evidence_crypto as crypto,
    evidence_service::{self as service, Command, Request, SignedRequest},
    evidence_spool::Spool,
    sign::Identity,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Spool(#[from] crate::evidence_spool::Error),
    #[error(transparent)]
    Crypto(#[from] crypto::Error),
    #[error(transparent)]
    Service(#[from] service::Failure),
    #[error("writer does not match spool")]
    Writer,
    #[error("operation already retained; inspect its status and drain the existing request")]
    ReusedOperation,
    #[error("request scope or writer does not match the explicit pin")]
    Binding,
}
#[derive(Debug, Clone, serde::Serialize)]
pub struct Queued {
    pub operation: String,
    pub position: u64,
    pub manifest: String,
}

/// No network I/O. Reused identifiers are refused, never re-encrypted as retries.
/// Writer reservation, frontier derivation, encryption/signing and commit share
/// one transaction, so concurrent producers cannot sign a stale frontier.
pub fn queue(
    spool: &mut Spool,
    signer: &Identity,
    recipient: &[u8; 32],
    operation: &[u8; 16],
    plaintext: &[u8],
) -> Result<Queued, Error> {
    let operation = service::hex(operation);
    let result = spool.enqueue_generated(&operation, |st| {
        if signer.did().as_str() != st.writer {
            return Err(Error::Writer);
        }
        let scope = service::unhex(&st.scope, 32)?
            .try_into()
            .map_err(|_| service::Failure::Invalid)?;
        let ciphertext = crypto::seal(recipient, &scope, plaintext)?;
        let request = SignedRequest::sign(
            Request {
                version: 1,
                scope: st.scope,
                principal: st.writer,
                audience: st.audience,
                expires: None,
                command: Command::Append {
                    id: operation.clone(),
                    position: st.next,
                    previous: st.previous,
                    ciphertext: service::hex(&ciphertext),
                },
            },
            signer,
        )?
        .bytes()?;
        let manifest = service::append_manifest(&request)?.cid().to_string();
        Ok((
            request,
            Queued {
                operation: operation.clone(),
                position: st.next,
                manifest,
            },
        ))
    });
    match result {
        Err(Error::Spool(crate::evidence_spool::Error::ReusedOperation)) => {
            Err(Error::ReusedOperation)
        }
        other => other,
    }
}

/// Sends only a durably queued request. No key, resealing, skipping or frontier guessing.
/// Cancellation/transport failure can leave the remote committed; retry the same head.
pub async fn deliver_one(spool: &mut Spool, endpoint: &str) -> Result<Option<Queued>, Error> {
    let _custody = spool.erasure_lease()?;
    spool.reconcile_managed_erasure()?;
    let Some(request) = spool.head()? else {
        return Ok(None);
    };
    let signed = SignedRequest::decode(&request)?;
    let Command::Append { id, position, .. } = &signed.request.command else {
        return Err(service::Failure::Invalid.into());
    };
    let reply = crate::evidence_http::send(endpoint, &signed.request.audience, &request).await?;
    let manifest = service::admitted_manifest(&request, &reply, &signed.request.audience)?;
    // A competing drainer may already have advanced the head. Acknowledge rechecks
    // the actual head and refuses this stale proof rather than dropping another row.
    spool.acknowledge(&reply.bytes()?)?;
    Ok(Some(Queued {
        operation: id.clone(),
        position: *position,
        manifest: manifest.cid().to_string(),
    }))
}

/// Authenticated offline recovery with explicit expected scope and writer.
/// Signature validity proves key possession, not historical authorization/admission.
pub fn decrypt_request(
    request: &[u8],
    private: &[u8; 32],
    scope: &[u8; 32],
    writer: &str,
) -> Result<Vec<u8>, Error> {
    let signed = SignedRequest::decode(request)?;
    if signed.request.scope != service::hex(scope) || signed.request.principal != writer {
        return Err(Error::Binding);
    }
    let Command::Append { ciphertext, .. } = signed.request.command else {
        return Err(service::Failure::Invalid.into());
    };
    Ok(crypto::open(
        private,
        scope,
        &service::unhex(&ciphertext, service::MAX_PAYLOAD)?,
    )?)
}

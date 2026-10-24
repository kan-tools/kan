//! Native browser downloads avoid Blob URL support requirements. Credentials
//! travel only in an origin-checked POST body, never URLs, cookies or logs.
use super::*;
use serde_json::Value;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceForm {
    token: String,
    request: Query,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryForm {
    token: String,
    package: crate::evidence_keys::RecoveryPackage,
}
fn attachment(bytes: Vec<u8>, filename: &str) -> Result<Response<Full<Bytes>>, Failure> {
    let mut result = response(StatusCode::OK, "application/octet-stream", bytes);
    result.headers_mut().insert(
        "content-disposition",
        format!("attachment; filename=\"{filename}\"")
            .parse()
            .map_err(|_| Failure::Invalid)?,
    );
    Ok(result)
}
fn coordinate(value: &Value) -> Result<u64, Failure> {
    value.as_u64().map_or_else(
        || crate::evidence_content::coordinate(value.as_str().ok_or(Failure::Corrupt)?),
        Ok,
    )
}
async fn source(
    reader: &Readers,
    bytes: &[u8],
    token: &str,
) -> Result<Response<Full<Bytes>>, ContentError> {
    let form: SourceForm = serde_json::from_slice(bytes).map_err(|_| Failure::Invalid)?;
    if form.token != token {
        return Err(Failure::AccessLimited.into());
    }
    if let Query::ProofAttachment {
        source,
        pin,
        selections,
        direction,
        pointer,
    } = &form.request
    {
        let value = reader
            .attachment(source, pin, selections, *direction, pointer)
            .await?;
        let digest = value.metadata["decoded_sha256"]
            .as_str()
            .ok_or(Failure::Corrupt)?;
        let mut response = attachment(value.bytes, &format!("kan-attachment-{digest}.bin"))?;
        response.headers_mut().insert(
            "x-kan-content-sha256",
            digest.parse().map_err(|_| Failure::Corrupt)?,
        );
        return Ok(response);
    }
    if !matches!(
        form.request,
        Query::Source { .. }
            | Query::SourceExact { .. }
            | Query::ProofSource { .. }
            | Query::CitationSource { .. }
    ) {
        return Err(Failure::Invalid.into());
    }
    // The ordinary source path rechecks current grants, membership, signatures,
    // payload availability and decryption. The form supplies no cached plaintext.
    let value: Value =
        serde_json::from_slice(&reader.query(form.request).await?).map_err(|_| Failure::Corrupt)?;
    let bytes = crate::evidence_service::unhex(
        value["bytes_hex"].as_str().ok_or(Failure::Missing)?,
        262144,
    )?;
    let filename = format!(
        "kan-occurrence-{}-offset-{}.bin",
        coordinate(&value["record"]["sequence"])?,
        coordinate(&value["offset"])?
    );
    Ok(attachment(bytes, &filename)?)
}
fn recovery(reader: &Readers, bytes: &[u8]) -> Result<Response<Full<Bytes>>, Failure> {
    let form: RecoveryForm = serde_json::from_slice(bytes).map_err(|_| Failure::Invalid)?;
    let owner = reader.owner.as_ref().ok_or(Failure::AccessLimited)?;
    if !owner.same_token(&form.token) {
        return Err(Failure::AccessLimited);
    }
    if form.package.version != "kan-key-recovery/1" || form.package.records.len() > 64 {
        return Err(Failure::Invalid);
    }
    let package = serde_json::to_vec(&form.package).map_err(|_| Failure::Invalid)?;
    if package.len() > 131072 {
        return Err(Failure::Invalid);
    }
    // This is transport of the already-exported wrapped package, not verification,
    // restoration, activation, key unwrapping, or a new custody grant.
    attachment(package, "kan-wrapped-key-recovery.json")
}
pub(super) async fn handle(
    r: Request<Incoming>,
    host: &str,
    token: &str,
    reader: &Readers,
    owner: bool,
) -> Response<Full<Bytes>> {
    if r.method() != hyper::Method::POST {
        return denied(StatusCode::METHOD_NOT_ALLOWED);
    }
    if r.headers().get_all("origin").iter().count() != 1
        || r.headers().get("origin").and_then(|v| v.to_str().ok())
            != Some(format!("http://{host}").as_str())
    {
        return denied(StatusCode::FORBIDDEN);
    }
    if r.headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        != Some("text/plain")
    {
        return denied(StatusCode::BAD_REQUEST);
    }
    let body = match tokio::time::timeout(
        Duration::from_secs(3),
        Limited::new(r.into_body(), 2 * 1024 * 1024).collect(),
    )
    .await
    {
        Ok(Ok(body)) => body.to_bytes(),
        Ok(Err(_)) => return denied(StatusCode::PAYLOAD_TOO_LARGE),
        Err(_) => return denied(StatusCode::REQUEST_TIMEOUT),
    };
    // One text/plain form field. JSON escapes embedded line endings; extra form
    // fields, duplicate credentials and trailing bytes cannot be accepted.
    let Some(body) = body
        .strip_prefix(b"payload=")
        .and_then(|b| b.strip_suffix(b"\r\n"))
    else {
        return denied(StatusCode::BAD_REQUEST);
    };
    let result = if owner {
        recovery(reader, body).map_err(ContentError::from)
    } else {
        source(reader, body, token).await
    };
    match result {
        Ok(response) => response,
        Err(ContentError::Read(Failure::AccessLimited)) => denied(StatusCode::FORBIDDEN),
        Err(ContentError::Read(Failure::Missing)) => denied(StatusCode::NOT_FOUND),
        Err(ContentError::Read(Failure::Invalid)) => denied(StatusCode::BAD_REQUEST),
        Err(ContentError::Busy) => denied(StatusCode::TOO_MANY_REQUESTS),
        Err(ContentError::Limited) => denied(StatusCode::UNPROCESSABLE_ENTITY),
        Err(_) => denied(StatusCode::SERVICE_UNAVAILABLE),
    }
}

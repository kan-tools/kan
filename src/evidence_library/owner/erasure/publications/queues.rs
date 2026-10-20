//! Owner-only queue cancellation. Original signed requests retain their chain
//! position; payload retirement requires a real committed admission proof.
use super::*;
use crate::evidence_spool::{Error as SpoolError, Spool};

const INTENTS: usize = 512;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    version: u8,
    job: String,
    request: String,
    identity: (String, String, String),
    authorization: custody::Record,
}
fn key(job: &str, n: usize) -> String {
    format!("erasure:{job}:queue-intent:{n}")
}
fn retained(journal: &Workspace, job: &str) -> Result<Vec<Intent>, Failure> {
    let mut intents = Vec::new();
    for n in 0..INTENTS {
        let Some(value) = journal.get("owner-result", &key(job, n))? else {
            break;
        };
        let intent: Intent = serde_json::from_value(value).map_err(invalid)?;
        if intent.version != 1 || intent.job != job {
            return Err(Failure::Corrupt);
        }
        intents.push(intent);
    }
    Ok(intents)
}
fn spool_error(error: SpoolError) -> Failure {
    match error {
        SpoolError::Proof(f) => f,
        SpoolError::Conflict => Failure::Conflict,
        _ => Failure::Unavailable,
    }
}
pub(super) fn cancel(
    target: &PublicationTarget,
    path: &Path,
    spool: &mut Spool,
    seeds: &BTreeSet<String>,
    selected: &BTreeSet<(String, String, String)>,
    journal: &Workspace,
    job: &str,
) -> Result<Value, Failure> {
    if target.history.binding.profile != Profile::Admitted {
        return Ok(json!({"state":"not-an-admission-destination"}));
    }
    let status = spool.status().map_err(spool_error)?;
    if status.scope != target.history.binding.scope
        || status.audience != target.history.binding.issuer
    {
        return Err(Failure::AccessLimited);
    }
    let keys = keyring(target)?;
    let mut identities = selected.clone();
    for intent in retained(journal, job)? {
        identities.insert(intent.identity);
    }
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut processed = 0;
    for _ in 0..128 {
        if Instant::now() >= deadline {
            return Ok(json!({"state":"pending-budget","processed":processed}));
        }
        let Some(raw) = spool.head().map_err(spool_error)? else {
            return Ok(json!({"state":"queue-empty","processed":processed}));
        };
        let Some(lineage) = decode(&raw, &target.history.binding, &keys)? else {
            return Ok(json!({"state":"pending-unrelated-prefix","processed":processed}));
        };
        if !identities.contains(&lineage.identity)
            && !lineage.cites.iter().any(|c| seeds.contains(c))
            && !lineage.parents.iter().any(|p| identities.contains(p))
        {
            // Do not acknowledge, discard, re-sign or transmit an unrelated head.
            return Ok(json!({"state":"pending-unrelated-prefix","processed":processed}));
        }
        let policy = target.policy.as_ref().ok_or(Failure::AccessLimited)?;
        let policy_snapshot = policy.read()?;
        let request = service::SignedRequest::decode(&raw)?;
        if !policy_snapshot
            .grants()?
            .iter()
            .any(|g| g.principal == request.request.principal && g.append)
        {
            return Err(Failure::AccessLimited);
        }
        let object = store::ciphertext_cid(&raw).to_string();
        // Preparing under exclusive custody excludes managed admission between
        // inspecting archive position and publishing prospective authorization.
        let authorization = target.history.append_prepared(|snapshot| {
            let record = if let Some(record) = snapshot.history.iter().find(|record| {
                record
                    .change
                    .erasure
                    .as_ref()
                    .is_some_and(|e| e.plan.targets.iter().any(|t| t.object == object))
            }) {
                record.clone()
            } else {
                snapshot
                    .check_archive(&target.root.join("archive.sqlite"), &target.history.binding)?;
                let archive = store::attested::Archive::open(
                    &target.root,
                    target.history.binding.owner_binding()?,
                )?;
                let plan = archive.preview_request_erasure(
                    &raw,
                    service::hex(&rand::random::<[u8; 32]>()),
                    crate::evidence_operations::now(),
                )?;
                let erasure = storage::Record::sign(
                    plan,
                    &Identity::load_existing(&target.issuer_key).map_err(invalid)?,
                )?;
                custody::Record::sign(
                    custody::Change {
                        version: 1,
                        binding: target.history.binding.clone(),
                        owner: target.history.owner.clone(),
                        sequence: snapshot.history.len().to_string(),
                        previous: snapshot.tip.clone(),
                        nonce: service::hex(&rand::random::<[u8; 32]>()),
                        recorded_at: crate::evidence_operations::now().to_string(),
                        erasure: Some(erasure),
                    },
                    &Identity::load_existing(&target.signing_key).map_err(invalid)?,
                )?
            };
            let intents = retained(journal, job)?;
            if intents.iter().any(|i| {
                i.request == object
                    && i.identity == lineage.identity
                    && i.authorization.id().ok() == record.id().ok()
            }) {
                return Ok(record);
            }
            let n = intents.len();
            if n >= INTENTS {
                return Err(Failure::Unavailable);
            }
            // Only minimal lineage and signed coordinates survive; no body or
            // signed raw request is copied into the owner journal.
            journal.put(
                "owner-result",
                &key(job, n),
                serde_json::to_value(Intent {
                    version: 1,
                    job: job.into(),
                    request: object.clone(),
                    identity: lineage.identity.clone(),
                    authorization: record.clone(),
                })
                .map_err(invalid)?,
            )?;
            Ok(record)
        })?;
        let erasure = authorization
            .change
            .erasure
            .as_ref()
            .ok_or(Failure::Corrupt)?;
        if erasure.plan.initial_erasure.is_some() {
            let archive = store::attested::Archive::open(
                &target.root,
                target.history.binding.owner_binding()?,
            )?;
            let mut service = service::AdmittingService::new(
                archive,
                Identity::load_existing(&target.issuer_key).map_err(invalid)?,
                policy_snapshot.grants()?,
            )?
            .with_policy(policy.clone())?;
            let proof = service.admit_erased(&raw, erasure, &target.history)?;
            spool
                .reconcile_erasure_with_admissions(&target.history, &[proof])
                .map_err(spool_error)?;
        } else {
            target.history.reconcile_archive(&target.root)?;
            spool
                .reconcile_erasure(&target.history)
                .map_err(spool_error)?;
        }
        identities.insert(lineage.identity);
        if spool.head().map_err(spool_error)?.as_ref() == Some(&raw) {
            return Err(Failure::Conflict);
        }
        processed += 1;
    }
    Ok(json!({"state":"pending-budget","processed":processed,"database":path}))
}

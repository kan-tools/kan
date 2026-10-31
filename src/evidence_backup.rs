//! Independently retained backup receipts. A remote admission receipt never
//! implies backup completion. Transfer and failure-domain independence are
//! operator configured; verification authenticates the destination closure.
use crate::{
    evidence_proof_service as wire,
    evidence_reader::proof::Pin,
    evidence_service::{self as service, Failure},
    evidence_store as store,
    sign::{self, Identity},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    path::Path,
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};
type Result<T> = std::result::Result<T, Failure>;
const DOMAIN: &[u8] = b"tools.kan.backup.checkpoint.v1\0";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Statement {
    pub version: u8,
    pub binding: wire::Binding,
    pub frontier: wire::Coordinate,
    pub bytes: String,
    pub sha256: String,
    pub destination: String,
    pub independent: bool,
    pub verified_at: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub statement: Statement,
    pub owner: String,
    pub signature: String,
}
fn bad<E>(_: E) -> Failure {
    Failure::Corrupt
}
fn preimage(statement: &Statement, owner: &str) -> Result<Vec<u8>> {
    let mut bytes = DOMAIN.to_vec();
    bytes.extend_from_slice(&Sha256::digest(
        serde_json::to_vec(&(statement, owner)).map_err(bad)?,
    ));
    Ok(bytes)
}
impl Checkpoint {
    pub fn sign(statement: Statement, signer: &Identity) -> Result<Self> {
        let owner = signer.did().to_string();
        let signature = service::hex(&signer.sign(&preimage(&statement, &owner)?).map_err(bad)?);
        let value = Self {
            statement,
            owner,
            signature,
        };
        value.verify(signer.did().as_str())?;
        Ok(value)
    }
    pub fn verify(&self, expected_owner: &str) -> Result<()> {
        let s = &self.statement;
        s.binding.owner_binding()?;
        s.frontier.frontier(&s.binding)?;
        if self.owner != expected_owner
            || s.version != 1
            || s.destination.is_empty()
            || s.destination.len() > 128
            || s.bytes
                .parse::<u64>()
                .ok()
                .is_none_or(|n| n == 0 || n.to_string() != s.bytes)
            || s.verified_at
                .parse::<u64>()
                .ok()
                .is_none_or(|n| n.to_string() != s.verified_at)
            || service::unhex(&s.sha256, 32)?.len() != 32
            || !sign::verify(
                &self.owner,
                &preimage(s, &self.owner)?,
                &service::unhex(&self.signature, 64)?,
            )
        {
            return Err(Failure::Corrupt);
        }
        Ok(())
    }
}
fn standalone(path: &Path) -> Result<()> {
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut name = path.as_os_str().to_owned();
        name.push(suffix);
        match std::fs::symlink_metadata(name) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            _ => return Err(Failure::Conflict),
        }
    }
    Ok(())
}
fn identity(meta: &std::fs::Metadata) -> Result<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.mode() & 0o077 != 0 || meta.nlink() != 1 {
            return Err(Failure::Invalid);
        }
        Ok(format!(
            "{}:{}:{}:{}:{}:{}:{}",
            meta.dev(),
            meta.ino(),
            meta.len(),
            meta.mtime(),
            meta.mtime_nsec(),
            meta.ctime(),
            meta.ctime_nsec()
        ))
    }
    #[cfg(not(unix))]
    {
        Ok(format!(
            "{}:{:?}",
            meta.len(),
            meta.modified().map_err(bad)?
        ))
    }
}
/// Audit a completed standalone destination, including all retained payloads,
/// before signing anything. Never silently repair or activate this file.
pub fn inspect(
    path: &Path,
    binding: &wire::Binding,
    destination: &str,
    independent: bool,
) -> Result<Statement> {
    standalone(path)?;
    let before = std::fs::symlink_metadata(path).map_err(bad)?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err(Failure::Invalid);
    }
    let fingerprint = identity(&before)?;
    let file = std::fs::File::open(path).map_err(bad)?;
    fs4::FileExt::try_lock_shared(&file).map_err(|_| Failure::Conflict)?;
    let mut file = crate::file_lease::FileLease(file);
    if identity(&file.0.metadata().map_err(bad)?)? != fingerprint {
        return Err(Failure::Conflict);
    }
    match binding.profile {
        wire::Profile::Admitted => {
            store::attested::Archive::verify_file(path, binding.owner_binding()?)?;
        }
        wire::Profile::Copied => {
            store::copied::Archive::verify_file(path, binding.owner_binding()?)?;
        }
    }
    let profile = match binding.profile {
        wire::Profile::Admitted => store::inventory::Profile::Admitted,
        wire::Profile::Copied => store::inventory::Profile::Copied,
    };
    let inventory = store::inventory::Inventory::open(
        path,
        profile,
        binding.owner_binding()?,
        store::inventory::Budget {
            items: u64::MAX,
            metadata_bytes: u64::MAX,
            duration: Duration::from_secs(3600),
            cancelled: Arc::new(AtomicBool::new(false)),
        },
    )?;
    let frontier = wire::Coordinate::from_frontier(inventory.frontier());
    drop(inventory);
    let mut hash = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 65536];
    while let n @ 1.. = file.0.read(&mut buffer).map_err(bad)? {
        hash.update(&buffer[..n]);
        bytes = bytes.checked_add(n as u64).ok_or(Failure::Invalid)?;
    }
    standalone(path)?;
    if bytes != before.len()
        || identity(&file.0.metadata().map_err(bad)?)? != fingerprint
        || identity(&std::fs::symlink_metadata(path).map_err(bad)?)? != fingerprint
    {
        return Err(Failure::Conflict);
    }
    Ok(Statement {
        version: 1,
        binding: binding.clone(),
        frontier,
        bytes: bytes.to_string(),
        sha256: service::hex(&hash.finalize()),
        destination: destination.into(),
        independent,
        verified_at: crate::evidence_operations::now().to_string(),
    })
}
/// Validate an independently retained service snapshot. The signed witness
/// establishes an acknowledged high-water mark, not ancestry after a lost tail.
pub fn witnessed_frontier(pin: &Pin, binding: &wire::Binding) -> Result<wire::Coordinate> {
    let bytes = service::unhex(&pin.request, wire::MAX_REQUEST)?;
    let request = wire::SignedRequest::decode(&bytes)?;
    if request.request.binding != *binding
        || !matches!(request.request.command, wire::Command::Snapshot)
    {
        return Err(Failure::Invalid);
    }
    let reply = pin.reply.verify(&bytes, &binding.issuer)?;
    let wire::Output::Snapshot { frontier, .. } = reply.result.as_ref().map_err(Clone::clone)?
    else {
        return Err(Failure::Corrupt);
    };
    frontier.frontier(binding)?;
    Ok(frontier.clone())
}
pub fn coverage(
    checkpoint: &Checkpoint,
    expected_owner: &str,
    observed: &Statement,
    witness: Option<&Pin>,
) -> Result<Value> {
    checkpoint.verify(expected_owner)?;
    let s = &checkpoint.statement;
    if s.binding != observed.binding
        || s.frontier != observed.frontier
        || s.sha256 != observed.sha256
        || s.bytes != observed.bytes
    {
        return Err(Failure::Conflict);
    }
    let backed = s.frontier.frontier(&s.binding)?.through;
    let witness = witness
        .map(|p| witnessed_frontier(p, &s.binding))
        .transpose()?;
    let witnessed = witness
        .as_ref()
        .map(|f| f.frontier(&s.binding).map(|f| f.through))
        .transpose()?;
    if witnessed == Some(backed) && witness.as_ref() != Some(&s.frontier) {
        return Err(Failure::Conflict);
    }
    Ok(
        json!({"state":if s.independent {"backup-checkpointed"}else{"local-copy-verified"},
        "checkpoint_frontier":s.frontier,"checkpoint_age_seconds":crate::evidence_operations::now().saturating_sub(s.verified_at.parse::<u64>().map_err(bad)?).to_string(),
        "witnessed_frontier":witness,"uncovered_interval":witnessed.filter(|n|*n>backed).map(|n|json!({"first":(backed+1).to_string(),"last":n.to_string(),"count":(n-backed).to_string()})),
        "receipt_coverage":match witnessed {None=>"unknown-no-independent-witness",Some(n) if n>backed=>"acknowledged-positions-not-covered",Some(n) if n<backed=>"witness-older-than-checkpoint",_=>"covered-through-witness"},
        "ancestry_after_checkpoint":"not-provable-from-a-high-water-witness-alone; divergent signed histories require investigation",
        "independence":"operator-declared failure domain; destination closure verified", "scope":"archive payloads and embedded provenance/control; separate key and workspace recovery packages remain required", "activation":"not-performed"}),
    )
}

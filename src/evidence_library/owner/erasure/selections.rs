//! Complete retained selections are separate from bounded deletion authorities.
use super::*;
mod execution;
mod pages;
const DOMAIN: &[u8] = b"tools.kan.owner.erasure-selection.v1\0";
const PAGE: usize = 512;
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Selector {
    Capture { capture: storage::Capture },
    Captures { captures: Vec<storage::Capture> },
    ArchivePrefix,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reference {
    pub selection: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Approval {
    Inline(Box<Preview>),
    Retained(Reference),
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u8,
    target: String,
    binding: Binding,
    owner: String,
    selector: Selector,
    through: u64,
    tip: String,
    custody: String,
    root: String,
    pages: usize,
    objects: usize,
    bytes: String,
    recording_gap: Option<bool>,
    coverage: String,
}
fn inspect(
    target: &Target,
    sequences: Option<&[u64]>,
    prefix: Option<(u64, &str)>,
) -> Result<storage::Coordinates, Failure> {
    let Configured { root, history, .. } = configured(target)?;
    let binding = history.binding.owner_binding()?;
    Ok(match history.binding.profile {
        Profile::Admitted => store::attested::Archive::open(root, binding)?
            .inspect_erasure_selection(sequences, prefix)?,
        Profile::Copied => store::copied::Archive::open(root, binding)?
            .inspect_erasure_selection(sequences, prefix)?,
    })
}
fn contract(target: &Target, reference: &Reference, manifest: &Manifest) -> Result<Value, Failure> {
    let value = json!({"version":1,"target":target,"operation":"erase-selection","plan":reference,"selection":manifest,
        "effect":"Authorize exactly the complete retained selection. Publish bounded issuer and owner authorizations to independent custody before removing payloads. Reconcile configured replicas, queues, dependent workspaces and publication lineage. Keep signed minimal provenance and visible recording gaps. Later archive appends are outside this approval; historical backups and keys remain separate.",
        "cancellation":"Once accepted, erasure cannot be rolled back. Resume this retained consent after interruption; execution batches never expand the approved selection."});
    if serde_json::to_vec(&value).map_err(invalid)?.len() > 200 * 1024 {
        return Err(Failure::Unavailable);
    }
    Ok(value)
}
fn signed_bytes(contract: &Value) -> Result<Vec<u8>, Failure> {
    Ok([DOMAIN, &serde_json::to_vec(contract).map_err(invalid)?].concat())
}
impl Owner {
    pub(in crate::evidence_library::owner) async fn preview_erasure_selection(
        self: &Arc<Self>,
        target: String,
        selector: Selector,
        page_records: usize,
    ) -> Result<Value, Failure> {
        if page_records == 0 || page_records > 512 {
            return Err(Failure::Invalid);
        }
        let target = self
            .targets
            .get(&target)
            .ok_or(Failure::AccessLimited)?
            .clone();
        let permit = self
            .preparation
            .clone()
            .try_acquire_owned()
            .map_err(|_| Failure::Unavailable)?;
        let owner = self.clone();
        tokio::task::spawn_blocking(move|| {
            let _permit=permit;
            let Configured {root,history,..}=configured(&target)?;
            let current=history.current()?;
            current.check_archive(&root.join("archive.sqlite"),&history.binding)?;
            let captures=match &selector {
                Selector::Capture {capture}=>vec![capture.clone()],
                Selector::Captures {captures}=> {
                    if captures.is_empty() {return Err(Failure::Invalid);}
                    let mut unique=std::collections::BTreeSet::new();
                    for capture in captures {if !unique.insert(Owner::hash(&serde_json::to_value(capture).map_err(invalid)?)?) {return Err(Failure::Invalid);}}
                    captures.clone()
                },
                Selector::ArchivePrefix=>Vec::new(),
            };
            let mut sequences=std::collections::BTreeSet::new();
            let mut frontier=None;
            let mut gaps=false;
            for (index,capture) in captures.iter().enumerate() {
                let selected=match discover_capture(&owner.workspace,&target,capture.clone(),page_records)? {
                    Discovery::Pending(progress)=>return Ok(json!({"target":target.id(),"state":"discovering","progress":progress,"capture_index":index,"captures":captures.len(),"effect":"Discovery only; complete selection approval is unavailable until every selected capture is closed and fully discovered."})),
                    Discovery::Complete(selected)=>*selected,
                };
                if frontier.as_ref().is_some_and(|f|f!=&(selected.through,selected.tip.clone())) {return Err(Failure::Conflict);}
                frontier=Some((selected.through,selected.tip));gaps|=selected.recording_gap;
                sequences.extend(selected.sequences);
            }
            let sequences=sequences.into_iter().collect::<Vec<_>>();
            let coordinates=inspect(&target,(!captures.is_empty()).then_some(sequences.as_slice()),frontier.as_ref().map(|(n,id)|(*n,id.as_str())))?;
            if frontier.as_ref().is_some_and(|f|f!=&(coordinates.through,coordinates.tip.clone())) {return Err(Failure::Conflict);}
            let coverage=if captures.is_empty() {
                "Every retained payload in this pinned archive prefix, including opaque/imported data and active captures. This is deliberately broader than closed-capture selection. Later appends are excluded; recording completeness is not inferred."
            } else {
                "Complete retained membership of every explicitly selected closed writer/observer/attempt in one pinned archive prefix. Recording gaps remain disclosed."
            };
            let manifest=pages::retain(&owner.workspace,&target,selector,&coordinates,current.tip.ok_or(Failure::Corrupt)?,(!captures.is_empty()).then_some(gaps),coverage)?;
            let reference=Reference {selection:Owner::hash(&serde_json::to_value(&manifest).map_err(invalid)?)?};
            let c=contract(&target,&reference,&manifest)?;
            Ok(json!({"target":target.id(),"digest":Owner::hash(&c)?,"plan":reference,"contract":c,"summary":manifest}))
        }).await.map_err(|_|Failure::Unavailable)?
    }
    pub(in crate::evidence_library::owner) async fn inspect_erasure_selection(
        self: &Arc<Self>,
        target: String,
        selection: String,
        page: usize,
    ) -> Result<Value, Failure> {
        let target = self
            .targets
            .get(&target)
            .ok_or(Failure::AccessLimited)?
            .clone();
        let owner = self.clone();
        tokio::task::spawn_blocking(move|| {
            let (manifest,pages)=pages::read(&owner.workspace,&selection)?;
            pages::check_target(&target,&manifest)?;
            let selected=pages.get(page).ok_or(Failure::Missing)?;
            Ok(json!({"selection":selection,"summary":manifest,"page":page,"targets":selected.targets,"next":(page+1<pages.len()).then_some(page+1)}))
        }).await.map_err(|_|Failure::Unavailable)?
    }
}

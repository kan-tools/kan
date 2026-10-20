//! Host-local managed launch enrollment. This file is independently configured;
//! restored databases never select their own custody or downgrade the checks.
use super::{Command, PathBuf};
use kan::{evidence_erasure_history::Access, evidence_workspace::publication::Config as Guard};
use serde::Deserialize;
use std::{
    collections::BTreeSet,
    path::{Component, Path},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Deployment {
    version: u8,
    #[serde(default)]
    archives: Vec<Archive>,
    #[serde(default)]
    spools: Vec<Spool>,
    #[serde(default)]
    workspaces: Vec<Workspace>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Archive {
    root: PathBuf,
    history: PathBuf,
}
#[derive(Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum Kind {
    Raw,
    Annotation,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spool {
    database: PathBuf,
    history: PathBuf,
    kind: Kind,
    publication_guard: Option<PathBuf>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Workspace {
    database: PathBuf,
    guard: PathBuf,
}
fn path(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err("managed paths must be absolute without parent/current components".into());
    }
    Ok(())
}
fn read<T: serde::de::DeserializeOwned>(file: &Path) -> Result<T> {
    path(file)?;
    Ok(serde_json::from_slice(
        &kan::evidence_gateway::secret_file(file)?,
    )?)
}
fn history(file: &Path) -> Result<Access> {
    let access: Access = read(file)?;
    access.validate()?;
    if access.minimum.is_none() {
        return Err("managed custody requires an independent checkpoint".into());
    }
    Ok(access)
}
fn guard(file: &Path) -> Result<Guard> {
    let config: Guard = read(file)?;
    for p in [&config.database, &config.signing_key, &config.recipient_key] {
        path(p)?;
    }
    if config.sources.is_empty() || config.sources.len() > 16 {
        return Err("managed workspace requires 1..16 source histories".into());
    }
    let mut seen = BTreeSet::new();
    for access in &config.sources {
        access.validate()?;
        if access.minimum.is_none() || !seen.insert(serde_json::to_vec(&access.binding)?) {
            return Err("managed sources require unique independently pinned custody".into());
        }
    }
    Ok(config)
}
fn select(selected: &mut Option<PathBuf>, required: &Path) -> Result<()> {
    if selected.as_ref().is_some_and(|p| p != required) {
        return Err("command overrides managed enrollment".into());
    }
    *selected = Some(required.to_path_buf());
    Ok(())
}
impl Deployment {
    pub(super) fn load(file: &Path) -> Result<Self> {
        let config: Self = read(file)?;
        let count = config.archives.len() + config.spools.len() + config.workspaces.len();
        if config.version != 1 || count == 0 || count > 256 {
            return Err("invalid managed deployment inventory".into());
        }
        let mut paths = BTreeSet::new();
        let mut authorities = std::collections::BTreeMap::new();
        let mut remember = |access: Access| -> Result<()> {
            let binding = serde_json::to_vec(&access.binding)?;
            let value = serde_json::to_vec(&access)?;
            if authorities
                .insert(binding, value.clone())
                .is_some_and(|old| old != value)
            {
                return Err("one managed binding has conflicting custody configurations".into());
            }
            Ok(())
        };
        for archive in &config.archives {
            path(&archive.root)?;
            if !paths.insert(&archive.root) {
                return Err("duplicate managed path".into());
            }
            remember(history(&archive.history)?)?;
        }
        for workspace in &config.workspaces {
            path(&workspace.database)?;
            if !paths.insert(&workspace.database) {
                return Err("duplicate managed path".into());
            }
            let selected = guard(&workspace.guard)?;
            if selected.database != workspace.database {
                return Err("managed workspace guard names another database".into());
            }
            for source in selected.sources {
                remember(source)?;
            }
        }
        for spool in &config.spools {
            path(&spool.database)?;
            if !paths.insert(&spool.database) {
                return Err("duplicate managed path".into());
            }
            let access = history(&spool.history)?;
            if access.binding.profile != kan::evidence_proof_service::Profile::Admitted {
                return Err("managed sender requires an admitted destination".into());
            }
            remember(access)?;
            match (&spool.kind, &spool.publication_guard) {
                (Kind::Raw, None) => {}
                (Kind::Annotation, Some(file)) => {
                    let selected = guard(file)?;
                    if !config
                        .workspaces
                        .iter()
                        .any(|w| w.database == selected.database && &w.guard == file)
                    {
                        return Err("annotation sender workspace is not registered".into());
                    }
                }
                _ => {
                    return Err(
                        "annotation senders require source guards; raw senders cannot use them"
                            .into(),
                    )
                }
            }
        }
        Ok(config)
    }
    fn spool(&self, database: &Path) -> Result<&Spool> {
        self.spools
            .iter()
            .find(|s| s.database == database)
            .ok_or_else(|| "sender is not registered in managed deployment".into())
    }
    pub(super) fn outbox(
        &self,
        database: &Path,
        workspace: &Guard,
        selected: Option<Access>,
    ) -> Result<Access> {
        let spool = self.spool(database)?;
        let file = spool
            .publication_guard
            .as_ref()
            .ok_or("managed annotation outbox requires a source guard")?;
        if spool.kind != Kind::Annotation
            || serde_json::to_vec(&guard(file)?)? != serde_json::to_vec(workspace)?
        {
            return Err("outbox uses another managed workspace".into());
        }
        let required = history(&spool.history)?;
        if selected
            .as_ref()
            .is_some_and(|s| serde_json::to_vec(s).ok() != serde_json::to_vec(&required).ok())
        {
            return Err("outbox overrides managed custody".into());
        }
        Ok(required)
    }
    /// Match the owner's cleanup scope to this host's declared launch inventory.
    /// This checks configuration coverage, not whether another process is running
    /// with this configuration, nor the existence of unregistered/off-host copies.
    pub(super) fn validate_owner(&self, config: &kan::evidence_library::OwnerConfig) -> Result<()> {
        let targets = serde_json::to_value(&config.targets)?;
        for target in targets.as_array().ok_or("invalid owner targets")? {
            if target["kind"] != "capture-erasure" {
                continue;
            }
            let mut destinations = vec![target];
            if let Some(publications) = target["publications"].as_array() {
                destinations.extend(publications);
            }
            let mut accesses = Vec::new();
            for destination in &destinations {
                let access: Access = serde_json::from_value(destination["history"].clone())?;
                let mut roots = vec![destination["root"].as_str().ok_or("missing erasure root")?];
                if let Some(replicas) = destination["replicas"].as_array() {
                    for replica in replicas {
                        roots.push(replica.as_str().ok_or("invalid erasure replica")?);
                    }
                }
                for root in &roots {
                    let entry = self
                        .archives
                        .iter()
                        .find(|a| a.root == Path::new(root))
                        .ok_or("erasure archive is not registered")?;
                    if serde_json::to_vec(&history(&entry.history)?)?
                        != serde_json::to_vec(&access)?
                    {
                        return Err("erasure target conflicts with managed archive custody".into());
                    }
                }
                for archive in &self.archives {
                    if history(&archive.history)?.binding == access.binding
                        && !roots.iter().any(|p| archive.root == Path::new(p))
                    {
                        return Err("erasure target omits a registered archive replica".into());
                    }
                }
                let queues = destination["spools"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default();
                for queue in &queues {
                    let entry =
                        self.spool(Path::new(queue.as_str().ok_or("invalid erasure queue")?))?;
                    if serde_json::to_vec(&history(&entry.history)?)?
                        != serde_json::to_vec(&access)?
                    {
                        return Err(
                            "erasure queue conflicts with managed destination custody".into()
                        );
                    }
                }
                for spool in &self.spools {
                    if history(&spool.history)?.binding == access.binding
                        && !queues
                            .iter()
                            .any(|p| p.as_str().is_some_and(|p| spool.database == Path::new(p)))
                    {
                        return Err("erasure target omits a registered sender".into());
                    }
                }
                accesses.push(access);
            }
            let workspaces = target["workspaces"].as_array().cloned().unwrap_or_default();
            for workspace in &workspaces {
                let database = Path::new(
                    workspace["database"]
                        .as_str()
                        .ok_or("invalid erasure workspace")?,
                );
                let registered = self
                    .workspaces
                    .iter()
                    .find(|w| w.database == database)
                    .ok_or("erasure workspace is not registered")?;
                let selected = guard(&registered.guard)?;
                if workspace["signing_key"].as_str().map(Path::new)
                    != Some(selected.signing_key.as_path())
                    || workspace["recipient_key"].as_str().map(Path::new)
                        != Some(selected.recipient_key.as_path())
                {
                    return Err(
                        "erasure workspace credentials conflict with managed enrollment".into(),
                    );
                }
            }
            for workspace in &self.workspaces {
                let selected = guard(&workspace.guard)?;
                if selected
                    .sources
                    .iter()
                    .any(|s| accesses.iter().any(|a| a.binding == s.binding))
                    && !workspaces.iter().any(|w| {
                        w["database"]
                            .as_str()
                            .is_some_and(|p| workspace.database == Path::new(p))
                    })
                {
                    return Err("erasure target omits a registered dependent workspace".into());
                }
            }
            for spool in &self.spools {
                if let Some(file) = &spool.publication_guard {
                    let selected = guard(file)?;
                    if selected
                        .sources
                        .iter()
                        .any(|s| accesses.iter().any(|a| a.binding == s.binding))
                        && !accesses
                            .iter()
                            .any(|a| history(&spool.history).is_ok_and(|h| a.binding == h.binding))
                    {
                        return Err(
                            "erasure target omits a dependent publication destination".into()
                        );
                    }
                }
            }
        }
        Ok(())
    }
    pub(super) fn enroll(&self, command: &mut Command) -> Result<Option<Guard>> {
        match command {
            Command::ServeAdmitted {
                archive,
                erasure_history,
                ..
            } => {
                let entry = self
                    .archives
                    .iter()
                    .find(|a| a.root == *archive)
                    .ok_or("archive is not registered in managed deployment")?;
                select(erasure_history, &entry.history)?;
            }
            Command::ServeProof {
                archive,
                erasure_history,
                ..
            } => {
                let entry = self
                    .archives
                    .iter()
                    .find(|a| a.root == *archive || a.root.join("archive.sqlite") == *archive)
                    .ok_or("archive is not registered in managed deployment")?;
                // The manifest enrolls a directory, while the read-only proof
                // service opens its database. Preserve the legacy explicit-file
                // CLI form without accepting another file under that directory.
                *archive = entry.root.join("archive.sqlite");
                select(erasure_history, &entry.history)?;
            }
            Command::SpoolHead {
                spool,
                erasure_history,
                publication_guard,
            }
            | Command::SpoolDrain {
                spool,
                erasure_history,
                publication_guard,
                ..
            }
            | Command::SpoolWatch {
                spool,
                erasure_history,
                publication_guard,
                ..
            } => {
                let entry = self.spool(spool)?;
                select(erasure_history, &entry.history)?;
                match &entry.publication_guard {
                    Some(file) => select(publication_guard, file)?,
                    None if publication_guard.is_none() => {}
                    None => return Err("raw sender cannot override its managed role".into()),
                }
            }
            Command::SpoolStatus {
                spool,
                erasure_history,
                ..
            } => {
                select(erasure_history, &self.spool(spool)?.history)?;
            }
            Command::QueueInput {
                spool,
                erasure_history,
                ..
            } => {
                let entry = self.spool(spool)?;
                if entry.kind != Kind::Raw {
                    return Err("raw input cannot enter a managed annotation queue".into());
                }
                select(erasure_history, &entry.history)?;
            }
            Command::Owner { .. } => {}
            Command::Library {
                workspace,
                workspace_key,
                signing_key,
                workspace_erasure_history,
                ..
            } => {
                let database = workspace
                    .as_ref()
                    .ok_or("managed Library requires its registered workspace")?;
                let entry = self
                    .workspaces
                    .iter()
                    .find(|w| &w.database == database)
                    .ok_or("Library workspace is not registered")?;
                let selected = guard(&entry.guard)?;
                if workspace_key.as_ref() != Some(&selected.recipient_key)
                    || *signing_key != selected.signing_key
                    || !workspace_erasure_history.is_empty()
                {
                    return Err("Library arguments override managed workspace custody".into());
                }
                // Check old restores before exposing API, MCP or a listener.
                drop(selected.open()?);
                return Ok(Some(selected));
            }
            _ => return Err(
                "this command has no managed launch role; use explicit offline maintenance instead"
                    .into(),
            ),
        }
        Ok(None)
    }
}

//! Read-only resolution for the machine-relative RFC 2 `kan` authority.

use std::path::Path;

use atproto_dasl::Cid;

use super::{
    AtAuthority, EvidenceSelection, KanAuthority, PrincipalId, ResolutionRequest, Resource, Route,
    ScopeSelector, SubjectSelector,
};
use crate::{
    claim::view::{ClaimSource, ClaimSubjectId, ClaimView},
    fold::claim_view::SubjectView,
    identity::{
        control::IdentityVersion,
        did_kan_update::{DidKanResolution, NonActiveIdentityStanding},
        ledger::IdentityLedger,
        scope_inception::ScopeId,
        scope_store::{InstalledScope, ScopeIdentityStore},
        system::SystemIdentityStore,
        ClaimJudgments,
    },
    workspace::{MixedWorkspaceProjection, Workspace},
};

pub struct LocalResolver<'a> {
    cwd: &'a Path,
    system: &'a SystemIdentityStore,
}

impl<'a> LocalResolver<'a> {
    pub fn new(cwd: &'a Path, system: &'a SystemIdentityStore) -> Self {
        Self { cwd, system }
    }

    pub async fn resolve_uri(&self, input: &str) -> Result<ResolutionResult, Error> {
        let request = ResolutionRequest::parse(input)?;
        self.resolve(&request).await
    }

    pub async fn resolve(&self, request: &ResolutionRequest) -> Result<ResolutionResult, Error> {
        match request.route() {
            Route::Kan(KanAuthority::Local { port: None }) => {
                self.resolve_scoped_local(request).await
            }
            Route::Kan(KanAuthority::Did(principal)) => {
                self.resolve_freestanding(request, principal).await
            }
            Route::Kan(KanAuthority::Local { port: Some(_) })
            | Route::Kan(KanAuthority::Host { .. })
            | Route::Git(_)
            | Route::At(AtAuthority::Handle(_) | AtAuthority::Did(_)) => {
                Err(Error::AuthorityNotFound)
            }
        }
    }

    async fn resolve_scoped_local(
        &self,
        request: &ResolutionRequest,
    ) -> Result<ResolutionResult, Error> {
        if matches!(request.resource(), Resource::AuthorityIdentity) && request.scope().is_none() {
            return Err(Error::AuthorityIdentityUnknown);
        }
        validate_local_source(request.evidence())?;
        let discovered_root = crate::workspace::find_repo_root(self.cwd);
        if discovered_root.join(".git").is_file() {
            // A linked worktree or submodule has an indirect Git directory.
            // Until #197 defines whether `.kan` follows the common repository
            // or the checkout, selecting either would silently choose an
            // ownership model. Explicit URI resolution refuses that guess.
            return Err(Error::IndirectGitDirectoryUnsupported);
        }
        let Some(selector) = request.scope() else {
            return Err(Error::ScopeNotFound);
        };

        let before = source_guard(Some(&discovered_root), self.system)?;
        let mut workspace =
            Workspace::open_resolution_read_only_with_system(self.cwd, self.system).await?;
        let projection = self.project(&mut workspace, request).await?;
        let scope_store = ScopeIdentityStore::at(workspace.root.join(".kan").join("scope"));
        let installed = scope_store.read()?.ok_or(Error::ScopeNotFound)?;
        let selected_scope = installed.scope;
        if projection
            .legacy_scope()
            .is_some_and(|verified| verified != selected_scope)
        {
            return Err(Error::ScopeIdentifierMismatch);
        }
        let bindings = [ScopeBinding {
            scope: selected_scope,
            names: &installed.inception.names,
        }];
        if select_scope(selector, &bindings)? != selected_scope {
            return Err(Error::ScopeIdentifierMismatch);
        }

        let after = source_guard(Some(&workspace.root), self.system)?;
        if before != after {
            return Err(Error::SourceChangedDuringResolution);
        }
        let snapshot = snapshot(Some(&workspace), self.system, Some(&installed), after)?;
        require_snapshot(request.evidence(), &snapshot)?;
        let diagnostics = workspace
            .published
            .read_errors()
            .iter()
            .map(|error| format!("{}:{}:{}", error.kind, error.path, error.message))
            .collect::<Vec<_>>();
        let resource =
            resolve_scoped_resource(request, &projection, selected_scope, installed.clone())?;
        Ok(result(
            request,
            Some(selected_scope),
            snapshot,
            "local-kan",
            selected_scope.to_string(),
            diagnostics,
            resource,
        ))
    }

    async fn resolve_freestanding(
        &self,
        request: &ResolutionRequest,
        principal: &PrincipalId,
    ) -> Result<ResolutionResult, Error> {
        validate_local_source(request.evidence())?;
        if request.scope().is_some()
            || !matches!(request.resource(), Resource::PrincipalIdentity(value) if value == principal)
        {
            return Err(Error::AuthorityNotFound);
        }
        let before = source_guard(None, self.system)?;
        let resolutions = self.system.resolve_public_identities()?;
        let resolution = resolve_principal(
            principal,
            request.evidence().version.as_ref(),
            &resolutions,
            &[],
        )?;
        let after = source_guard(None, self.system)?;
        if before != after {
            return Err(Error::SourceChangedDuringResolution);
        }
        let snapshot = snapshot(None, self.system, None, after)?;
        require_snapshot(request.evidence(), &snapshot)?;
        Ok(result(
            request,
            None,
            snapshot,
            "system-identity-ledger",
            principal.to_string(),
            Vec::new(),
            ResolvedResource::PrincipalIdentity(PrincipalIdentityResult {
                principal: principal.clone(),
                resolution,
            }),
        ))
    }

    async fn project(
        &self,
        workspace: &mut Workspace,
        request: &ResolutionRequest,
    ) -> Result<MixedWorkspaceProjection, Error> {
        match request.evaluation().trust.as_ref() {
            None => Ok(workspace
                .mixed_local_projection_with_system(self.system)
                .await?),
            Some(trust) => {
                let specs = vec![trust.clone()];
                let (frame, _) = workspace.trust_from_detailed_with_system(&specs, self.system)?;
                Ok(workspace
                    .mixed_projection_with_system(self.system, &frame)
                    .await?)
            }
        }
    }
}

#[derive(Clone, Copy)]
struct ScopeBinding<'a> {
    scope: ScopeId,
    names: &'a [String],
}

fn select_scope(selector: &ScopeSelector, bindings: &[ScopeBinding<'_>]) -> Result<ScopeId, Error> {
    match selector {
        ScopeSelector::Direct(requested) => bindings
            .iter()
            .find(|binding| binding.scope == *requested)
            .map(|binding| binding.scope)
            .ok_or_else(|| {
                if bindings.is_empty() {
                    Error::ScopeNotFound
                } else {
                    Error::ScopeIdentifierMismatch
                }
            }),
        ScopeSelector::Named(locator) => {
            let matches = bindings
                .iter()
                .filter(|binding| binding.names.iter().any(|name| name == locator.as_str()))
                .map(|binding| binding.scope)
                .collect::<std::collections::BTreeSet<_>>();
            match matches.len() {
                0 => Err(Error::ScopeNotFound),
                1 => Ok(*matches.first().expect("one matching scope")),
                _ => Err(Error::AmbiguousScopeLocator),
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResolutionResult {
    pub canonical_request: String,
    pub immutable_replay: String,
    pub target: TargetKey,
    pub sources: Vec<SourceResult>,
    pub claim_evaluations: Vec<ClaimEvaluation>,
    pub resource: ResolvedResource,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetKey {
    pub scope: Option<ScopeId>,
    pub resource: Resource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceResult {
    pub kind: String,
    pub identity: String,
    pub substrate: String,
    pub access: SourceAccess,
    pub snapshot: Cid,
    pub completeness: SourceCompleteness,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceAccess {
    Available,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceCompleteness {
    Committed,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClaimEvaluation {
    pub claim: Cid,
    pub judgments: ClaimJudgments,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ResolvedResource {
    Claim(Box<ClaimView>),
    Subject(SubjectResult),
    ScopeIdentity(ScopeIdentityResult),
    PrincipalIdentity(PrincipalIdentityResult),
}

#[derive(Debug, Clone, PartialEq)]
pub struct SubjectResult {
    pub selector: SubjectSelector,
    /// All authentic evidence for the exact target, including claims excluded
    /// from the selected fold by admission or trust.
    pub evidence: Vec<ClaimView>,
    /// The selected consumer view, when the target participates in it.
    pub folded: Option<SubjectView>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScopeIdentityResult {
    pub identifier: ScopeId,
    pub installed: InstalledScope,
    pub standing: ScopeIdentityStanding,
    pub governance: Vec<GovernancePrincipalResult>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeIdentityStanding {
    Active,
    Contested,
    Unknown,
    Unsupported,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernancePrincipalResult {
    pub principal: String,
    pub resolution: GovernancePrincipalResolution,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernancePrincipalResolution {
    Resolved(PrincipalResolution),
    UnsupportedDidMethod,
    UnknownHistory,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalIdentityResult {
    pub principal: PrincipalId,
    pub resolution: PrincipalResolution,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrincipalResolution {
    DidKan(DidKanResolution),
    Static,
}

fn resolve_scoped_resource(
    request: &ResolutionRequest,
    projection: &MixedWorkspaceProjection,
    scope: ScopeId,
    installed: InstalledScope,
) -> Result<ResolvedResource, Error> {
    match request.resource() {
        Resource::Claim(cid) => projection
            .claims()
            .iter()
            .find(|claim| claim.claim_id() == cid)
            .cloned()
            .map(|claim| ResolvedResource::Claim(Box::new(claim)))
            .ok_or(Error::ResourceNotFoundAtSnapshot),
        Resource::Subject(selector) => {
            resolve_subject(projection, scope, selector.clone()).map(ResolvedResource::Subject)
        }
        Resource::ScopeIdentity => {
            let governance = installed
                .inception
                .governance_roots
                .iter()
                .map(|root| {
                    let resolution = match parse_principal(root) {
                        Ok(principal) => match resolve_principal(
                            &principal,
                            None,
                            projection.identity_resolutions(),
                            &installed.inception.governance_roots,
                        ) {
                            Ok(resolution) => GovernancePrincipalResolution::Resolved(resolution),
                            Err(Error::UnsupportedDidMethod) => {
                                GovernancePrincipalResolution::UnsupportedDidMethod
                            }
                            Err(Error::UnknownHistory) => {
                                GovernancePrincipalResolution::UnknownHistory
                            }
                            Err(_) => GovernancePrincipalResolution::Invalid,
                        },
                        Err(_) => GovernancePrincipalResolution::Invalid,
                    };
                    GovernancePrincipalResult {
                        principal: root.clone(),
                        resolution,
                    }
                })
                .collect::<Vec<_>>();
            let standing = scope_identity_standing(&installed, projection.identity_resolutions());
            Ok(ResolvedResource::ScopeIdentity(ScopeIdentityResult {
                identifier: scope,
                installed,
                standing,
                governance,
            }))
        }
        Resource::PrincipalIdentity(principal) => {
            let resolution = resolve_principal(
                principal,
                request.evidence().version.as_ref(),
                projection.identity_resolutions(),
                &installed.inception.governance_roots,
            )?;
            Ok(ResolvedResource::PrincipalIdentity(
                PrincipalIdentityResult {
                    principal: principal.clone(),
                    resolution,
                },
            ))
        }
        Resource::AuthorityIdentity => Err(Error::AuthorityIdentityUnknown),
    }
}

fn scope_identity_standing(
    installed: &InstalledScope,
    resolutions: &[DidKanResolution],
) -> ScopeIdentityStanding {
    let mut standing = ScopeIdentityStanding::Unknown;
    for root in &installed.inception.governance_roots {
        if root.starts_with("did:key:") {
            match installed
                .inception
                .proved_event(installed.event.proofs.clone())
            {
                Ok(event) if event == installed.event => return ScopeIdentityStanding::Active,
                Ok(_) | Err(_) => standing = ScopeIdentityStanding::Invalid,
            }
            continue;
        }
        if !root.starts_with("did:kan:") {
            if standing != ScopeIdentityStanding::Invalid {
                standing = ScopeIdentityStanding::Unsupported;
            }
            continue;
        }
        let resolution = resolutions.iter().find(|resolution| match resolution {
            DidKanResolution::Active(state) => state.did == *root,
            DidKanResolution::NonActive(state) => state.did.as_deref() == Some(root.as_str()),
        });
        match resolution {
            Some(DidKanResolution::Active(state)) => match installed
                .inception
                .proved_event_with_did_kan_state(state, installed.event.proofs.clone())
            {
                Ok(event) if event == installed.event => return ScopeIdentityStanding::Active,
                Ok(_) | Err(_) => standing = ScopeIdentityStanding::Invalid,
            },
            Some(DidKanResolution::NonActive(state)) => match state.standing {
                NonActiveIdentityStanding::Contested => standing = ScopeIdentityStanding::Contested,
                NonActiveIdentityStanding::Invalid => {
                    if standing != ScopeIdentityStanding::Contested {
                        standing = ScopeIdentityStanding::Invalid;
                    }
                }
                NonActiveIdentityStanding::Unsupported => {
                    if !matches!(
                        standing,
                        ScopeIdentityStanding::Contested | ScopeIdentityStanding::Invalid
                    ) {
                        standing = ScopeIdentityStanding::Unsupported;
                    }
                }
                NonActiveIdentityStanding::UnknownHistory => {}
            },
            None => {}
        }
    }
    standing
}

fn resolve_subject(
    projection: &MixedWorkspaceProjection,
    scope: ScopeId,
    selector: SubjectSelector,
) -> Result<SubjectResult, Error> {
    match &selector {
        SubjectSelector::Path(path) => {
            let target = ClaimSubjectId::Scoped {
                scope,
                path: path.to_string(),
            };
            let folded_view = projection.fold();
            let folded = folded_view.subject(&target).cloned();
            let folded_subjects = folded
                .as_ref()
                .map(|subject| subject.subjects.as_slice())
                .unwrap_or(std::slice::from_ref(&target));
            let evidence = projection
                .claims()
                .iter()
                .filter(|claim| {
                    claim
                        .subject_id(projection.legacy_scope())
                        .is_some_and(|subject| folded_subjects.contains(&subject))
                })
                .cloned()
                .collect::<Vec<_>>();
            let evidence = sorted_evidence(evidence);
            if evidence.is_empty() {
                return Err(Error::ResourceNotFoundAtSnapshot);
            }
            Ok(SubjectResult {
                selector,
                evidence,
                folded,
            })
        }
        SubjectSelector::PreservedV1Cid(target) => {
            let evidence = projection
                .claims()
                .iter()
                .filter(|claim| match claim.source() {
                    ClaimSource::V1(claim) => crate::cid::content_cid(&claim.content.subject)
                        .is_ok_and(|cid| &cid == target),
                    ClaimSource::Claim(_) | ClaimSource::Unsupported(_) => false,
                })
                .cloned()
                .collect::<Vec<_>>();
            let evidence = sorted_evidence(evidence);
            if evidence.is_empty() {
                return Err(Error::ResourceNotFoundAtSnapshot);
            }
            Ok(SubjectResult {
                selector,
                evidence,
                folded: None,
            })
        }
    }
}

fn sorted_evidence(mut evidence: Vec<ClaimView>) -> Vec<ClaimView> {
    evidence.sort_by(|left, right| {
        left.claim_id()
            .to_string()
            .cmp(&right.claim_id().to_string())
    });
    evidence
}

fn resolve_principal(
    principal: &PrincipalId,
    version: Option<&IdentityVersion>,
    resolutions: &[DidKanResolution],
    _static_roots: &[String],
) -> Result<PrincipalResolution, Error> {
    let did = principal.to_string();
    // `did:key` is self-certifying. Governance membership affects scope
    // admission, not whether the static identity itself can be resolved.
    if principal.method() == "key" {
        return match version {
            None | Some(IdentityVersion::Static) => Ok(PrincipalResolution::Static),
            Some(_) => Err(Error::UnknownHistory),
        };
    }
    if principal.method() != "kan" {
        return Err(Error::UnsupportedDidMethod);
    }
    let resolution = resolutions.iter().find(|resolution| match resolution {
        DidKanResolution::Active(state) => state.did == did,
        DidKanResolution::NonActive(state) => state.did.as_deref() == Some(did.as_str()),
    });
    let Some(resolution) = resolution else {
        return Err(Error::UnknownHistory);
    };
    match (version, resolution) {
        (None, resolution) => Ok(PrincipalResolution::DidKan(resolution.clone())),
        (Some(IdentityVersion::Event(requested)), DidKanResolution::Active(state))
            if requested == &state.active_event =>
        {
            Ok(PrincipalResolution::DidKan(resolution.clone()))
        }
        (Some(IdentityVersion::Event(requested)), DidKanResolution::NonActive(state))
            if state.events.iter().any(|event| event == requested) =>
        {
            Ok(PrincipalResolution::DidKan(resolution.clone()))
        }
        (Some(IdentityVersion::VersionId(_) | IdentityVersion::DocumentCid(_)), _) => {
            Err(Error::Unsupported)
        }
        (Some(IdentityVersion::Static | IdentityVersion::Event(_)), _) => {
            Err(Error::UnknownHistory)
        }
    }
}

fn parse_principal(value: &str) -> Result<PrincipalId, Error> {
    let Some(rest) = value.strip_prefix("did:") else {
        return Err(Error::Invalid);
    };
    let Some((method, identifier)) = rest.split_once(':') else {
        return Err(Error::Invalid);
    };
    let uri = format!("kan://did/{method}/{identifier}/identity");
    let request = ResolutionRequest::parse(&uri)?;
    match request.resource() {
        Resource::PrincipalIdentity(principal) => Ok(principal.clone()),
        _ => Err(Error::Invalid),
    }
}

fn validate_local_source(evidence: &EvidenceSelection) -> Result<(), Error> {
    if evidence.sources.iter().any(|source| source != "local") {
        return Err(Error::SourceNotFound);
    }
    Ok(())
}

fn require_snapshot(evidence: &EvidenceSelection, current: &Cid) -> Result<(), Error> {
    if evidence
        .snapshot
        .as_ref()
        .is_some_and(|snapshot| snapshot != &current.to_string())
    {
        return Err(Error::SnapshotUnavailable);
    }
    Ok(())
}

fn snapshot(
    workspace: Option<&Workspace>,
    system: &SystemIdentityStore,
    scope: Option<&InstalledScope>,
    mut components: Vec<(String, Vec<u8>)>,
) -> Result<Cid, Error> {
    if let Some(workspace) = workspace {
        if let Some(root) = workspace.log.current_root() {
            components.push(("log-root".to_string(), root.to_bytes()));
        }
        if let Some(root) = workspace.overlay.current_root() {
            components.push(("overlay-root".to_string(), root.to_bytes()));
        }
        if let Some(hash) = workspace.published.content_hash() {
            components.push(("accepted-git-tree".to_string(), hash.as_bytes().to_vec()));
        }
    }
    if let Some(scope) = scope {
        components.push((
            "scope-event".to_string(),
            scope.event.proved_cid()?.to_bytes(),
        ));
    }
    let ledger = IdentityLedger::at(system.config_root().join("identity").join("ledger"));
    for event in ledger.read_all()? {
        components.push(("identity-event".to_string(), event.proved_cid()?.to_bytes()));
    }
    components.sort();
    let mut bytes = b"tools.kan.local-source-snapshot.v1".to_vec();
    for (kind, value) in components {
        bytes.extend_from_slice(&(kind.len() as u64).to_be_bytes());
        bytes.extend_from_slice(kind.as_bytes());
        bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&value);
    }
    Ok(Cid::from(atproto_repo::compute_cid(&bytes)))
}

fn source_guard(
    workspace_root: Option<&Path>,
    system: &SystemIdentityStore,
) -> Result<Vec<(String, Vec<u8>)>, Error> {
    let mut components = Vec::new();
    if let Some(root) = workspace_root {
        raw_tree_components("scope", &root.join(".kan/scope"), &mut components)?;
        raw_tree_components("claims", &root.join(".claims"), &mut components)?;
    }
    raw_tree_components(
        "identity-ledger",
        &system.config_root().join("identity").join("ledger"),
        &mut components,
    )?;
    components.sort();
    Ok(components)
}

fn raw_tree_components(
    label: &str,
    root: &Path,
    components: &mut Vec<(String, Vec<u8>)>,
) -> Result<(), Error> {
    fn walk(
        label: &str,
        root: &Path,
        path: &Path,
        components: &mut Vec<(String, Vec<u8>)>,
    ) -> Result<(), Error> {
        let mut entries = std::fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let relative = path.strip_prefix(root).map_err(|_| Error::Invalid)?;
            let relative = relative.to_string_lossy();
            let kind = entry.file_type()?;
            if kind.is_dir() {
                components.push((format!("raw:{label}:dir:{relative}"), Vec::new()));
                walk(label, root, &path, components)?;
            } else if kind.is_file() {
                components.push((format!("raw:{label}:file:{relative}"), std::fs::read(path)?));
            } else if kind.is_symlink() {
                components.push((
                    format!("raw:{label}:symlink:{relative}"),
                    std::fs::read_link(path)?
                        .to_string_lossy()
                        .as_bytes()
                        .to_vec(),
                ));
            } else {
                components.push((format!("raw:{label}:other:{relative}"), Vec::new()));
            }
        }
        Ok(())
    }

    match std::fs::symlink_metadata(root) {
        Ok(metadata) if metadata.is_dir() => walk(label, root, root, components),
        Ok(_) => {
            components.push((format!("raw:{label}:non-directory"), Vec::new()));
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn result(
    request: &ResolutionRequest,
    scope: Option<ScopeId>,
    snapshot: Cid,
    substrate: &str,
    source_identity: String,
    diagnostics: Vec<String>,
    resource: ResolvedResource,
) -> ResolutionResult {
    let claim_evaluations = match &resource {
        ResolvedResource::Claim(claim) => vec![evaluation(claim)],
        ResolvedResource::Subject(subject) => subject.evidence.iter().map(evaluation).collect(),
        ResolvedResource::ScopeIdentity(_) | ResolvedResource::PrincipalIdentity(_) => Vec::new(),
    };
    let mut replay = request.clone();
    replay.evidence.snapshot = Some(snapshot.to_string());
    ResolutionResult {
        canonical_request: request.canonical_uri(),
        immutable_replay: replay.canonical_uri(),
        target: TargetKey {
            scope,
            resource: request.resource().clone(),
        },
        sources: vec![SourceResult {
            kind: "local".to_string(),
            identity: source_identity,
            substrate: substrate.to_string(),
            access: SourceAccess::Available,
            snapshot,
            completeness: SourceCompleteness::Committed,
            diagnostics: diagnostics.clone(),
        }],
        claim_evaluations,
        resource,
        diagnostics,
    }
}

fn evaluation(claim: &ClaimView) -> ClaimEvaluation {
    ClaimEvaluation {
        claim: claim.claim_id().clone(),
        judgments: claim.judgments(),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Parse(#[from] super::ParseError),
    #[error("authority-not-found")]
    AuthorityNotFound,
    #[error("authority-identity-unknown")]
    AuthorityIdentityUnknown,
    #[error("scope-not-found")]
    ScopeNotFound,
    #[error("ambiguous-scope-locator")]
    AmbiguousScopeLocator,
    #[error("source-not-found")]
    SourceNotFound,
    #[error("snapshot-unavailable")]
    SnapshotUnavailable,
    #[error("resource-not-found-at-snapshot")]
    ResourceNotFoundAtSnapshot,
    #[error("scope-identifier-mismatch")]
    ScopeIdentifierMismatch,
    #[error("unsupported-did-method")]
    UnsupportedDidMethod,
    #[error("unknown-history")]
    UnknownHistory,
    #[error("unsupported")]
    Unsupported,
    #[error("indirect Git directory workspace ownership is not defined")]
    IndirectGitDirectoryUnsupported,
    #[error("source changed during resolution")]
    SourceChangedDuringResolution,
    #[error("invalid")]
    Invalid,
    #[error(transparent)]
    Workspace(#[from] crate::workspace::Error),
    #[error(transparent)]
    Scope(#[from] crate::identity::scope_store::Error),
    #[error(transparent)]
    System(#[from] crate::identity::system::Error),
    #[error(transparent)]
    Ledger(#[from] crate::identity::ledger::Error),
    #[error(transparent)]
    Control(#[from] crate::identity::control::Error),
    #[error(transparent)]
    Cid(#[from] crate::cid::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl Error {
    pub fn code(&self) -> &str {
        match self {
            Self::Parse(error) => error.code(),
            Self::AuthorityNotFound => "authority-not-found",
            Self::AuthorityIdentityUnknown => "authority-identity-unknown",
            Self::ScopeNotFound => "scope-not-found",
            Self::AmbiguousScopeLocator => "ambiguous-scope-locator",
            Self::SourceNotFound => "source-not-found",
            Self::SnapshotUnavailable => "snapshot-unavailable",
            Self::ResourceNotFoundAtSnapshot => "resource-not-found-at-snapshot",
            Self::ScopeIdentifierMismatch => "scope-identifier-mismatch",
            Self::UnsupportedDidMethod => "unsupported-did-method",
            Self::UnknownHistory => "unknown-history",
            Self::Unsupported => "unsupported",
            Self::IndirectGitDirectoryUnsupported => "unsupported",
            Self::SourceChangedDuringResolution => "snapshot-unavailable",
            Self::Invalid => "invalid",
            Self::Workspace(_)
            | Self::Scope(_)
            | Self::System(_)
            | Self::Ledger(_)
            | Self::Control(_)
            | Self::Cid(_)
            | Self::Io(_) => "invalid",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::scope_inception::ScopeInception;

    fn scope(nonce: u8, name: &str) -> ScopeId {
        ScopeInception::new(
            [nonce; 32],
            vec![name.to_string()],
            vec!["did:key:zDnaenWDM6qp5Ra829d9wPUzBKBA3V6fm2cg4KVP3WFKqsYTv".to_string()],
            vec![],
        )
        .unwrap()
        .scope_id()
        .unwrap()
    }

    #[test]
    fn exact_locator_selection_distinguishes_missing_ambiguous_and_direct_mismatch() {
        let first = scope(0xc1, "shared:scope");
        let second = scope(0xc2, "shared:scope");
        let first_names = vec!["shared:scope".to_string()];
        let second_names = vec!["shared:scope".to_string()];
        let bindings = [
            ScopeBinding {
                scope: first,
                names: &first_names,
            },
            ScopeBinding {
                scope: second,
                names: &second_names,
            },
        ];

        let ambiguous = ResolutionRequest::parse("kan://local/shared:scope/subject/x").unwrap();
        assert_eq!(
            select_scope(ambiguous.scope().unwrap(), &bindings)
                .unwrap_err()
                .code(),
            "ambiguous-scope-locator"
        );

        let missing = ResolutionRequest::parse("kan://local/missing:scope/subject/x").unwrap();
        assert_eq!(
            select_scope(missing.scope().unwrap(), &bindings)
                .unwrap_err()
                .code(),
            "scope-not-found"
        );

        let other = scope(0xc3, "other:scope");
        let direct =
            ResolutionRequest::parse(&format!("kan://local/@id:{other}/subject/x")).unwrap();
        assert_eq!(
            select_scope(direct.scope().unwrap(), &bindings)
                .unwrap_err()
                .code(),
            "scope-identifier-mismatch"
        );
    }
}

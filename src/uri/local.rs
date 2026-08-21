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
        did_kan_update::DidKanResolution,
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
        let Some(selector) = request.scope() else {
            return Err(Error::ScopeNotFound);
        };

        let mut workspace =
            Workspace::open_resolution_read_only_with_system(self.cwd, self.system).await?;
        let projection = self.project(&mut workspace, request).await?;
        let scope_store = ScopeIdentityStore::at(workspace.root.join(".kan").join("scope"));
        let installed = scope_store.read()?.ok_or(Error::ScopeNotFound)?;
        let verified = projection.legacy_scope().ok_or(Error::Invalid)?;
        if installed.scope != verified {
            return Err(Error::Invalid);
        }
        match selector {
            ScopeSelector::Direct(requested) if *requested != verified => {
                return Err(Error::ScopeIdentifierMismatch);
            }
            ScopeSelector::Named(locator)
                if !installed
                    .inception
                    .names
                    .iter()
                    .any(|name| name == locator.as_str()) =>
            {
                return Err(Error::ScopeNotFound);
            }
            ScopeSelector::Direct(_) | ScopeSelector::Named(_) => {}
        }

        let snapshot = snapshot(Some(&workspace), self.system, Some(&installed))?;
        require_snapshot(request.evidence(), &snapshot)?;
        let resource = resolve_scoped_resource(request, &projection, verified, installed.clone())?;
        Ok(result(
            request,
            Some(verified),
            snapshot,
            "local-kan",
            verified.to_string(),
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
        let resolutions = self.system.resolve_public_identities()?;
        let resolution = resolve_principal(
            principal,
            request.evidence().version.as_ref(),
            &resolutions,
            &[],
        )?;
        let snapshot = snapshot(None, self.system, None)?;
        require_snapshot(request.evidence(), &snapshot)?;
        Ok(result(
            request,
            None,
            snapshot,
            "system-identity-ledger",
            principal.to_string(),
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
    pub governance: Vec<PrincipalIdentityResult>,
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
                    let principal = parse_principal(root)?;
                    let resolution = resolve_principal(
                        &principal,
                        None,
                        projection.identity_resolutions(),
                        &installed.inception.governance_roots,
                    )?;
                    Ok(PrincipalIdentityResult {
                        principal,
                        resolution,
                    })
                })
                .collect::<Result<Vec<_>, Error>>()?;
            Ok(ResolvedResource::ScopeIdentity(ScopeIdentityResult {
                identifier: scope,
                installed,
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
) -> Result<Cid, Error> {
    let mut components = Vec::new();
    if let Some(workspace) = workspace {
        if let Some(root) = workspace.log.current_root() {
            components.push(("log", root.to_bytes()));
        }
        if let Some(root) = workspace.overlay.current_root() {
            components.push(("overlay", root.to_bytes()));
        }
        if let Some(hash) = workspace.published.content_hash() {
            components.push(("git-tree", hash.as_bytes().to_vec()));
        }
    }
    if let Some(scope) = scope {
        components.push(("scope", scope.event.proved_cid()?.to_bytes()));
    }
    let ledger = IdentityLedger::at(system.config_root().join("identity").join("ledger"));
    for event in ledger.read_all()? {
        components.push(("identity", event.proved_cid()?.to_bytes()));
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

fn result(
    request: &ResolutionRequest,
    scope: Option<ScopeId>,
    snapshot: Cid,
    substrate: &str,
    source_identity: String,
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
            diagnostics: Vec::new(),
        }],
        claim_evaluations,
        resource,
        diagnostics: Vec::new(),
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
            Self::Invalid => "invalid",
            Self::Workspace(_)
            | Self::Scope(_)
            | Self::System(_)
            | Self::Ledger(_)
            | Self::Control(_)
            | Self::Cid(_) => "invalid",
        }
    }
}

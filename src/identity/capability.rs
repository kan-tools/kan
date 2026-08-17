//! RFC 1 repository capabilities, delegations, and revocations.

use std::collections::{BTreeSet, HashSet};

use atproto_dasl::{Cid, Ipld};
use serde::{Deserialize, Serialize};

use super::{
    control::{verify_static_did_key_proof, ControlEvent, IdentityVersion, Proof, SigningInput},
    did_kan::validate_did,
    repository_inception::validate_repository_id,
    CryptographicValidity,
};

pub const DELEGATION_DOMAIN: &str = "kan.capability.delegation.v1";
pub const DELEGATION_EVENT_TYPE: &str = "delegation";
pub const REVOCATION_DOMAIN: &str = "kan.capability.revocation.v1";
pub const REVOCATION_EVENT_TYPE: &str = "revocation";

pub const CLAIM_WRITE: &str = "claim.write";
pub const LINEAGE_ATTEST: &str = "lineage.attest";
pub const ROLE_NAME: &str = "role.name";
pub const CAPABILITY_DELEGATE: &str = "capability.delegate";
pub const CAPABILITY_REVOKE: &str = "capability.revoke";
pub const GOVERNANCE_UPDATE: &str = "governance.update";

const V1_OPERATIONS: [&str; 6] = [
    CAPABILITY_DELEGATE,
    CAPABILITY_REVOKE,
    CLAIM_WRITE,
    GOVERNANCE_UPDATE,
    LINEAGE_ATTEST,
    ROLE_NAME,
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Capability {
    repository: String,
    subject_prefix: Option<String>,
    operations: Vec<String>,
    not_before: Option<i64>,
    not_after: Option<i64>,
    delegable: bool,
}

impl Capability {
    pub fn new(
        repository: String,
        subject_prefix: Option<String>,
        mut operations: Vec<String>,
        not_before: Option<i64>,
        not_after: Option<i64>,
        delegable: bool,
    ) -> Result<Self, Error> {
        reject_duplicates(&operations, "operations")?;
        operations.sort();
        let capability = Self {
            repository,
            subject_prefix,
            operations,
            not_before,
            not_after,
            delegable,
        };
        capability.validate_supported()?;
        Ok(capability)
    }

    pub fn validate(&self) -> Result<(), Error> {
        validate_repository_id(&self.repository)?;
        validate_sorted_unique(&self.operations, "operations")?;
        if self
            .not_before
            .zip(self.not_after)
            .is_some_and(|(start, end)| start > end)
        {
            return Err(Error::TimeRange);
        }
        Ok(())
    }

    pub fn validate_supported(&self) -> Result<(), Error> {
        self.validate()?;
        if let Some(operation) = self
            .operations
            .iter()
            .find(|operation| !V1_OPERATIONS.contains(&operation.as_str()))
        {
            return Err(Error::UnsupportedOperation(operation.clone()));
        }
        Ok(())
    }

    pub fn repository(&self) -> &str {
        &self.repository
    }

    pub fn subject_prefix(&self) -> Option<&str> {
        self.subject_prefix.as_deref()
    }

    pub fn operations(&self) -> &[String] {
        &self.operations
    }

    pub fn not_before(&self) -> Option<i64> {
        self.not_before
    }

    pub fn not_after(&self) -> Option<i64> {
        self.not_after
    }

    pub fn delegable(&self) -> bool {
        self.delegable
    }

    pub fn covers(&self, operation: &str, subject: &str, instant: Option<i64>) -> Coverage {
        if !self
            .operations
            .iter()
            .any(|candidate| candidate == operation)
        {
            return Coverage::No;
        }
        if !subject_is_covered(self.subject_prefix.as_deref(), subject) {
            return Coverage::No;
        }
        if self.not_before.is_some() || self.not_after.is_some() {
            let Some(instant) = instant else {
                return Coverage::UnknownTime;
            };
            if self.not_before.is_some_and(|start| instant < start)
                || self.not_after.is_some_and(|end| instant > end)
            {
                return Coverage::No;
            }
        }
        Coverage::Yes
    }

    pub fn attenuates(&self, parent: &Self) -> Result<(), Error> {
        self.validate_supported()?;
        parent.validate_supported()?;
        if !parent.delegable {
            return Err(Error::ParentNotDelegable);
        }
        if self.repository != parent.repository {
            return Err(Error::RepositoryMismatch);
        }
        if !prefix_is_subset(
            self.subject_prefix.as_deref(),
            parent.subject_prefix.as_deref(),
        ) {
            return Err(Error::SubjectAmplification);
        }
        if self
            .operations
            .iter()
            .any(|operation| parent.operations.binary_search(operation).is_err())
        {
            return Err(Error::OperationAmplification);
        }
        if parent
            .not_before
            .is_some_and(|parent_start| self.not_before.is_none_or(|start| start < parent_start))
            || parent
                .not_after
                .is_some_and(|parent_end| self.not_after.is_none_or(|end| end > parent_end))
        {
            return Err(Error::TimeAmplification);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coverage {
    Yes,
    No,
    UnknownTime,
}

/// The active governance facts required to evaluate root-derived capability
/// heads without allowing a historical governance event to select old roots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceAuthority {
    pub repository: String,
    pub active_event: Cid,
    pub governance_roots: Vec<String>,
    pub ancestors: HashSet<Cid>,
}

impl GovernanceAuthority {
    pub fn new(
        repository: String,
        active_event: Cid,
        mut governance_roots: Vec<String>,
        mut ancestors: HashSet<Cid>,
    ) -> Result<Self, Error> {
        validate_repository_id(&repository)?;
        reject_duplicates(&governance_roots, "governanceRoots")?;
        governance_roots.sort();
        for root in &governance_roots {
            validate_did(root)?;
        }
        ancestors.insert(active_event.clone());
        Ok(Self {
            repository,
            active_event,
            governance_roots,
            ancestors,
        })
    }

    pub fn from_active(
        repository: String,
        active: &super::governance::ActiveGovernance,
    ) -> Result<Self, Error> {
        Self::new(
            repository,
            active.active_event.clone(),
            active.governance_roots.clone(),
            active.ancestral_events().iter().cloned().collect(),
        )
    }

    fn recognizes(&self, event: &Cid) -> bool {
        self.ancestors.contains(event)
    }

    fn is_root(&self, principal: &str) -> bool {
        self.governance_roots
            .binary_search_by(|root| root.as_str().cmp(principal))
            .is_ok()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Delegation {
    v: u64,
    repository: String,
    grantor: String,
    grantor_identity_version: IdentityVersion,
    governance_event: Cid,
    delegate: String,
    parent: Option<Cid>,
    capability: Capability,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationState {
    pub event: Cid,
    pub repository: String,
    pub grantor: String,
    pub governance_event: Cid,
    pub delegate: String,
    pub parent: Option<Cid>,
    pub capability: Capability,
}

impl Delegation {
    pub fn root(
        governance: &GovernanceAuthority,
        grantor: String,
        grantor_identity_version: IdentityVersion,
        governance_event: Cid,
        delegate: String,
        capability: Capability,
    ) -> Result<Self, Error> {
        if !governance.is_root(&grantor) {
            return Err(Error::GrantorNotRoot);
        }
        let delegation = Self::new(
            grantor,
            grantor_identity_version,
            governance_event,
            delegate,
            None,
            capability,
        )?;
        delegation.validate_governance(governance)?;
        Ok(delegation)
    }

    pub fn child(
        governance: &GovernanceAuthority,
        parent: &DelegationState,
        grantor_identity_version: IdentityVersion,
        delegate: String,
        capability: Capability,
    ) -> Result<Self, Error> {
        capability.attenuates(&parent.capability)?;
        let delegation = Self::new(
            parent.delegate.clone(),
            grantor_identity_version,
            parent.governance_event.clone(),
            delegate,
            Some(parent.event.clone()),
            capability,
        )?;
        delegation.validate_governance(governance)?;
        Ok(delegation)
    }

    fn new(
        grantor: String,
        grantor_identity_version: IdentityVersion,
        governance_event: Cid,
        delegate: String,
        parent: Option<Cid>,
        capability: Capability,
    ) -> Result<Self, Error> {
        let delegation = Self {
            v: 1,
            repository: capability.repository.clone(),
            grantor,
            grantor_identity_version,
            governance_event,
            delegate,
            parent,
            capability,
        };
        delegation.validate_structure()?;
        Ok(delegation)
    }

    pub fn validate_structure(&self) -> Result<(), Error> {
        if self.v != 1 {
            return Err(Error::UnsupportedVersion(self.v));
        }
        validate_repository_id(&self.repository)?;
        validate_did(&self.grantor)?;
        validate_did(&self.delegate)?;
        self.capability.validate_supported()?;
        if self.capability.repository != self.repository {
            return Err(Error::RepositoryMismatch);
        }
        Ok(())
    }

    pub fn validate_governance(&self, governance: &GovernanceAuthority) -> Result<(), Error> {
        if self.repository != governance.repository {
            return Err(Error::RepositoryMismatch);
        }
        if !governance.recognizes(&self.governance_event) {
            return Err(Error::GovernanceNotAncestral);
        }
        if self.parent.is_none() && !governance.is_root(&self.grantor) {
            return Err(Error::GrantorNotRoot);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate_structure()?;
        Ok(atproto_dasl::to_vec(self)?)
    }

    pub fn signing_input(&self) -> Result<SigningInput, Error> {
        let payload: Ipld = atproto_dasl::from_reader(&self.canonical_bytes()?[..])?;
        Ok(SigningInput::new(
            DELEGATION_DOMAIN,
            DELEGATION_EVENT_TYPE,
            payload,
        )?)
    }

    pub fn proved_event(&self, proofs: Vec<Proof>) -> Result<ControlEvent, Error> {
        let input = self.signing_input()?;
        authorize_principal(
            &input,
            &proofs,
            &self.grantor,
            &self.grantor_identity_version,
        )?;
        Ok(ControlEvent::new(input, proofs)?)
    }

    pub fn state(&self) -> Result<DelegationState, Error> {
        Ok(DelegationState {
            event: self.signing_input()?.logical_cid()?,
            repository: self.repository.clone(),
            grantor: self.grantor.clone(),
            governance_event: self.governance_event.clone(),
            delegate: self.delegate.clone(),
            parent: self.parent.clone(),
            capability: self.capability.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Revocation {
    v: u64,
    repository: String,
    delegation: Cid,
    revoker: String,
    revoker_identity_version: IdentityVersion,
    governance_event: Cid,
    effective_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationState {
    pub event: Cid,
    pub repository: String,
    pub delegation: Cid,
    pub revoker: String,
    pub governance_event: Cid,
    pub effective_at: Option<i64>,
}

impl Revocation {
    pub fn new(
        governance: &GovernanceAuthority,
        delegation: &DelegationState,
        revoker: String,
        revoker_identity_version: IdentityVersion,
        governance_event: Cid,
        effective_at: Option<i64>,
    ) -> Result<Self, Error> {
        if revoker != delegation.grantor && !governance.is_root(&revoker) {
            return Err(Error::RevokerNotAuthorized);
        }
        let revocation = Self {
            v: 1,
            repository: delegation.repository.clone(),
            delegation: delegation.event.clone(),
            revoker,
            revoker_identity_version,
            governance_event,
            effective_at,
        };
        revocation.validate_against(governance, delegation)?;
        Ok(revocation)
    }

    pub fn validate_structure(&self) -> Result<(), Error> {
        if self.v != 1 {
            return Err(Error::UnsupportedVersion(self.v));
        }
        validate_repository_id(&self.repository)?;
        validate_did(&self.revoker)?;
        Ok(())
    }

    pub fn validate_against(
        &self,
        governance: &GovernanceAuthority,
        delegation: &DelegationState,
    ) -> Result<(), Error> {
        self.validate_structure()?;
        if self.repository != governance.repository {
            return Err(Error::RepositoryMismatch);
        }
        if self.repository != delegation.repository || self.delegation != delegation.event {
            return Err(Error::DelegationMismatch);
        }
        if !governance.recognizes(&self.governance_event) {
            return Err(Error::GovernanceNotAncestral);
        }
        if self.revoker != delegation.grantor && !governance.is_root(&self.revoker) {
            return Err(Error::RevokerNotAuthorized);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate_structure()?;
        Ok(atproto_dasl::to_vec(self)?)
    }

    pub fn signing_input(&self) -> Result<SigningInput, Error> {
        let payload: Ipld = atproto_dasl::from_reader(&self.canonical_bytes()?[..])?;
        Ok(SigningInput::new(
            REVOCATION_DOMAIN,
            REVOCATION_EVENT_TYPE,
            payload,
        )?)
    }

    pub fn proved_event(
        &self,
        governance: &GovernanceAuthority,
        delegation: &DelegationState,
        proofs: Vec<Proof>,
    ) -> Result<ControlEvent, Error> {
        self.validate_against(governance, delegation)?;
        let input = self.signing_input()?;
        authorize_principal(
            &input,
            &proofs,
            &self.revoker,
            &self.revoker_identity_version,
        )?;
        Ok(ControlEvent::new(input, proofs)?)
    }

    pub fn state(&self) -> Result<RevocationState, Error> {
        Ok(RevocationState {
            event: self.signing_input()?.logical_cid()?,
            repository: self.repository.clone(),
            delegation: self.delegation.clone(),
            revoker: self.revoker.clone(),
            governance_event: self.governance_event.clone(),
            effective_at: self.effective_at,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityPathEvaluation {
    pub trusted_time: super::TrustedTime,
    pub revocation: super::RevocationStanding,
    pub capability: super::CapabilityEvidence,
}

/// Evaluate one explicitly named delegation head. Inputs are recognized
/// delegation/revocation states whose envelope, proof, identity standing, and
/// repository admission were established by their respective resolvers.
pub fn evaluate_path(
    governance: &GovernanceAuthority,
    head: &Cid,
    delegations: &[DelegationState],
    revocations: &[RevocationState],
    operation: &str,
    subject: &str,
    evaluation_instant: Option<i64>,
) -> CapabilityPathEvaluation {
    let by_id: std::collections::HashMap<&Cid, &DelegationState> = delegations
        .iter()
        .map(|state| (&state.event, state))
        .collect();
    let Some(head_state) = by_id.get(head).copied() else {
        return CapabilityPathEvaluation {
            trusted_time: super::TrustedTime::NotRequired,
            revocation: super::RevocationStanding::Clear,
            capability: super::CapabilityEvidence::Missing,
        };
    };
    if head_state.repository != governance.repository
        || !governance.recognizes(&head_state.governance_event)
    {
        return no_covering_path();
    }

    let mut path = vec![head_state];
    let mut seen = HashSet::from([head_state.event.clone()]);
    let mut current = head_state;
    while let Some(parent_id) = &current.parent {
        let Some(parent) = by_id.get(parent_id).copied() else {
            return CapabilityPathEvaluation {
                trusted_time: super::TrustedTime::NotRequired,
                revocation: super::RevocationStanding::Clear,
                capability: super::CapabilityEvidence::Missing,
            };
        };
        if !seen.insert(parent.event.clone()) {
            return no_covering_path();
        }
        if current.grantor != parent.delegate
            || current.governance_event != parent.governance_event
            || current.capability.attenuates(&parent.capability).is_err()
        {
            return no_covering_path();
        }
        path.push(parent);
        current = parent;
    }
    if !governance.is_root(&current.grantor) || !governance.recognizes(&current.governance_event) {
        return no_covering_path();
    }

    for revocation in revocations {
        if revocation.repository != governance.repository
            || !governance.recognizes(&revocation.governance_event)
            || !path
                .iter()
                .any(|delegation| delegation.event == revocation.delegation)
        {
            continue;
        }
        match (revocation.effective_at, evaluation_instant) {
            (Some(_), None) => {
                return CapabilityPathEvaluation {
                    trusted_time: super::TrustedTime::Unavailable,
                    revocation: super::RevocationStanding::Unknown,
                    capability: super::CapabilityEvidence::CompleteWithCoveringPath,
                };
            }
            (Some(boundary), Some(instant)) if instant < boundary => {}
            (None, _) | (Some(_), Some(_)) => return no_covering_path(),
        }
    }

    match head_state
        .capability
        .covers(operation, subject, evaluation_instant)
    {
        Coverage::No => return no_covering_path(),
        Coverage::UnknownTime => {
            return CapabilityPathEvaluation {
                trusted_time: super::TrustedTime::Unavailable,
                revocation: super::RevocationStanding::Clear,
                capability: super::CapabilityEvidence::CompleteWithCoveringPath,
            };
        }
        Coverage::Yes => {}
    }

    CapabilityPathEvaluation {
        trusted_time: if head_state.capability.not_before.is_some()
            || head_state.capability.not_after.is_some()
        {
            super::TrustedTime::Available
        } else {
            super::TrustedTime::NotRequired
        },
        revocation: super::RevocationStanding::Clear,
        capability: super::CapabilityEvidence::CompleteWithCoveringPath,
    }
}

fn no_covering_path() -> CapabilityPathEvaluation {
    CapabilityPathEvaluation {
        trusted_time: super::TrustedTime::NotRequired,
        revocation: super::RevocationStanding::Clear,
        capability: super::CapabilityEvidence::CompleteWithoutCoveringPath,
    }
}

fn authorize_principal(
    input: &SigningInput,
    proofs: &[Proof],
    principal: &str,
    version: &IdentityVersion,
) -> Result<(), Error> {
    if !principal.starts_with("did:key:") {
        return Err(Error::UnsupportedController(principal.to_string()));
    }
    if version != &IdentityVersion::Static {
        return Err(Error::IdentityVersionMismatch);
    }
    let mut unsupported = false;
    for proof in proofs {
        let controller = proof.method.split_once('#').map(|(did, _)| did);
        if controller != Some(principal) || &proof.controller_state != version {
            continue;
        }
        match verify_static_did_key_proof(input, proof) {
            CryptographicValidity::Valid => return Ok(()),
            CryptographicValidity::Unsupported | CryptographicValidity::Unknown => {
                unsupported = true;
            }
            CryptographicValidity::Invalid => {}
        }
    }
    if unsupported {
        Err(Error::UnsupportedAuthorization)
    } else {
        Err(Error::NoAuthorization)
    }
}

fn subject_is_covered(prefix: Option<&str>, subject: &str) -> bool {
    match prefix {
        None => true,
        Some("") => subject.is_empty(),
        Some(prefix) => {
            subject == prefix
                || subject
                    .strip_prefix(prefix)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        }
    }
}

fn prefix_is_subset(child: Option<&str>, parent: Option<&str>) -> bool {
    match (child, parent) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some(child), Some(parent)) => subject_is_covered(Some(parent), child),
    }
}

fn validate_sorted_unique<T: Ord>(values: &[T], field: &'static str) -> Result<(), Error> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(Error::NotSortedUnique(field));
    }
    Ok(())
}

fn reject_duplicates<T: Ord + Clone>(values: &[T], field: &'static str) -> Result<(), Error> {
    let mut seen = BTreeSet::new();
    if values.iter().any(|value| !seen.insert(value.clone())) {
        return Err(Error::Duplicate(field));
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unsupported capability event version {0}")]
    UnsupportedVersion(u64),
    #[error("{0} must be sorted and duplicate-free")]
    NotSortedUnique(&'static str),
    #[error("{0} contains a duplicate")]
    Duplicate(&'static str),
    #[error("unsupported repository operation: {0}")]
    UnsupportedOperation(String),
    #[error("capability notBefore must not be after notAfter")]
    TimeRange,
    #[error("parent capability does not permit delegation")]
    ParentNotDelegable,
    #[error("capability repository amplification")]
    RepositoryMismatch,
    #[error("capability subject-prefix amplification")]
    SubjectAmplification,
    #[error("capability operation amplification")]
    OperationAmplification,
    #[error("capability time-range amplification")]
    TimeAmplification,
    #[error("root delegation grantor is not a current governance root")]
    GrantorNotRoot,
    #[error("governance event is not ancestral to the active governance leaf")]
    GovernanceNotAncestral,
    #[error("revoker is neither the original grantor nor a current governance root")]
    RevokerNotAuthorized,
    #[error("revocation does not name the supplied delegation")]
    DelegationMismatch,
    #[error("supported authorization requires static did:key")]
    IdentityVersionMismatch,
    #[error("unsupported controller: {0}")]
    UnsupportedController(String),
    #[error("capability event has no authorized proof")]
    NoAuthorization,
    #[error("capability event authorization is unsupported")]
    UnsupportedAuthorization,
    #[error(transparent)]
    Identity(#[from] super::did_kan::Error),
    #[error(transparent)]
    Inception(#[from] super::repository_inception::Error),
    #[error(transparent)]
    Control(#[from] super::control::Error),
    #[error(transparent)]
    Encode(#[from] atproto_dasl::EncodeError),
    #[error(transparent)]
    Decode(#[from] atproto_dasl::DecodeError),
}

//! RFC 1 scope capabilities, delegations, and revocations.

use std::{
    cmp::Ordering,
    collections::{BTreeSet, HashMap, HashSet},
};

use atproto_dasl::{Cid, Ipld};
use serde::{Deserialize, Serialize};

use super::{
    control::{
        verify_static_did_key_proof, ControlEvent, IdentityVersion, PreservedControlEvent, Proof,
        SigningInput,
    },
    did_kan::validate_did,
    scope_inception::ScopeId,
    CryptographicValidity,
};

pub const DELEGATION_DOMAIN: &str = "tools.kan.capability.delegation.v1";
pub const DELEGATION_EVENT_TYPE: &str = "delegation";
pub const REVOCATION_DOMAIN: &str = "tools.kan.capability.revocation.v1";
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
    scope: ScopeId,
    subject_prefix: Option<String>,
    operations: Vec<String>,
    not_before: Option<i64>,
    not_after: Option<i64>,
    delegable: bool,
}

impl Capability {
    pub fn new(
        scope: ScopeId,
        subject_prefix: Option<String>,
        mut operations: Vec<String>,
        not_before: Option<i64>,
        not_after: Option<i64>,
        delegable: bool,
    ) -> Result<Self, Error> {
        reject_duplicates(&operations, "operations")?;
        operations.sort();
        let capability = Self {
            scope,
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

    pub fn scope(&self) -> ScopeId {
        self.scope
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
        if self.scope != parent.scope {
            return Err(Error::ScopeMismatch);
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
    pub scope: ScopeId,
    pub active_event: Cid,
    pub governance_roots: Vec<String>,
    pub ancestors: HashSet<Cid>,
}

impl GovernanceAuthority {
    pub fn new(
        scope: ScopeId,
        active_event: Cid,
        mut governance_roots: Vec<String>,
        mut ancestors: HashSet<Cid>,
    ) -> Result<Self, Error> {
        reject_duplicates(&governance_roots, "governanceRoots")?;
        governance_roots.sort();
        for root in &governance_roots {
            validate_did(root)?;
        }
        ancestors.insert(active_event.clone());
        Ok(Self {
            scope,
            active_event,
            governance_roots,
            ancestors,
        })
    }

    pub fn from_active(
        scope: ScopeId,
        active: &super::governance::ActiveGovernance,
    ) -> Result<Self, Error> {
        Self::new(
            scope,
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
    scope: ScopeId,
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
    pub scope: ScopeId,
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
            scope: capability.scope,
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
        validate_did(&self.grantor)?;
        validate_did(&self.delegate)?;
        self.capability.validate_supported()?;
        if self.capability.scope != self.scope {
            return Err(Error::ScopeMismatch);
        }
        Ok(())
    }

    pub fn validate_governance(&self, governance: &GovernanceAuthority) -> Result<(), Error> {
        if self.scope != governance.scope {
            return Err(Error::ScopeMismatch);
        }
        if !governance.recognizes(&self.governance_event) {
            return Err(Error::GovernanceNotAncestral);
        }
        if self.parent.is_none() && !governance.is_root(&self.grantor) {
            return Err(Error::GrantorNotRoot);
        }
        Ok(())
    }

    fn validate_parent(&self, parent: &DelegationState) -> Result<(), Error> {
        if self.parent.as_ref() != Some(&parent.event) {
            return Err(Error::DelegationMismatch);
        }
        if self.grantor != parent.delegate || self.governance_event != parent.governance_event {
            return Err(Error::ParentMismatch);
        }
        self.capability.attenuates(&parent.capability)
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
            scope: self.scope,
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
    scope: ScopeId,
    delegation: Cid,
    revoker: String,
    revoker_identity_version: IdentityVersion,
    governance_event: Cid,
    effective_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationState {
    pub event: Cid,
    pub scope: ScopeId,
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
            scope: delegation.scope,
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
        validate_did(&self.revoker)?;
        Ok(())
    }

    pub fn validate_against(
        &self,
        governance: &GovernanceAuthority,
        delegation: &DelegationState,
    ) -> Result<(), Error> {
        self.validate_structure()?;
        if self.scope != governance.scope {
            return Err(Error::ScopeMismatch);
        }
        if self.scope != delegation.scope || self.delegation != delegation.event {
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
            scope: self.scope,
            delegation: self.delegation.clone(),
            revoker: self.revoker.clone(),
            governance_event: self.governance_event.clone(),
            effective_at: self.effective_at,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityResolution {
    pub delegations: Vec<DelegationState>,
    pub revocations: Vec<RevocationState>,
    pub orphans: Vec<Cid>,
    pub missing_references: Vec<Cid>,
    pub unsupported: Vec<Cid>,
    pub invalid: Vec<Cid>,
    pub diagnostics: Vec<String>,
}

impl CapabilityResolution {
    pub fn evaluate(
        &self,
        governance: &GovernanceAuthority,
        head: &Cid,
        operation: &str,
        subject: &str,
        evaluation_instant: Option<i64>,
    ) -> CapabilityPathEvaluation {
        evaluate_path(
            governance,
            head,
            &self.delegations,
            &self.revocations,
            operation,
            subject,
            evaluation_instant,
        )
    }
}

/// Resolve capability control events without consulting observation order,
/// timestamps, proof count, or external state. Proof variants sharing a
/// logical identifier contribute authorization evidence to the same event.
pub fn resolve(
    governance: &GovernanceAuthority,
    candidates: &[ControlEvent],
) -> CapabilityResolution {
    let mut diagnostics = BTreeSet::new();
    let mut orphans = HashSet::new();
    let mut unsupported = HashSet::new();
    let mut invalid = HashSet::new();
    let mut evidence_ids = HashSet::new();
    let mut invalid_envelope_ids = HashSet::new();
    let mut groups: HashMap<Cid, CandidateGroup> = HashMap::new();

    for event in candidates {
        let Ok(cid) = event.logical_cid() else {
            diagnostics.insert("candidate has an invalid signing input".to_string());
            continue;
        };
        evidence_ids.insert(cid.clone());
        if let Err(error) = event.validate() {
            diagnostics.insert(format!("{cid}: invalid control envelope: {error}"));
            invalid_envelope_ids.insert(cid);
            continue;
        }
        groups
            .entry(cid)
            .and_modify(|group| group.proofs.extend(event.proofs.clone()))
            .or_insert_with(|| CandidateGroup {
                input: event.signing_input(),
                proofs: event.proofs.clone(),
                decoded: decode_payload(event),
            });
    }
    for cid in invalid_envelope_ids {
        if !groups.contains_key(&cid) {
            orphans.insert(cid.clone());
            invalid.insert(cid);
        }
    }

    let mut delegations = HashMap::new();
    let mut pending: HashSet<Cid> = groups
        .iter()
        .filter_map(|(cid, group)| {
            matches!(group.decoded, DecodedPayload::Delegation(_)).then_some(cid.clone())
        })
        .collect();

    classify_non_delegations(
        &groups,
        &mut orphans,
        &mut unsupported,
        &mut invalid,
        &mut diagnostics,
    );

    loop {
        let mut progressed = false;
        for cid in sorted_cids(pending.clone()) {
            let group = &groups[&cid];
            let DecodedPayload::Delegation(delegation) = &group.decoded else {
                unreachable!();
            };
            let parent = match &delegation.parent {
                Some(parent) => {
                    let Some(parent) = delegations.get(parent) else {
                        continue;
                    };
                    Some(parent)
                }
                None => None,
            };
            let result = delegation
                .validate_structure()
                .and_then(|()| delegation.validate_governance(governance))
                .and_then(|()| match parent {
                    Some(parent) => delegation.validate_parent(parent),
                    None => Ok(()),
                })
                .and_then(|()| {
                    authorize_principal(
                        &group.input,
                        &group.proofs,
                        &delegation.grantor,
                        &delegation.grantor_identity_version,
                    )
                });
            match result {
                Ok(()) => {
                    let mut state = delegation
                        .state()
                        .expect("validated delegation has a state");
                    state.event = cid.clone();
                    delegations.insert(cid.clone(), state);
                }
                Err(error) => classify_error(
                    &cid,
                    error,
                    &mut orphans,
                    &mut unsupported,
                    &mut invalid,
                    &mut diagnostics,
                ),
            }
            pending.remove(&cid);
            progressed = true;
        }
        if !progressed {
            break;
        }
    }

    let mut missing_references = HashSet::new();
    for cid in pending {
        orphans.insert(cid.clone());
        let DecodedPayload::Delegation(delegation) = &groups[&cid].decoded else {
            unreachable!();
        };
        if let Some(parent) = &delegation.parent {
            if !evidence_ids.contains(parent) {
                missing_references.insert(parent.clone());
                diagnostics.insert(format!("{cid}: missing delegation parent {parent}"));
            } else {
                invalid.insert(cid.clone());
                diagnostics.insert(format!("{cid}: delegation parent is not recognized"));
            }
        }
    }

    let mut revocations = HashMap::new();
    for cid in sorted_cids(groups.keys().cloned().collect()) {
        let group = &groups[&cid];
        let DecodedPayload::Revocation(revocation) = &group.decoded else {
            continue;
        };
        let Some(target) = delegations.get(&revocation.delegation) else {
            orphans.insert(cid.clone());
            if !evidence_ids.contains(&revocation.delegation) {
                missing_references.insert(revocation.delegation.clone());
                diagnostics.insert(format!(
                    "{cid}: missing revoked delegation {}",
                    revocation.delegation
                ));
            } else {
                invalid.insert(cid.clone());
                diagnostics.insert(format!("{cid}: revoked delegation is not recognized"));
            }
            continue;
        };
        let result = revocation
            .validate_against(governance, target)
            .and_then(|()| {
                authorize_principal(
                    &group.input,
                    &group.proofs,
                    &revocation.revoker,
                    &revocation.revoker_identity_version,
                )
            });
        match result {
            Ok(()) => {
                let mut state = revocation
                    .state()
                    .expect("validated revocation has a state");
                state.event = cid.clone();
                revocations.insert(cid, state);
            }
            Err(error) => classify_error(
                &cid,
                error,
                &mut orphans,
                &mut unsupported,
                &mut invalid,
                &mut diagnostics,
            ),
        }
    }

    CapabilityResolution {
        delegations: sorted_states(delegations),
        revocations: sorted_states(revocations),
        orphans: sorted_cids(orphans),
        missing_references: sorted_cids(missing_references),
        unsupported: sorted_cids(unsupported),
        invalid: sorted_cids(invalid),
        diagnostics: diagnostics.into_iter().collect(),
    }
}

/// Resolve events received through the lossless control-event boundary.
/// Additive envelope/proof fields remain addressed by their original logical
/// identifiers and are disclosed as unsupported instead of being narrowed.
pub fn resolve_preserved(
    governance: &GovernanceAuthority,
    candidates: &[PreservedControlEvent],
) -> CapabilityResolution {
    let mut typed = Vec::new();
    let mut preserved_unsupported = Vec::new();
    for event in candidates {
        if event.unsupported_fields().is_empty() {
            if let Some(event) = event.typed() {
                typed.push(event);
                continue;
            }
        }
        if let Ok(cid) = event.logical_cid() {
            preserved_unsupported.push((cid, event.unsupported_fields().to_vec()));
        }
    }
    let mut resolution = resolve(governance, &typed);
    let mut orphans: HashSet<Cid> = resolution.orphans.into_iter().collect();
    let mut unsupported: HashSet<Cid> = resolution.unsupported.into_iter().collect();
    let mut diagnostics: BTreeSet<String> = resolution.diagnostics.into_iter().collect();
    for (cid, fields) in preserved_unsupported {
        orphans.insert(cid.clone());
        unsupported.insert(cid.clone());
        diagnostics.insert(format!(
            "{cid}: unsupported preserved control fields {}",
            fields.join(", ")
        ));
    }
    resolution.orphans = sorted_cids(orphans);
    resolution.unsupported = sorted_cids(unsupported);
    resolution.diagnostics = diagnostics.into_iter().collect();
    resolution
}

#[derive(Debug, Clone)]
struct CandidateGroup {
    input: SigningInput,
    proofs: Vec<Proof>,
    decoded: DecodedPayload,
}

#[derive(Debug, Clone)]
enum DecodedPayload {
    Delegation(Delegation),
    Revocation(Revocation),
    Unsupported(String),
    Invalid(String),
}

fn decode_payload(event: &ControlEvent) -> DecodedPayload {
    let (known, kind) = match (event.domain.as_str(), event.event_type.as_str()) {
        (DELEGATION_DOMAIN, DELEGATION_EVENT_TYPE) => (
            &[
                "v",
                "scope",
                "grantor",
                "grantorIdentityVersion",
                "governanceEvent",
                "delegate",
                "parent",
                "capability",
            ][..],
            DELEGATION_EVENT_TYPE,
        ),
        (REVOCATION_DOMAIN, REVOCATION_EVENT_TYPE) => (
            &[
                "v",
                "scope",
                "delegation",
                "revoker",
                "revokerIdentityVersion",
                "governanceEvent",
                "effectiveAt",
            ][..],
            REVOCATION_EVENT_TYPE,
        ),
        _ => {
            return DecodedPayload::Invalid(
                "wrong capability event domain or event type".to_string(),
            )
        }
    };
    let Ipld::Map(fields) = &event.payload else {
        return DecodedPayload::Invalid("capability payload is not a map".to_string());
    };
    let unknown: Vec<&str> = fields
        .keys()
        .filter(|field| !known.contains(&field.as_str()))
        .map(String::as_str)
        .collect();
    if !unknown.is_empty() {
        return DecodedPayload::Unsupported(format!(
            "unsupported {kind} fields {}",
            unknown.join(", ")
        ));
    }
    if kind == DELEGATION_EVENT_TYPE {
        let Some(Ipld::Map(capability)) = fields.get("capability") else {
            return DecodedPayload::Invalid("capability is not a map".to_string());
        };
        let known_capability = [
            "scope",
            "subjectPrefix",
            "operations",
            "notBefore",
            "notAfter",
            "delegable",
        ];
        let unknown_capability: Vec<&str> = capability
            .keys()
            .filter(|field| !known_capability.contains(&field.as_str()))
            .map(String::as_str)
            .collect();
        if !unknown_capability.is_empty() {
            return DecodedPayload::Unsupported(format!(
                "unsupported capability fields {}",
                unknown_capability.join(", ")
            ));
        }
    }
    match fields.get("v") {
        Some(Ipld::Integer(1)) => {}
        Some(Ipld::Integer(version)) => {
            return DecodedPayload::Unsupported(format!("unsupported version {version}"))
        }
        _ => return DecodedPayload::Invalid("v is not an integer".to_string()),
    }
    let bytes = match atproto_dasl::to_vec(&event.payload) {
        Ok(bytes) => bytes,
        Err(error) => return DecodedPayload::Invalid(error.to_string()),
    };
    if kind == DELEGATION_EVENT_TYPE {
        let decoded: Delegation = match atproto_dasl::from_reader(&bytes[..]) {
            Ok(decoded) => decoded,
            Err(error) => return DecodedPayload::Invalid(error.to_string()),
        };
        match decoded.validate_structure() {
            Ok(()) => DecodedPayload::Delegation(decoded),
            Err(Error::UnsupportedVersion(_) | Error::UnsupportedOperation(_)) => {
                DecodedPayload::Unsupported("unsupported delegation semantics".to_string())
            }
            Err(error) => DecodedPayload::Invalid(error.to_string()),
        }
    } else {
        let decoded: Revocation = match atproto_dasl::from_reader(&bytes[..]) {
            Ok(decoded) => decoded,
            Err(error) => return DecodedPayload::Invalid(error.to_string()),
        };
        match decoded.validate_structure() {
            Ok(()) => DecodedPayload::Revocation(decoded),
            Err(Error::UnsupportedVersion(_)) => {
                DecodedPayload::Unsupported("unsupported revocation semantics".to_string())
            }
            Err(error) => DecodedPayload::Invalid(error.to_string()),
        }
    }
}

fn classify_non_delegations(
    groups: &HashMap<Cid, CandidateGroup>,
    orphans: &mut HashSet<Cid>,
    unsupported: &mut HashSet<Cid>,
    invalid: &mut HashSet<Cid>,
    diagnostics: &mut BTreeSet<String>,
) {
    for (cid, group) in groups {
        match &group.decoded {
            DecodedPayload::Unsupported(reason) => {
                orphans.insert(cid.clone());
                unsupported.insert(cid.clone());
                diagnostics.insert(format!("{cid}: {reason}"));
            }
            DecodedPayload::Invalid(reason) => {
                orphans.insert(cid.clone());
                invalid.insert(cid.clone());
                diagnostics.insert(format!("{cid}: {reason}"));
            }
            DecodedPayload::Delegation(_) | DecodedPayload::Revocation(_) => {}
        }
    }
}

fn classify_error(
    cid: &Cid,
    error: Error,
    orphans: &mut HashSet<Cid>,
    unsupported: &mut HashSet<Cid>,
    invalid: &mut HashSet<Cid>,
    diagnostics: &mut BTreeSet<String>,
) {
    if matches!(
        error,
        Error::UnsupportedVersion(_)
            | Error::UnsupportedOperation(_)
            | Error::UnsupportedController(_)
            | Error::UnsupportedAuthorization
            | Error::IdentityVersionMismatch
    ) {
        unsupported.insert(cid.clone());
    } else {
        invalid.insert(cid.clone());
    }
    orphans.insert(cid.clone());
    diagnostics.insert(format!("{cid}: {error}"));
}

trait EventState {
    fn event(&self) -> &Cid;
}

impl EventState for DelegationState {
    fn event(&self) -> &Cid {
        &self.event
    }
}

impl EventState for RevocationState {
    fn event(&self) -> &Cid {
        &self.event
    }
}

fn sorted_states<T: EventState>(states: HashMap<Cid, T>) -> Vec<T> {
    let mut states: Vec<T> = states.into_values().collect();
    states.sort_by(|left, right| cid_cmp(left.event(), right.event()));
    states
}

fn cid_cmp(left: &Cid, right: &Cid) -> Ordering {
    left.to_bytes().cmp(&right.to_bytes())
}

fn sorted_cids(values: HashSet<Cid>) -> Vec<Cid> {
    let mut values: Vec<Cid> = values.into_iter().collect();
    values.sort_by(cid_cmp);
    values
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityPathEvaluation {
    pub trusted_time: super::TrustedTime,
    pub revocation: super::RevocationStanding,
    pub capability: super::CapabilityEvidence,
}

/// Evaluate one explicitly named delegation head. Inputs are recognized
/// delegation/revocation states whose envelope, proof, identity standing, and
/// scope admission were established by their respective resolvers.
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
    if head_state.scope != governance.scope || !governance.recognizes(&head_state.governance_event)
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
        if revocation.scope != governance.scope
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
    #[error("unsupported scope operation: {0}")]
    UnsupportedOperation(String),
    #[error("capability notBefore must not be after notAfter")]
    TimeRange,
    #[error("parent capability does not permit delegation")]
    ParentNotDelegable,
    #[error("capability scope amplification")]
    ScopeMismatch,
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
    #[error("child delegation does not match its parent grantor and governance origin")]
    ParentMismatch,
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
    Inception(#[from] super::scope_inception::Error),
    #[error(transparent)]
    Control(#[from] super::control::Error),
    #[error(transparent)]
    Encode(#[from] atproto_dasl::EncodeError),
    #[error(transparent)]
    Decode(#[from] atproto_dasl::DecodeError),
}

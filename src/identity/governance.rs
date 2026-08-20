//! RFC 1 scope governance events and deterministic evidence resolution.

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
};

use atproto_dasl::{Cid, Ipld};
use serde::{Deserialize, Serialize};

use super::{
    control::{verify_static_did_key_proof, ControlEvent, Proof, SigningInput},
    did_kan::validate_did,
    scope_inception::{ScopeId, ScopeInception},
    CryptographicValidity,
};

pub const GOVERNANCE_DOMAIN: &str = "tools.kan.scope.governance.v1";
pub const GOVERNANCE_EVENT_TYPE: &str = "governance";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum GovernanceMode {
    Update,
    Reconcile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GovernanceEvent {
    pub v: u64,
    pub scope: ScopeId,
    pub mode: GovernanceMode,
    pub parents: Vec<Cid>,
    pub sequence: u64,
    pub governance_roots: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceState {
    pub scope: ScopeId,
    pub event: Cid,
    pub sequence: u64,
    pub governance_roots: Vec<String>,
}

impl GovernanceState {
    pub fn from_inception(inception: &ScopeInception) -> Result<Self, Error> {
        inception.validate()?;
        Ok(Self {
            scope: inception.scope_id()?,
            event: inception.signing_input()?.logical_cid()?,
            sequence: 0,
            governance_roots: inception.governance_roots.clone(),
        })
    }
}

impl GovernanceEvent {
    pub fn new(
        mode: GovernanceMode,
        scope: ScopeId,
        mut parents: Vec<Cid>,
        sequence: u64,
        mut governance_roots: Vec<String>,
    ) -> Result<Self, Error> {
        reject_cid_duplicates(&parents, "parents")?;
        reject_duplicates(&governance_roots, "governanceRoots")?;
        parents.sort_by(cid_cmp);
        governance_roots.sort();
        let event = Self {
            v: 1,
            scope,
            mode,
            parents,
            sequence,
            governance_roots,
        };
        event.validate()?;
        Ok(event)
    }

    pub fn update(parent: &GovernanceState, governance_roots: Vec<String>) -> Result<Self, Error> {
        Self::new(
            GovernanceMode::Update,
            parent.scope,
            vec![parent.event.clone()],
            parent
                .sequence
                .checked_add(1)
                .ok_or(Error::SequenceOverflow)?,
            governance_roots,
        )
    }

    pub fn reconcile(
        parents: &[GovernanceState],
        governance_roots: Vec<String>,
    ) -> Result<Self, Error> {
        let Some(first) = parents.first() else {
            return Err(Error::ParentCount {
                mode: GovernanceMode::Reconcile,
                found: 0,
            });
        };
        if parents.iter().any(|parent| parent.scope != first.scope) {
            return Err(Error::ScopeMismatch);
        }
        let sequence = parents
            .iter()
            .map(|parent| parent.sequence)
            .max()
            .expect("non-empty parents")
            .checked_add(1)
            .ok_or(Error::SequenceOverflow)?;
        Self::new(
            GovernanceMode::Reconcile,
            first.scope,
            parents.iter().map(|parent| parent.event.clone()).collect(),
            sequence,
            governance_roots,
        )
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.v != 1 {
            return Err(Error::UnsupportedVersion(self.v));
        }
        validate_sorted_unique_cids(&self.parents, "parents")?;
        validate_sorted_unique_nonempty(&self.governance_roots, "governanceRoots")?;
        for root in &self.governance_roots {
            validate_did(root)?;
        }
        let valid_parent_count = match self.mode {
            GovernanceMode::Update => self.parents.len() == 1,
            GovernanceMode::Reconcile => self.parents.len() >= 2,
        };
        if !valid_parent_count {
            return Err(Error::ParentCount {
                mode: self.mode,
                found: self.parents.len(),
            });
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        Ok(atproto_dasl::to_vec(self)?)
    }

    pub fn signing_input(&self) -> Result<SigningInput, Error> {
        self.validate()?;
        let payload: Ipld = atproto_dasl::from_reader(&self.canonical_bytes()?[..])?;
        Ok(SigningInput::new(
            GOVERNANCE_DOMAIN,
            GOVERNANCE_EVENT_TYPE,
            payload,
        )?)
    }

    pub fn validate_against(&self, parents: &[GovernanceState]) -> Result<(), Error> {
        self.validate()?;
        if parents.len() != self.parents.len() {
            return Err(Error::MissingParentState);
        }
        if parents.iter().any(|parent| parent.scope != self.scope) {
            return Err(Error::ScopeMismatch);
        }
        let mut actual_parents: Vec<Cid> =
            parents.iter().map(|parent| parent.event.clone()).collect();
        actual_parents.sort_by(cid_cmp);
        if actual_parents != self.parents {
            return Err(Error::ParentMismatch);
        }
        let expected = parents
            .iter()
            .map(|parent| parent.sequence)
            .max()
            .ok_or(Error::MissingParentState)?
            .checked_add(1)
            .ok_or(Error::SequenceOverflow)?;
        if self.sequence != expected {
            return Err(Error::Sequence {
                expected,
                found: self.sequence,
            });
        }
        Ok(())
    }

    pub fn proved_event(
        &self,
        parents: &[GovernanceState],
        proofs: Vec<Proof>,
    ) -> Result<ControlEvent, Error> {
        self.validate_against(parents)?;
        let input = self.signing_input()?;
        match authorize_all(&input, &proofs, parents) {
            Authorization::Valid => Ok(ControlEvent::new(input, proofs)?),
            Authorization::Unsupported => Err(Error::UnsupportedAuthorization),
            Authorization::Invalid => Err(Error::NoAuthorization),
        }
    }

    pub fn resulting_state(
        &self,
        parents: &[GovernanceState],
        event: Cid,
    ) -> Result<GovernanceState, Error> {
        self.validate_against(parents)?;
        Ok(self.state(event))
    }

    fn state(&self, event: Cid) -> GovernanceState {
        GovernanceState {
            scope: self.scope,
            event,
            sequence: self.sequence,
            governance_roots: self.governance_roots.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NonActiveGovernanceStanding {
    Contested,
    UnknownHistory,
    Unsupported,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActiveGovernance {
    pub standing: ActiveGovernanceStanding,
    pub active_event: Cid,
    pub governance_roots: Vec<String>,
    #[serde(default)]
    ancestral_events: Vec<Cid>,
    pub orphans: Vec<Cid>,
    pub missing_references: Vec<Cid>,
    pub diagnostics: Vec<String>,
}

impl ActiveGovernance {
    pub fn ancestral_events(&self) -> &[Cid] {
        &self.ancestral_events
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ActiveGovernanceStanding {
    Active,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NonActiveGovernance {
    pub standing: NonActiveGovernanceStanding,
    pub active_leaves: Vec<Cid>,
    pub known_leaves: Vec<Cid>,
    pub orphans: Vec<Cid>,
    pub missing_references: Vec<Cid>,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceResolution {
    Active(ActiveGovernance),
    NonActive(NonActiveGovernance),
}

/// Resolve a complete in-memory evidence set without consulting observation
/// order, wall-clock time, proof count, or external state.
pub fn resolve(
    inception: &ScopeInception,
    inception_event: &ControlEvent,
    candidates: &[ControlEvent],
) -> GovernanceResolution {
    let mut reasons = BTreeSet::new();
    let mut orphans = HashSet::new();
    let mut missing_references = HashSet::new();

    let Ok(inception_state) = GovernanceState::from_inception(inception) else {
        return non_active(
            NonActiveGovernanceStanding::Invalid,
            HashSet::new(),
            orphans,
            missing_references,
            ["invalid scope inception".to_string()],
        );
    };
    let Ok(expected_inception_input) = inception.signing_input() else {
        return non_active(
            NonActiveGovernanceStanding::Invalid,
            HashSet::new(),
            orphans,
            missing_references,
            ["invalid scope inception signing input".to_string()],
        );
    };
    if inception_event.validate().is_err() {
        return non_active(
            NonActiveGovernanceStanding::Invalid,
            HashSet::new(),
            orphans,
            missing_references,
            ["inception event has an invalid control envelope".to_string()],
        );
    }
    if inception_event.signing_input() != expected_inception_input {
        return non_active(
            NonActiveGovernanceStanding::Invalid,
            HashSet::new(),
            orphans,
            missing_references,
            ["inception event does not match its payload".to_string()],
        );
    }
    match authorize_all(
        &expected_inception_input,
        &inception_event.proofs,
        std::slice::from_ref(&inception_state),
    ) {
        Authorization::Unsupported => {
            return non_active(
                NonActiveGovernanceStanding::Unsupported,
                HashSet::new(),
                orphans,
                missing_references,
                ["scope inception authorization is unsupported".to_string()],
            );
        }
        Authorization::Invalid => {
            return non_active(
                NonActiveGovernanceStanding::Invalid,
                HashSet::new(),
                orphans,
                missing_references,
                ["scope inception authorization is invalid".to_string()],
            );
        }
        Authorization::Valid => {}
    }

    let mut groups: HashMap<Cid, CandidateGroup> = HashMap::new();
    let mut evidence_ids = HashSet::new();
    let mut invalid_envelope_ids = HashSet::new();
    for event in candidates {
        let Ok(cid) = event.logical_cid() else {
            reasons.insert("candidate has an invalid control envelope".to_string());
            continue;
        };
        evidence_ids.insert(cid.clone());
        if let Err(error) = event.validate() {
            reasons.insert(format!("{cid}: invalid control envelope: {error}"));
            invalid_envelope_ids.insert(cid);
            continue;
        }
        groups
            .entry(cid.clone())
            .and_modify(|group| group.proofs.extend(event.proofs.clone()))
            .or_insert_with(|| CandidateGroup {
                input: event.signing_input(),
                proofs: event.proofs.clone(),
                decoded: decode_payload(event),
            });
    }
    for cid in invalid_envelope_ids {
        if !groups.contains_key(&cid) {
            orphans.insert(cid);
        }
    }

    let mut states = HashMap::from([(inception_state.event.clone(), inception_state)]);
    let mut pending: HashSet<Cid> = groups.keys().cloned().collect();
    let mut unsupported = false;

    loop {
        let mut progressed = false;
        let mut pending_order: Vec<Cid> = pending.iter().cloned().collect();
        pending_order.sort_by(cid_cmp);
        for cid in pending_order {
            let group = &groups[&cid];
            if let DecodedPayload::Invalid(reason) = &group.decoded {
                reasons.insert(format!("{cid}: {reason}"));
                orphans.insert(cid.clone());
                pending.remove(&cid);
                progressed = true;
                continue;
            }
            if let DecodedPayload::Unsupported { reason, header } = &group.decoded {
                let Some(header) = header else {
                    reasons.insert(format!("{cid}: {reason}"));
                    orphans.insert(cid.clone());
                    pending.remove(&cid);
                    progressed = true;
                    continue;
                };
                let Some(parent_states) = header
                    .parents
                    .iter()
                    .map(|parent| states.get(parent).cloned())
                    .collect::<Option<Vec<_>>>()
                else {
                    continue;
                };
                match header
                    .validate_against(&parent_states)
                    .map(|()| authorize_all(&group.input, &group.proofs, &parent_states))
                {
                    Ok(Authorization::Valid | Authorization::Unsupported) => {
                        unsupported = true;
                        reasons.insert(format!("{cid}: {reason}"));
                    }
                    Ok(Authorization::Invalid) => {
                        reasons.insert(format!("{cid}: authorization is invalid"));
                    }
                    Err(error) => {
                        reasons.insert(format!("{cid}: {error}"));
                    }
                }
                orphans.insert(cid.clone());
                pending.remove(&cid);
                progressed = true;
                continue;
            }
            let DecodedPayload::Supported {
                event,
                unsupported_fields,
            } = &group.decoded
            else {
                unreachable!();
            };
            let Some(parent_states) = event
                .parents
                .iter()
                .map(|parent| states.get(parent).cloned())
                .collect::<Option<Vec<_>>>()
            else {
                continue;
            };
            if let Err(error) = event.validate_against(&parent_states) {
                reasons.insert(format!("{cid}: {error}"));
                orphans.insert(cid.clone());
                pending.remove(&cid);
                progressed = true;
                continue;
            }
            match authorize_all(&group.input, &group.proofs, &parent_states) {
                Authorization::Valid if unsupported_fields.is_empty() => {
                    states.insert(cid.clone(), event.state(cid.clone()));
                }
                Authorization::Valid => {
                    unsupported = true;
                    reasons.insert(format!(
                        "{cid}: unsupported fields {}",
                        unsupported_fields.join(", ")
                    ));
                    orphans.insert(cid.clone());
                }
                Authorization::Unsupported => {
                    unsupported = true;
                    reasons.insert(format!("{cid}: authorization is unsupported"));
                    orphans.insert(cid.clone());
                }
                Authorization::Invalid => {
                    reasons.insert(format!("{cid}: authorization is invalid"));
                    orphans.insert(cid.clone());
                }
            }
            pending.remove(&cid);
            progressed = true;
        }
        if !progressed {
            break;
        }
    }

    let mut unknown_history = false;
    for cid in pending {
        let group = &groups[&cid];
        orphans.insert(cid.clone());
        let parents = match &group.decoded {
            DecodedPayload::Supported { event, .. } => &event.parents,
            DecodedPayload::Unsupported {
                header: Some(header),
                ..
            } => &header.parents,
            DecodedPayload::Unsupported { header: None, .. } | DecodedPayload::Invalid(_) => {
                continue
            }
        };
        for parent in parents {
            if !states.contains_key(parent) && !evidence_ids.contains(parent) {
                missing_references.insert(parent.clone());
            }
        }
        let DecodedPayload::Supported { event, .. } = &group.decoded else {
            continue;
        };
        if event.mode == GovernanceMode::Reconcile {
            let available: Vec<GovernanceState> = event
                .parents
                .iter()
                .filter_map(|parent| states.get(parent).cloned())
                .collect();
            let has_absent_parent = event
                .parents
                .iter()
                .any(|parent| !states.contains_key(parent) && !evidence_ids.contains(parent));
            let sequence_still_possible = available
                .iter()
                .map(|parent| parent.sequence)
                .max()
                .is_some_and(|known_max| event.sequence > known_max);
            let scope_matches = available.iter().all(|parent| parent.scope == event.scope);
            if !available.is_empty()
                && available.len() < event.parents.len()
                && has_absent_parent
                && sequence_still_possible
                && scope_matches
                && authorize_all(&group.input, &group.proofs, &available) == Authorization::Valid
            {
                unknown_history = true;
                reasons.insert(format!(
                    "{cid}: authenticated reconciliation has missing history"
                ));
            }
        }
    }

    let mut leaves: HashSet<Cid> = states.keys().cloned().collect();
    for (cid, group) in &groups {
        if !states.contains_key(cid) {
            continue;
        }
        if let DecodedPayload::Supported { event, .. } = &group.decoded {
            for parent in &event.parents {
                leaves.remove(parent);
            }
        }
    }

    if unknown_history {
        return non_active(
            NonActiveGovernanceStanding::UnknownHistory,
            leaves,
            orphans,
            missing_references,
            reasons,
        );
    }
    if leaves.len() > 1 {
        return non_active(
            NonActiveGovernanceStanding::Contested,
            leaves,
            orphans,
            missing_references,
            reasons,
        );
    }
    if unsupported {
        return non_active(
            NonActiveGovernanceStanding::Unsupported,
            leaves,
            orphans,
            missing_references,
            reasons,
        );
    }

    let mut active_events: Vec<Cid> = leaves.iter().cloned().collect();
    active_events.sort_by(cid_cmp);
    let active_event = active_events
        .into_iter()
        .next()
        .expect("recognized inception always leaves at least one leaf");
    let active = &states[&active_event];
    let ancestral_events = collect_ancestral_events(&active_event, &states, &groups);
    GovernanceResolution::Active(ActiveGovernance {
        standing: ActiveGovernanceStanding::Active,
        active_event,
        governance_roots: active.governance_roots.clone(),
        ancestral_events,
        orphans: sorted_cids(orphans),
        missing_references: sorted_cids(missing_references),
        diagnostics: reasons.into_iter().collect(),
    })
}

fn collect_ancestral_events(
    active_event: &Cid,
    states: &HashMap<Cid, GovernanceState>,
    groups: &HashMap<Cid, CandidateGroup>,
) -> Vec<Cid> {
    let mut ancestors = HashSet::new();
    let mut pending = vec![active_event.clone()];
    while let Some(event) = pending.pop() {
        if !ancestors.insert(event.clone()) {
            continue;
        }
        let Some(CandidateGroup {
            decoded: DecodedPayload::Supported { event, .. },
            ..
        }) = groups.get(&event)
        else {
            continue;
        };
        pending.extend(
            event
                .parents
                .iter()
                .filter(|parent| states.contains_key(*parent))
                .cloned(),
        );
    }
    sorted_cids(ancestors)
}

#[derive(Debug, Clone)]
struct CandidateGroup {
    input: SigningInput,
    proofs: Vec<Proof>,
    decoded: DecodedPayload,
}

#[derive(Debug, Clone)]
enum DecodedPayload {
    Supported {
        event: GovernanceEvent,
        unsupported_fields: Vec<String>,
    },
    Unsupported {
        reason: String,
        header: Option<GovernanceHeader>,
    },
    Invalid(String),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GovernanceHeader {
    scope: ScopeId,
    parents: Vec<Cid>,
    sequence: u64,
    governance_roots: Vec<String>,
}

impl GovernanceHeader {
    fn validate_against(&self, parents: &[GovernanceState]) -> Result<(), Error> {
        validate_sorted_unique_cids(&self.parents, "parents")?;
        validate_sorted_unique_nonempty(&self.governance_roots, "governanceRoots")?;
        for root in &self.governance_roots {
            validate_did(root)?;
        }
        if parents.len() != self.parents.len() {
            return Err(Error::MissingParentState);
        }
        if parents.iter().any(|parent| parent.scope != self.scope) {
            return Err(Error::ScopeMismatch);
        }
        let mut actual: Vec<Cid> = parents.iter().map(|parent| parent.event.clone()).collect();
        actual.sort_by(cid_cmp);
        if actual != self.parents {
            return Err(Error::ParentMismatch);
        }
        let expected = parents
            .iter()
            .map(|parent| parent.sequence)
            .max()
            .ok_or(Error::MissingParentState)?
            .checked_add(1)
            .ok_or(Error::SequenceOverflow)?;
        if self.sequence != expected {
            return Err(Error::Sequence {
                expected,
                found: self.sequence,
            });
        }
        Ok(())
    }
}

fn decode_payload(event: &ControlEvent) -> DecodedPayload {
    if event.domain != GOVERNANCE_DOMAIN || event.event_type != GOVERNANCE_EVENT_TYPE {
        return DecodedPayload::Invalid("wrong governance domain or event type".to_string());
    }
    let Ipld::Map(fields) = &event.payload else {
        return DecodedPayload::Invalid("governance payload is not a map".to_string());
    };
    let known = [
        "v",
        "scope",
        "mode",
        "parents",
        "sequence",
        "governanceRoots",
    ];
    let mut unsupported_fields: Vec<String> = fields
        .keys()
        .filter(|key| !known.contains(&key.as_str()))
        .cloned()
        .collect();
    unsupported_fields.sort();
    let header = decode_header(fields);
    match fields.get("v") {
        Some(Ipld::Integer(1)) => {}
        Some(Ipld::Integer(version)) => {
            return DecodedPayload::Unsupported {
                reason: format!("unsupported version {version}"),
                header,
            };
        }
        _ => return DecodedPayload::Invalid("v is not an integer".to_string()),
    }
    if let Some(Ipld::String(mode)) = fields.get("mode") {
        if mode != "update" && mode != "reconcile" {
            return DecodedPayload::Unsupported {
                reason: format!("unsupported mode {mode}"),
                header,
            };
        }
    }
    let projection: BTreeMap<String, Ipld> = fields
        .iter()
        .filter(|(key, _)| known.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let bytes = match atproto_dasl::to_vec(&Ipld::Map(projection)) {
        Ok(bytes) => bytes,
        Err(error) => return DecodedPayload::Invalid(error.to_string()),
    };
    let decoded: GovernanceEvent = match atproto_dasl::from_reader(&bytes[..]) {
        Ok(decoded) => decoded,
        Err(error) => return DecodedPayload::Invalid(error.to_string()),
    };
    if let Err(error) = decoded.validate() {
        return match error {
            Error::UnsupportedVersion(_) => DecodedPayload::Unsupported {
                reason: error.to_string(),
                header,
            },
            _ => DecodedPayload::Invalid(error.to_string()),
        };
    }
    DecodedPayload::Supported {
        event: decoded,
        unsupported_fields,
    }
}

fn decode_header(fields: &BTreeMap<String, Ipld>) -> Option<GovernanceHeader> {
    let header_fields = ["scope", "parents", "sequence", "governanceRoots"];
    let projection: BTreeMap<String, Ipld> = fields
        .iter()
        .filter(|(key, _)| header_fields.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let bytes = atproto_dasl::to_vec(&Ipld::Map(projection)).ok()?;
    atproto_dasl::from_reader(&bytes[..]).ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Authorization {
    Valid,
    Unsupported,
    Invalid,
}

fn authorize_all(
    input: &SigningInput,
    proofs: &[Proof],
    parents: &[GovernanceState],
) -> Authorization {
    let mut unsupported = false;
    for parent in parents {
        let mut parent_valid = false;
        let mut parent_unsupported = false;
        for proof in proofs {
            let Some((controller, _)) = proof.method.split_once('#') else {
                continue;
            };
            if !parent
                .governance_roots
                .iter()
                .any(|root| root == controller)
            {
                continue;
            }
            if !controller.starts_with("did:key:") {
                parent_unsupported = true;
                continue;
            }
            match verify_static_did_key_proof(input, proof) {
                CryptographicValidity::Valid => parent_valid = true,
                CryptographicValidity::Unsupported | CryptographicValidity::Unknown => {
                    parent_unsupported = true;
                }
                CryptographicValidity::Invalid => {}
            }
        }
        if !parent_valid {
            if parent_unsupported {
                unsupported = true;
            } else {
                return Authorization::Invalid;
            }
        }
    }
    if unsupported {
        Authorization::Unsupported
    } else {
        Authorization::Valid
    }
}

fn non_active(
    standing: NonActiveGovernanceStanding,
    leaves: HashSet<Cid>,
    orphans: HashSet<Cid>,
    missing_references: HashSet<Cid>,
    reasons: impl IntoIterator<Item = String>,
) -> GovernanceResolution {
    let known_leaves = sorted_cids(leaves);
    let active_leaves = if standing == NonActiveGovernanceStanding::Contested {
        known_leaves.clone()
    } else {
        vec![]
    };
    let reasons: BTreeSet<String> = reasons.into_iter().collect();
    GovernanceResolution::NonActive(NonActiveGovernance {
        standing,
        active_leaves,
        known_leaves,
        orphans: sorted_cids(orphans),
        missing_references: sorted_cids(missing_references),
        reasons: reasons.into_iter().collect(),
    })
}

fn cid_cmp(left: &Cid, right: &Cid) -> Ordering {
    left.to_bytes().cmp(&right.to_bytes())
}

fn sorted_cids(values: HashSet<Cid>) -> Vec<Cid> {
    let mut values: Vec<Cid> = values.into_iter().collect();
    values.sort_by(cid_cmp);
    values
}

fn validate_sorted_unique_cids(values: &[Cid], field: &'static str) -> Result<(), Error> {
    if values.is_empty() {
        return Err(Error::Empty(field));
    }
    if values
        .windows(2)
        .any(|pair| cid_cmp(&pair[0], &pair[1]) != Ordering::Less)
    {
        return Err(Error::NotSortedUnique(field));
    }
    Ok(())
}

fn reject_cid_duplicates(values: &[Cid], field: &'static str) -> Result<(), Error> {
    let mut seen = HashSet::new();
    if values.iter().any(|value| !seen.insert(value.clone())) {
        return Err(Error::Duplicate(field));
    }
    Ok(())
}

fn validate_sorted_unique_nonempty<T: Ord>(values: &[T], field: &'static str) -> Result<(), Error> {
    if values.is_empty() {
        return Err(Error::Empty(field));
    }
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
    #[error("unsupported governance event version {0}")]
    UnsupportedVersion(u64),
    #[error("{0} must not be empty")]
    Empty(&'static str),
    #[error("{0} must be sorted and duplicate-free")]
    NotSortedUnique(&'static str),
    #[error("{0} contains a duplicate")]
    Duplicate(&'static str),
    #[error("{mode:?} governance event has {found} parents")]
    ParentCount { mode: GovernanceMode, found: usize },
    #[error("governance event scope does not match its parents")]
    ScopeMismatch,
    #[error("governance event parents do not match the supplied states")]
    ParentMismatch,
    #[error("governance event is missing a parent state")]
    MissingParentState,
    #[error("governance sequence must be {expected}, found {found}")]
    Sequence { expected: u64, found: u64 },
    #[error("governance sequence overflow")]
    SequenceOverflow,
    #[error("governance event has no proof authorized at every parent")]
    NoAuthorization,
    #[error("governance event authorization is unsupported")]
    UnsupportedAuthorization,
    #[error(transparent)]
    Identity(#[from] super::did_kan::Error),
    #[error(transparent)]
    Inception(#[from] super::scope_inception::Error),
    #[error(transparent)]
    Encode(#[from] atproto_dasl::EncodeError),
    #[error(transparent)]
    Decode(#[from] atproto_dasl::DecodeError),
    #[error(transparent)]
    Control(#[from] super::control::Error),
}

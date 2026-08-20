//! Typed RFC 1 `did:kan` update payloads and validated producer values.

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
};

use atproto_dasl::{Cid, Ipld};
use serde::{Deserialize, Serialize};

use super::{
    control::{verify_static_did_key_proof, ControlEvent, Proof, SigningInput},
    did_kan::{validate_did, validate_did_url, validate_service, validate_verification_method},
    did_kan_state::{DidKanState, IdentityOperation},
    CryptographicValidity,
};

pub const UPDATE_DOMAIN: &str = "tools.kan.did.update.v1";
pub const UPDATE_EVENT_TYPE: &str = "update";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum IdentityUpdateMode {
    Administration,
    Recovery,
}

/// A structurally supported update payload decoded from canonical evidence.
///
/// Semantic validity requires exact parent states and is represented by
/// [`ValidatedDidKanUpdate`]. Fields stay private so producer callers cannot
/// bypass that boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DidKanUpdate {
    v: u64,
    did: String,
    mode: IdentityUpdateMode,
    previous: Cid,
    sequence: u64,
    recovery_parent: Option<Cid>,
    recovery_epoch: u64,
    operations: Vec<IdentityOperation>,
    supersedes: Vec<Cid>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedDidKanUpdate {
    update: DidKanUpdate,
    resulting_state: DidKanState,
    authorization_state: DidKanState,
}

impl DidKanUpdate {
    pub fn administration(
        previous: &DidKanState,
        operations: Vec<IdentityOperation>,
    ) -> Result<ValidatedDidKanUpdate, Error> {
        let update = Self {
            v: 1,
            did: previous.did.clone(),
            mode: IdentityUpdateMode::Administration,
            previous: previous.event.clone(),
            sequence: previous
                .sequence
                .checked_add(1)
                .ok_or(Error::SequenceOverflow)?,
            recovery_parent: None,
            recovery_epoch: previous.recovery_epoch,
            operations,
            supersedes: vec![],
        };
        update.validate_structure()?;
        let event = update.signing_input_unchecked()?.logical_cid()?;
        let resulting_state = previous.apply_administration(event, &update.operations)?;
        Ok(ValidatedDidKanUpdate {
            update,
            resulting_state,
            authorization_state: previous.clone(),
        })
    }

    pub fn recovery(
        previous: &DidKanState,
        recovery_parent: &DidKanState,
        operations: Vec<IdentityOperation>,
        mut supersedes: Vec<Cid>,
    ) -> Result<ValidatedDidKanUpdate, Error> {
        reject_cid_duplicates(&supersedes, "supersedes")?;
        supersedes.sort_by(cid_cmp);
        let recovery_epoch = recovery_parent
            .recovery_epoch
            .checked_add(1)
            .ok_or(Error::SequenceOverflow)?;
        let update = Self {
            v: 1,
            did: previous.did.clone(),
            mode: IdentityUpdateMode::Recovery,
            previous: previous.event.clone(),
            sequence: previous
                .sequence
                .checked_add(1)
                .ok_or(Error::SequenceOverflow)?,
            recovery_parent: Some(recovery_parent.event.clone()),
            recovery_epoch,
            operations,
            supersedes,
        };
        update.validate_structure()?;
        let event = update.signing_input_unchecked()?.logical_cid()?;
        let resulting_state =
            previous.apply_recovery(recovery_parent, event, &update.operations)?;
        Ok(ValidatedDidKanUpdate {
            update,
            resulting_state,
            authorization_state: recovery_parent.clone(),
        })
    }

    pub fn v(&self) -> u64 {
        self.v
    }

    pub fn did(&self) -> &str {
        &self.did
    }

    pub fn mode(&self) -> IdentityUpdateMode {
        self.mode
    }

    pub fn previous(&self) -> &Cid {
        &self.previous
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn recovery_parent(&self) -> Option<&Cid> {
        self.recovery_parent.as_ref()
    }

    pub fn recovery_epoch(&self) -> u64 {
        self.recovery_epoch
    }

    pub fn operations(&self) -> &[IdentityOperation] {
        &self.operations
    }

    pub fn supersedes(&self) -> &[Cid] {
        &self.supersedes
    }

    pub fn validate_structure(&self) -> Result<(), Error> {
        if self.v != 1 {
            return Err(Error::UnsupportedVersion(self.v));
        }
        validate_did_kan(&self.did)?;
        if self.sequence == 0 {
            return Err(Error::SequenceZero);
        }
        if self.operations.is_empty() {
            return Err(Error::Empty("operations"));
        }
        for operation in &self.operations {
            validate_operation(operation)?;
        }
        validate_sorted_unique_cids(&self.supersedes, "supersedes")?;
        match self.mode {
            IdentityUpdateMode::Administration => {
                if self.recovery_parent.is_some() {
                    return Err(Error::AdministrationRecoveryParent);
                }
                if !self.supersedes.is_empty() {
                    return Err(Error::AdministrationSupersedes);
                }
                if self.operations.iter().any(|operation| {
                    matches!(
                        operation,
                        IdentityOperation::AddRecoveryController { .. }
                            | IdentityOperation::RemoveRecoveryController { .. }
                    )
                }) {
                    return Err(Error::AdministrationRecoveryOperation);
                }
            }
            IdentityUpdateMode::Recovery => {
                if self.recovery_parent.is_none() {
                    return Err(Error::MissingRecoveryParent);
                }
            }
        }
        Ok(())
    }

    fn canonical_bytes_unchecked(&self) -> Result<Vec<u8>, Error> {
        self.validate_structure()?;
        Ok(atproto_dasl::to_vec(self)?)
    }

    fn signing_input_unchecked(&self) -> Result<SigningInput, Error> {
        let payload: Ipld = atproto_dasl::from_reader(&self.canonical_bytes_unchecked()?[..])?;
        Ok(SigningInput::new(
            UPDATE_DOMAIN,
            UPDATE_EVENT_TYPE,
            payload,
        )?)
    }

    fn validate_against(
        &self,
        previous: &DidKanState,
        recovery_parent: Option<&DidKanState>,
        event: Cid,
    ) -> Result<DidKanState, Error> {
        self.validate_structure()?;
        if self.did != previous.did || self.previous != previous.event {
            return Err(Error::PreviousMismatch);
        }
        let expected_sequence = previous
            .sequence
            .checked_add(1)
            .ok_or(Error::SequenceOverflow)?;
        if self.sequence != expected_sequence {
            return Err(Error::Sequence {
                expected: expected_sequence,
                found: self.sequence,
            });
        }
        match self.mode {
            IdentityUpdateMode::Administration => {
                if recovery_parent.is_some() || self.recovery_epoch != previous.recovery_epoch {
                    return Err(Error::RecoveryEpoch {
                        expected: previous.recovery_epoch,
                        found: self.recovery_epoch,
                    });
                }
                Ok(previous.apply_administration(event, &self.operations)?)
            }
            IdentityUpdateMode::Recovery => {
                let recovery_parent = recovery_parent.ok_or(Error::MissingRecoveryParent)?;
                if self.recovery_parent.as_ref() != Some(&recovery_parent.event) {
                    return Err(Error::RecoveryParentMismatch);
                }
                let expected_epoch = recovery_parent
                    .recovery_epoch
                    .checked_add(1)
                    .ok_or(Error::SequenceOverflow)?;
                if self.recovery_epoch != expected_epoch {
                    return Err(Error::RecoveryEpoch {
                        expected: expected_epoch,
                        found: self.recovery_epoch,
                    });
                }
                Ok(previous.apply_recovery(recovery_parent, event, &self.operations)?)
            }
        }
    }
}

impl ValidatedDidKanUpdate {
    pub fn payload(&self) -> &DidKanUpdate {
        &self.update
    }

    pub fn resulting_state(&self) -> &DidKanState {
        &self.resulting_state
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        self.update.canonical_bytes_unchecked()
    }

    pub fn signing_input(&self) -> Result<SigningInput, Error> {
        self.update.signing_input_unchecked()
    }

    pub fn proved_event(&self, proofs: Vec<Proof>) -> Result<ControlEvent, Error> {
        let input = self.signing_input()?;
        match authorize(&input, &proofs, &self.authorization_state, self.update.mode) {
            Authorization::Valid => Ok(ControlEvent::new(input, proofs)?),
            Authorization::Unsupported => Err(Error::UnsupportedAuthorization),
            Authorization::Invalid => Err(Error::NoAuthorization),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedDidKanState {
    pub did: String,
    pub standing: ActiveIdentityStanding,
    pub active_event: Cid,
    pub recovery_parent: Option<Cid>,
    pub recovery_epoch: u64,
    pub recovery_controllers: Vec<String>,
    pub administration_controllers: Vec<String>,
    pub verification_methods: Vec<super::did_kan::VerificationMethod>,
    pub services: Vec<super::did_kan::Service>,
    pub retired_heads: Vec<Cid>,
    pub orphans: Vec<Cid>,
    pub missing_references: Vec<Cid>,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ActiveIdentityStanding {
    Active,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NonActiveIdentityStanding {
    Contested,
    UnknownHistory,
    Unsupported,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NonActiveDidKanState {
    pub did: Option<String>,
    pub standing: NonActiveIdentityStanding,
    pub active_leaves: Vec<Cid>,
    pub known_leaves: Vec<Cid>,
    pub retired_heads: Vec<Cid>,
    pub events: Vec<Cid>,
    pub orphans: Vec<Cid>,
    pub missing_references: Vec<Cid>,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DidKanResolution {
    Active(Box<ResolvedDidKanState>),
    NonActive(NonActiveDidKanState),
}

/// Resolve a complete in-memory `did:kan` evidence set without using
/// observation order, timestamps, CID ordering as precedence, or proof count.
pub fn resolve(
    genesis: &super::did_kan::DidKanGenesis,
    genesis_event: &ControlEvent,
    candidates: &[ControlEvent],
) -> DidKanResolution {
    let mut reasons = BTreeSet::new();
    let mut orphans = HashSet::new();
    let mut missing_references = HashSet::new();

    let Ok(genesis_state) = DidKanState::from_genesis(genesis) else {
        return non_active(
            None,
            NonActiveIdentityStanding::Invalid,
            HashSet::new(),
            HashSet::new(),
            HashSet::new(),
            orphans,
            missing_references,
            ["malformed".to_string()],
        );
    };
    let did = genesis_state.did.clone();
    let Ok(expected_genesis_input) = genesis.signing_input() else {
        return non_active(
            Some(did),
            NonActiveIdentityStanding::Invalid,
            HashSet::new(),
            HashSet::new(),
            HashSet::new(),
            orphans,
            missing_references,
            ["malformed".to_string()],
        );
    };
    if genesis_event.validate().is_err() || genesis_event.signing_input() != expected_genesis_input
    {
        return non_active(
            Some(did),
            NonActiveIdentityStanding::Invalid,
            HashSet::new(),
            HashSet::new(),
            HashSet::new(),
            orphans,
            missing_references,
            ["non-canonical".to_string()],
        );
    }
    match authorize(
        &expected_genesis_input,
        &genesis_event.proofs,
        &genesis_state,
        IdentityUpdateMode::Recovery,
    ) {
        Authorization::Valid => {}
        Authorization::Unsupported => {
            return non_active(
                Some(did),
                NonActiveIdentityStanding::Unsupported,
                HashSet::new(),
                HashSet::new(),
                HashSet::new(),
                orphans,
                missing_references,
                ["unsupported-algorithm".to_string()],
            );
        }
        Authorization::Invalid => {
            return non_active(
                Some(did),
                NonActiveIdentityStanding::Invalid,
                HashSet::new(),
                HashSet::new(),
                HashSet::new(),
                orphans,
                missing_references,
                ["invalid-proof".to_string()],
            );
        }
    }

    let mut groups: HashMap<Cid, CandidateGroup> = HashMap::new();
    let mut evidence_ids = HashSet::new();
    let mut invalid_envelope_ids = HashSet::new();
    for event in candidates {
        let Ok(cid) = event.logical_cid() else {
            reasons.insert("malformed".to_string());
            continue;
        };
        evidence_ids.insert(cid.clone());
        if event.validate().is_err() {
            reasons.insert(format!("{cid}: non-canonical"));
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
            orphans.insert(cid);
        }
    }

    let mut states = HashMap::from([(genesis_state.event.clone(), genesis_state)]);
    let mut recognized_updates: HashMap<Cid, DidKanUpdate> = HashMap::new();
    let mut pending: HashSet<Cid> = groups.keys().cloned().collect();
    let mut unsupported_events = HashSet::new();

    loop {
        let mut progressed = false;
        let mut order: Vec<Cid> = pending.iter().cloned().collect();
        order.sort_by(cid_cmp);
        for cid in order {
            let group = &groups[&cid];
            if let DecodedPayload::Invalid(reason) = &group.decoded {
                reasons.insert(format!("{cid}: {reason}"));
                orphans.insert(cid.clone());
                pending.remove(&cid);
                progressed = true;
                continue;
            }
            let header = group.decoded.header();
            let Some(previous) = states.get(&header.previous).cloned() else {
                continue;
            };
            let recovery_parent = match &header.recovery_parent {
                Some(parent) => {
                    let Some(state) = states.get(parent).cloned() else {
                        continue;
                    };
                    Some(state)
                }
                None => None,
            };
            if header
                .supersedes
                .iter()
                .any(|target| !states.contains_key(target))
            {
                continue;
            }
            if let Err(reason) = validate_supersedes(
                &header.supersedes,
                &states,
                &recognized_updates,
                &previous.genesis,
            ) {
                reasons.insert(format!("{cid}: {reason}"));
                orphans.insert(cid.clone());
                pending.remove(&cid);
                progressed = true;
                continue;
            }
            let authorization_state =
                match header.validate_against(&previous, recovery_parent.as_ref()) {
                    Ok(state) => state,
                    Err(error) => {
                        reasons.insert(format!("{cid}: {error}"));
                        orphans.insert(cid.clone());
                        pending.remove(&cid);
                        progressed = true;
                        continue;
                    }
                };
            match authorize(
                &group.input,
                &group.proofs,
                authorization_state,
                header.mode,
            ) {
                Authorization::Invalid => {
                    reasons.insert(format!("{cid}: unauthorized-proof"));
                    orphans.insert(cid.clone());
                }
                Authorization::Unsupported => {
                    reasons.insert(format!("{cid}: unsupported-algorithm"));
                    unsupported_events.insert(cid.clone());
                    orphans.insert(cid.clone());
                }
                Authorization::Valid => match &group.decoded {
                    DecodedPayload::Supported { update, .. } => match update.validate_against(
                        &previous,
                        recovery_parent.as_ref(),
                        cid.clone(),
                    ) {
                        Ok(state) => {
                            states.insert(cid.clone(), state);
                            recognized_updates.insert(cid.clone(), update.as_ref().clone());
                        }
                        Err(error) => {
                            reasons.insert(format!("{cid}: {error}"));
                            orphans.insert(cid.clone());
                        }
                    },
                    DecodedPayload::Unsupported { reason, .. } => {
                        reasons.insert(format!("{cid}: {reason}"));
                        unsupported_events.insert(cid.clone());
                        orphans.insert(cid.clone());
                    }
                    DecodedPayload::Invalid(_) => unreachable!(),
                },
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
        let Some(header) = group.decoded.header_option() else {
            continue;
        };
        for reference in header.references() {
            if !states.contains_key(reference) && !evidence_ids.contains(reference) {
                missing_references.insert(reference.clone());
            }
        }
        if header.mode == IdentityUpdateMode::Recovery {
            let recovery_parent = header
                .recovery_parent
                .as_ref()
                .and_then(|parent| states.get(parent));
            let has_absent_reference = header.references().into_iter().any(|reference| {
                !states.contains_key(reference) && !evidence_ids.contains(reference)
            });
            if has_absent_reference
                && recovery_parent.is_some()
                && header.did == did
                && authorize(
                    &group.input,
                    &group.proofs,
                    recovery_parent.expect("checked above"),
                    IdentityUpdateMode::Recovery,
                ) == Authorization::Valid
            {
                unknown_history = true;
                reasons.insert(format!("{cid}: missing-reference"));
            }
        }
    }

    let (retired, retired_heads) = retirement(&recognized_updates);
    let mut leaves: HashSet<Cid> = states
        .keys()
        .filter(|cid| !retired.contains(*cid))
        .cloned()
        .collect();
    for (cid, update) in &recognized_updates {
        if retired.contains(cid) {
            continue;
        }
        leaves.remove(&update.previous);
        if let Some(parent) = &update.recovery_parent {
            leaves.remove(parent);
        }
    }

    if unknown_history {
        return non_active(
            Some(did),
            NonActiveIdentityStanding::UnknownHistory,
            leaves.clone(),
            leaves,
            retired_heads,
            orphans,
            missing_references,
            reasons,
        );
    }
    if leaves.len() > 1 {
        return non_active(
            Some(did),
            NonActiveIdentityStanding::Contested,
            leaves.clone(),
            leaves,
            retired_heads,
            orphans,
            missing_references,
            reasons,
        );
    }
    if !unsupported_events.is_empty() {
        return non_active(
            Some(did),
            NonActiveIdentityStanding::Unsupported,
            HashSet::new(),
            leaves,
            retired_heads,
            orphans,
            missing_references,
            reasons,
        );
    }

    let active_event = leaves
        .iter()
        .next()
        .expect("recognized genesis leaves at least one active event")
        .clone();
    let active = &states[&active_event];
    DidKanResolution::Active(Box::new(ResolvedDidKanState {
        did,
        standing: ActiveIdentityStanding::Active,
        active_event,
        recovery_parent: active.recovery_parent.clone(),
        recovery_epoch: active.recovery_epoch,
        recovery_controllers: active.recovery_controllers.clone(),
        administration_controllers: active.administration_controllers.clone(),
        verification_methods: active.verification_methods.clone(),
        services: active.services.clone(),
        retired_heads: sorted_cids(retired_heads),
        orphans: sorted_cids(orphans),
        missing_references: sorted_cids(missing_references),
        diagnostics: reasons.into_iter().collect(),
    }))
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
        update: Box<DidKanUpdate>,
        header: UpdateHeader,
    },
    Unsupported {
        reason: String,
        header: UpdateHeader,
    },
    Invalid(String),
}

impl DecodedPayload {
    fn header(&self) -> &UpdateHeader {
        self.header_option().expect("invalid payload handled first")
    }

    fn header_option(&self) -> Option<&UpdateHeader> {
        match self {
            Self::Supported { header, .. } => Some(header),
            Self::Unsupported { header, .. } => Some(header),
            Self::Invalid(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UpdateHeader {
    did: String,
    mode: IdentityUpdateMode,
    previous: Cid,
    sequence: u64,
    recovery_parent: Option<Cid>,
    recovery_epoch: u64,
    supersedes: Vec<Cid>,
}

impl UpdateHeader {
    fn validate_against<'a>(
        &self,
        previous: &'a DidKanState,
        recovery_parent: Option<&'a DidKanState>,
    ) -> Result<&'a DidKanState, Error> {
        validate_did_kan(&self.did)?;
        validate_sorted_unique_cids(&self.supersedes, "supersedes")?;
        if self.did != previous.did || self.previous != previous.event {
            return Err(Error::PreviousMismatch);
        }
        let expected_sequence = previous
            .sequence
            .checked_add(1)
            .ok_or(Error::SequenceOverflow)?;
        if self.sequence != expected_sequence {
            return Err(Error::Sequence {
                expected: expected_sequence,
                found: self.sequence,
            });
        }
        match self.mode {
            IdentityUpdateMode::Administration => {
                if self.recovery_parent.is_some() {
                    return Err(Error::AdministrationRecoveryParent);
                }
                if !self.supersedes.is_empty() {
                    return Err(Error::AdministrationSupersedes);
                }
                if self.recovery_epoch != previous.recovery_epoch {
                    return Err(Error::RecoveryEpoch {
                        expected: previous.recovery_epoch,
                        found: self.recovery_epoch,
                    });
                }
                Ok(previous)
            }
            IdentityUpdateMode::Recovery => {
                let recovery_parent = recovery_parent.ok_or(Error::MissingRecoveryParent)?;
                if self.recovery_parent.as_ref() != Some(&recovery_parent.event) {
                    return Err(Error::RecoveryParentMismatch);
                }
                if previous.did != recovery_parent.did
                    || previous.genesis != recovery_parent.genesis
                {
                    return Err(Error::PreviousMismatch);
                }
                let expected_parent = previous
                    .recovery_parent
                    .as_ref()
                    .unwrap_or(&previous.genesis);
                if &recovery_parent.event != expected_parent {
                    return Err(Error::RecoveryParentMismatch);
                }
                let expected_epoch = recovery_parent
                    .recovery_epoch
                    .checked_add(1)
                    .ok_or(Error::SequenceOverflow)?;
                if self.recovery_epoch != expected_epoch
                    || expected_epoch <= previous.recovery_epoch
                {
                    return Err(Error::RecoveryEpoch {
                        expected: expected_epoch,
                        found: self.recovery_epoch,
                    });
                }
                Ok(recovery_parent)
            }
        }
    }

    fn references(&self) -> Vec<&Cid> {
        let mut references = vec![&self.previous];
        if let Some(parent) = &self.recovery_parent {
            references.push(parent);
        }
        references.extend(&self.supersedes);
        references
    }
}

fn decode_payload(event: &ControlEvent) -> DecodedPayload {
    if event.domain != UPDATE_DOMAIN || event.event_type != UPDATE_EVENT_TYPE {
        return DecodedPayload::Invalid("malformed".to_string());
    }
    let Ipld::Map(fields) = &event.payload else {
        return DecodedPayload::Invalid("malformed".to_string());
    };
    let header = match decode_header(fields) {
        Some(header) => header,
        None => return DecodedPayload::Invalid("malformed".to_string()),
    };
    match fields.get("v") {
        Some(Ipld::Integer(1)) => {}
        Some(Ipld::Integer(_)) => {
            return DecodedPayload::Unsupported {
                reason: "unsupported-operation".to_string(),
                header,
            };
        }
        _ => return DecodedPayload::Invalid("malformed".to_string()),
    }

    let known_fields = [
        "v",
        "did",
        "mode",
        "previous",
        "sequence",
        "recoveryParent",
        "recoveryEpoch",
        "operations",
        "supersedes",
    ];
    if fields
        .keys()
        .any(|key| !known_fields.contains(&key.as_str()))
    {
        return DecodedPayload::Unsupported {
            reason: "unknown-field".to_string(),
            header,
        };
    }
    let Some(Ipld::List(operations)) = fields.get("operations") else {
        return DecodedPayload::Invalid("malformed".to_string());
    };
    if operations.is_empty() {
        return DecodedPayload::Invalid("malformed".to_string());
    }
    for operation in operations {
        let Ipld::Map(operation) = operation else {
            return DecodedPayload::Invalid("malformed".to_string());
        };
        let Some(Ipld::String(tag)) = operation.get("op") else {
            return DecodedPayload::Invalid("malformed".to_string());
        };
        let expected: &[&str] = match tag.as_str() {
            "addMethod" => &["op", "method"],
            "removeMethod" => &["op", "id"],
            "setMethodPurposes" => &["op", "id", "purposes"],
            "addAdministrationController"
            | "removeAdministrationController"
            | "addRecoveryController"
            | "removeRecoveryController" => &["op", "did"],
            "addService" => &["op", "service"],
            "removeService" => &["op", "id"],
            _ => {
                return DecodedPayload::Unsupported {
                    reason: "unsupported-operation".to_string(),
                    header,
                };
            }
        };
        if expected.iter().any(|field| !operation.contains_key(*field)) {
            return DecodedPayload::Invalid("malformed".to_string());
        }
        if operation
            .keys()
            .any(|key| !expected.contains(&key.as_str()))
        {
            return DecodedPayload::Unsupported {
                reason: "unknown-field".to_string(),
                header,
            };
        }
    }
    let bytes = match atproto_dasl::to_vec(&event.payload) {
        Ok(bytes) => bytes,
        Err(_) => return DecodedPayload::Invalid("malformed".to_string()),
    };
    let update: DidKanUpdate = match atproto_dasl::from_reader(&bytes[..]) {
        Ok(update) => update,
        Err(_) => return DecodedPayload::Invalid("malformed".to_string()),
    };
    if update.validate_structure().is_err() {
        return DecodedPayload::Invalid("malformed".to_string());
    }
    DecodedPayload::Supported {
        update: Box::new(update),
        header,
    }
}

fn decode_header(fields: &BTreeMap<String, Ipld>) -> Option<UpdateHeader> {
    let names = [
        "did",
        "mode",
        "previous",
        "sequence",
        "recoveryParent",
        "recoveryEpoch",
        "supersedes",
    ];
    let projection: BTreeMap<String, Ipld> = fields
        .iter()
        .filter(|(key, _)| names.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let bytes = atproto_dasl::to_vec(&Ipld::Map(projection)).ok()?;
    atproto_dasl::from_reader(&bytes[..]).ok()
}

fn validate_supersedes(
    supersedes: &[Cid],
    states: &HashMap<Cid, DidKanState>,
    updates: &HashMap<Cid, DidKanUpdate>,
    genesis: &Cid,
) -> Result<(), &'static str> {
    for target in supersedes {
        if target == genesis || !states.contains_key(target) {
            return Err("missing-reference");
        }
        if updates.get(target).map(DidKanUpdate::mode) != Some(IdentityUpdateMode::Administration) {
            return Err("invalid-supersedes");
        }
    }
    Ok(())
}

fn retirement(updates: &HashMap<Cid, DidKanUpdate>) -> (HashSet<Cid>, HashSet<Cid>) {
    let retired_heads: HashSet<Cid> = updates
        .values()
        .filter(|update| update.mode == IdentityUpdateMode::Recovery)
        .flat_map(|update| update.supersedes.iter().cloned())
        .collect();
    let mut retired = retired_heads.clone();
    loop {
        let mut progressed = false;
        for (cid, update) in updates {
            if update.mode == IdentityUpdateMode::Administration
                && retired.contains(&update.previous)
                && retired.insert(cid.clone())
            {
                progressed = true;
            }
        }
        if !progressed {
            break;
        }
    }
    (retired, retired_heads)
}

#[allow(clippy::too_many_arguments)]
fn non_active(
    did: Option<String>,
    standing: NonActiveIdentityStanding,
    active_leaves: HashSet<Cid>,
    known_leaves: HashSet<Cid>,
    retired_heads: HashSet<Cid>,
    orphans: HashSet<Cid>,
    missing_references: HashSet<Cid>,
    reasons: impl IntoIterator<Item = String>,
) -> DidKanResolution {
    let events = if matches!(
        standing,
        NonActiveIdentityStanding::Unsupported | NonActiveIdentityStanding::Invalid
    ) {
        sorted_cids(orphans.clone())
    } else {
        vec![]
    };
    DidKanResolution::NonActive(NonActiveDidKanState {
        did,
        standing,
        active_leaves: sorted_cids(active_leaves),
        known_leaves: sorted_cids(known_leaves),
        retired_heads: sorted_cids(retired_heads),
        events,
        orphans: sorted_cids(orphans),
        missing_references: sorted_cids(missing_references),
        reasons: reasons.into_iter().collect(),
    })
}

fn sorted_cids(values: HashSet<Cid>) -> Vec<Cid> {
    let mut values: Vec<Cid> = values.into_iter().collect();
    values.sort_by(cid_cmp);
    values
}

fn validate_operation(operation: &IdentityOperation) -> Result<(), Error> {
    match operation {
        IdentityOperation::AddMethod { method } => validate_verification_method(method)?,
        IdentityOperation::RemoveMethod { id } => validate_did_url(id)?,
        IdentityOperation::SetMethodPurposes { id, purposes } => {
            validate_did_url(id)?;
            validate_sorted_unique_nonempty(purposes, "purposes")?;
        }
        IdentityOperation::AddAdministrationController { did }
        | IdentityOperation::RemoveAdministrationController { did }
        | IdentityOperation::AddRecoveryController { did }
        | IdentityOperation::RemoveRecoveryController { did } => validate_did(did)?,
        IdentityOperation::AddService { service } => validate_service(service)?,
        IdentityOperation::RemoveService { id } => validate_did_url(id)?,
    }
    Ok(())
}

fn validate_did_kan(did: &str) -> Result<(), Error> {
    let encoded = did
        .strip_prefix("did:kan:")
        .ok_or_else(|| Error::Did(did.to_string()))?;
    let (base, bytes) =
        atrium_crypto::multibase::decode(encoded).map_err(|_| Error::Did(did.to_string()))?;
    if base != atrium_crypto::multibase::Base::Base32Lower
        || bytes.len() != 34
        || bytes[..2] != [0x12, 0x20]
        || atrium_crypto::multibase::encode(base, &bytes) != encoded
    {
        return Err(Error::Did(did.to_string()));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Authorization {
    Valid,
    Unsupported,
    Invalid,
}

fn authorize(
    input: &SigningInput,
    proofs: &[Proof],
    state: &DidKanState,
    mode: IdentityUpdateMode,
) -> Authorization {
    let controllers = match mode {
        IdentityUpdateMode::Administration => &state.administration_controllers,
        IdentityUpdateMode::Recovery => &state.recovery_controllers,
    };
    let mut unsupported = false;
    for proof in proofs {
        let Some((controller, _)) = proof.method.split_once('#') else {
            continue;
        };
        if !controllers.iter().any(|candidate| candidate == controller) {
            continue;
        }
        if !controller.starts_with("did:key:") {
            unsupported = true;
            continue;
        }
        match verify_static_did_key_proof(input, proof) {
            CryptographicValidity::Valid => return Authorization::Valid,
            CryptographicValidity::Unsupported | CryptographicValidity::Unknown => {
                unsupported = true;
            }
            CryptographicValidity::Invalid => {}
        }
    }
    if unsupported {
        Authorization::Unsupported
    } else {
        Authorization::Invalid
    }
}

fn cid_cmp(left: &Cid, right: &Cid) -> Ordering {
    left.to_bytes().cmp(&right.to_bytes())
}

fn reject_cid_duplicates(values: &[Cid], field: &'static str) -> Result<(), Error> {
    let mut seen = HashSet::new();
    if values.iter().any(|value| !seen.insert(value.clone())) {
        return Err(Error::Duplicate(field));
    }
    Ok(())
}

fn validate_sorted_unique_cids(values: &[Cid], field: &'static str) -> Result<(), Error> {
    if values
        .windows(2)
        .any(|pair| cid_cmp(&pair[0], &pair[1]) != Ordering::Less)
    {
        return Err(Error::NotSortedUnique(field));
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

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unsupported did:kan update version {0}")]
    UnsupportedVersion(u64),
    #[error("invalid canonical did:kan identifier: {0}")]
    Did(String),
    #[error("{0} must not be empty")]
    Empty(&'static str),
    #[error("{0} must be sorted and duplicate-free")]
    NotSortedUnique(&'static str),
    #[error("{0} contains a duplicate")]
    Duplicate(&'static str),
    #[error("did:kan update sequence must be greater than zero")]
    SequenceZero,
    #[error("identity sequence overflow")]
    SequenceOverflow,
    #[error("identity update does not continue the supplied previous state")]
    PreviousMismatch,
    #[error("identity update sequence must be {expected}, found {found}")]
    Sequence { expected: u64, found: u64 },
    #[error("identity update recovery epoch must be {expected}, found {found}")]
    RecoveryEpoch { expected: u64, found: u64 },
    #[error("identity update recoveryParent does not match the supplied state")]
    RecoveryParentMismatch,
    #[error("administration update must have recoveryParent null")]
    AdministrationRecoveryParent,
    #[error("administration update must have empty supersedes")]
    AdministrationSupersedes,
    #[error("administration update cannot contain a recovery-controller operation")]
    AdministrationRecoveryOperation,
    #[error("recovery update must name recoveryParent")]
    MissingRecoveryParent,
    #[error("identity update has no proof authorized at its controller state")]
    NoAuthorization,
    #[error("identity update authorization is unsupported")]
    UnsupportedAuthorization,
    #[error(transparent)]
    Identity(#[from] super::did_kan::Error),
    #[error(transparent)]
    State(#[from] super::did_kan_state::Error),
    #[error(transparent)]
    Control(#[from] super::control::Error),
    #[error(transparent)]
    Encode(#[from] atproto_dasl::EncodeError),
    #[error(transparent)]
    Decode(#[from] atproto_dasl::DecodeError),
}

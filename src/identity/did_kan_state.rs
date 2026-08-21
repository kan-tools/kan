//! RFC 1 `did:kan` state transitions and typed operation wire schema.

use std::collections::BTreeMap;

use atproto_dasl::Cid;
use serde::{Deserialize, Serialize};

use super::did_kan::{
    reject_duplicates, validate_did, validate_service, validate_sorted_unique_nonempty,
    validate_verification_method, DidKanGenesis, Service, VerificationMethod, VerificationPurpose,
};

/// One closed RFC 1 identity-state operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "camelCase", deny_unknown_fields)]
pub enum IdentityOperation {
    AddMethod {
        method: VerificationMethod,
    },
    RemoveMethod {
        id: String,
    },
    SetMethodPurposes {
        id: String,
        purposes: Vec<VerificationPurpose>,
    },
    AddAdministrationController {
        did: String,
    },
    RemoveAdministrationController {
        did: String,
    },
    AddRecoveryController {
        did: String,
    },
    RemoveRecoveryController {
        did: String,
    },
    AddService {
        service: Service,
    },
    RemoveService {
        id: String,
    },
}

/// The complete state produced by one recognized `did:kan` event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidKanState {
    pub did: String,
    pub genesis: Cid,
    pub event: Cid,
    pub sequence: u64,
    pub recovery_parent: Option<Cid>,
    pub recovery_epoch: u64,
    pub recovery_controllers: Vec<String>,
    pub administration_controllers: Vec<String>,
    pub verification_methods: Vec<VerificationMethod>,
    pub services: Vec<Service>,
}

impl DidKanState {
    /// Project validated genesis into the first recognized identity state.
    pub fn from_genesis(genesis: &DidKanGenesis) -> Result<Self, Error> {
        genesis.validate()?;
        let did = genesis.did()?;
        let genesis_event = genesis.signing_input()?.logical_cid()?;
        Ok(Self {
            did,
            genesis: genesis_event.clone(),
            event: genesis_event,
            sequence: 0,
            recovery_parent: None,
            recovery_epoch: genesis.recovery_epoch,
            recovery_controllers: genesis.recovery_controllers.clone(),
            administration_controllers: genesis.administration_controllers.clone(),
            verification_methods: genesis.verification_methods.clone(),
            services: genesis.services.clone(),
        })
    }

    /// Apply an administration event's operations in their listed order.
    ///
    /// Proof authorization, envelope fields, and canonical wire decoding sit
    /// above this semantic layer. Administration cannot alter recovery
    /// controllers or the recovery epoch.
    pub fn apply_administration(
        &self,
        event: Cid,
        operations: &[IdentityOperation],
    ) -> Result<Self, Error> {
        self.apply_operations(
            event,
            operations,
            self.recovery_controllers.clone(),
            self.recovery_epoch,
            self.recovery_parent.clone(),
            false,
        )
    }

    /// Apply a recovery event using the recovery authority state selected by
    /// `recoveryParent` and all other state from `self` (`previous`).
    pub fn apply_recovery(
        &self,
        recovery_parent: &DidKanState,
        event: Cid,
        operations: &[IdentityOperation],
    ) -> Result<Self, Error> {
        if self.did != recovery_parent.did || self.genesis != recovery_parent.genesis {
            return Err(Error::IdentityMismatch);
        }
        let expected_parent = self.recovery_parent.as_ref().unwrap_or(&self.genesis);
        if &recovery_parent.event != expected_parent {
            return Err(Error::RecoveryParentMismatch);
        }
        let recovery_epoch = recovery_parent
            .recovery_epoch
            .checked_add(1)
            .ok_or(Error::SequenceOverflow)?;
        if recovery_epoch <= self.recovery_epoch {
            return Err(Error::RecoveryEpoch {
                previous: self.recovery_epoch,
                found: recovery_epoch,
            });
        }
        let latest_recovery = event.clone();
        self.apply_operations(
            event,
            operations,
            recovery_parent.recovery_controllers.clone(),
            recovery_epoch,
            Some(latest_recovery),
            true,
        )
    }

    fn apply_operations(
        &self,
        event: Cid,
        operations: &[IdentityOperation],
        recovery_controller_values: Vec<String>,
        recovery_epoch: u64,
        recovery_parent: Option<Cid>,
        allow_recovery: bool,
    ) -> Result<Self, Error> {
        if operations.is_empty() {
            return Err(Error::EmptyOperations);
        }

        let mut recovery_controllers: BTreeMap<String, ()> = recovery_controller_values
            .into_iter()
            .map(|did| (did, ()))
            .collect();
        let mut administration_controllers: BTreeMap<String, ()> = self
            .administration_controllers
            .iter()
            .cloned()
            .map(|did| (did, ()))
            .collect();
        let mut verification_methods: BTreeMap<String, VerificationMethod> = self
            .verification_methods
            .iter()
            .cloned()
            .map(|method| (method.id.clone(), method))
            .collect();
        let mut services: BTreeMap<String, Service> = self
            .services
            .iter()
            .cloned()
            .map(|service| (service.id.clone(), service))
            .collect();

        for operation in operations {
            match operation {
                IdentityOperation::AddMethod { method } => {
                    validate_verification_method(method)?;
                    if verification_methods
                        .insert(method.id.clone(), method.clone())
                        .is_some()
                    {
                        return Err(Error::DuplicateMethod(method.id.clone()));
                    }
                }
                IdentityOperation::RemoveMethod { id } => {
                    if verification_methods.remove(id).is_none() {
                        return Err(Error::UndefinedRemovalTarget(id.clone()));
                    }
                }
                IdentityOperation::SetMethodPurposes { id, purposes } => {
                    reject_duplicates(purposes, "verificationMethods.purposes")?;
                    validate_sorted_unique_nonempty(purposes, "verificationMethods.purposes")?;
                    let method = verification_methods
                        .get_mut(id)
                        .ok_or_else(|| Error::MissingMethod(id.clone()))?;
                    method.purposes = purposes.clone();
                }
                IdentityOperation::AddAdministrationController { did } => {
                    validate_did(did)?;
                    if administration_controllers.insert(did.clone(), ()).is_some() {
                        return Err(Error::DuplicateAdministrationController(did.clone()));
                    }
                }
                IdentityOperation::RemoveAdministrationController { did } => {
                    if administration_controllers.remove(did).is_none() {
                        return Err(Error::UndefinedRemovalTarget(did.clone()));
                    }
                }
                IdentityOperation::AddRecoveryController { did } => {
                    if !allow_recovery {
                        return Err(Error::RecoveryOperationInAdministration);
                    }
                    validate_did(did)?;
                    if recovery_controllers.insert(did.clone(), ()).is_some() {
                        return Err(Error::DuplicateRecoveryController(did.clone()));
                    }
                }
                IdentityOperation::RemoveRecoveryController { did } => {
                    if !allow_recovery {
                        return Err(Error::RecoveryOperationInAdministration);
                    }
                    if recovery_controllers.remove(did).is_none() {
                        return Err(Error::UndefinedRemovalTarget(did.clone()));
                    }
                }
                IdentityOperation::AddService { service } => {
                    validate_service(service)?;
                    if services
                        .insert(service.id.clone(), service.clone())
                        .is_some()
                    {
                        return Err(Error::DuplicateService(service.id.clone()));
                    }
                }
                IdentityOperation::RemoveService { id } => {
                    if services.remove(id).is_none() {
                        return Err(Error::UndefinedRemovalTarget(id.clone()));
                    }
                }
            }
        }

        if administration_controllers.is_empty() {
            return Err(Error::NoAdministrationControllers);
        }
        if recovery_controllers.is_empty() {
            return Err(Error::NoRecoveryControllers);
        }

        Ok(Self {
            did: self.did.clone(),
            genesis: self.genesis.clone(),
            event,
            sequence: self
                .sequence
                .checked_add(1)
                .ok_or(Error::SequenceOverflow)?,
            recovery_parent,
            recovery_epoch,
            recovery_controllers: recovery_controllers.into_keys().collect(),
            administration_controllers: administration_controllers.into_keys().collect(),
            verification_methods: verification_methods.into_values().collect(),
            services: services.into_values().collect(),
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("an identity update must contain at least one operation")]
    EmptyOperations,
    #[error("administration cannot change recovery controllers")]
    RecoveryOperationInAdministration,
    #[error("administration must retain at least one administration controller")]
    NoAdministrationControllers,
    #[error("recovery must retain at least one recovery controller")]
    NoRecoveryControllers,
    #[error("identity sequence overflow")]
    SequenceOverflow,
    #[error("verification method already exists: {0}")]
    DuplicateMethod(String),
    #[error("verification method does not exist: {0}")]
    MissingMethod(String),
    #[error("verification method purposes must not be empty: {0}")]
    EmptyPurposes(String),
    #[error("administration controller already exists: {0}")]
    DuplicateAdministrationController(String),
    #[error("recovery controller already exists: {0}")]
    DuplicateRecoveryController(String),
    #[error("service already exists: {0}")]
    DuplicateService(String),
    #[error("identity operation removes an absent target: {0}")]
    UndefinedRemovalTarget(String),
    #[error("identity states do not belong to the same did:kan history")]
    IdentityMismatch,
    #[error("recoveryParent is not the recovery authority for previous")]
    RecoveryParentMismatch,
    #[error("recovery epoch {found} must be greater than previous epoch {previous}")]
    RecoveryEpoch { previous: u64, found: u64 },
    #[error(transparent)]
    Genesis(#[from] super::did_kan::Error),
    #[error(transparent)]
    Control(#[from] super::control::Error),
}

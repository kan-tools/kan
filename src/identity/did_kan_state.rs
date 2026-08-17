//! Wire-independent RFC 1 `did:kan` state transitions.
//!
//! RFC 1 issue #244 tracks the missing canonical DAG-CBOR encoding for
//! `IdentityOperation`. Keeping this layer free of serde makes the transition
//! semantics usable without accidentally fixing a signed wire representation.

use std::collections::BTreeMap;

use atproto_dasl::Cid;

use super::did_kan::{
    reject_duplicates, validate_did, validate_service, validate_verification_method, DidKanGenesis,
    Service, VerificationMethod, VerificationPurpose,
};

/// One closed RFC 1 identity-state operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityOperation {
    AddMethod(VerificationMethod),
    RemoveMethod(String),
    SetMethodPurposes {
        id: String,
        purposes: Vec<VerificationPurpose>,
    },
    AddAdministrationController(String),
    RemoveAdministrationController(String),
    AddRecoveryController(String),
    RemoveRecoveryController(String),
    AddService(Service),
    RemoveService(String),
}

/// The complete state produced by one recognized `did:kan` event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidKanState {
    pub did: String,
    pub event: Cid,
    pub sequence: u64,
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
        Ok(Self {
            did: genesis.did()?,
            event: genesis.signing_input()?.logical_cid()?,
            sequence: 0,
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
        if operations.is_empty() {
            return Err(Error::EmptyOperations);
        }

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
                IdentityOperation::AddMethod(method) => {
                    validate_verification_method(method)?;
                    if verification_methods
                        .insert(method.id.clone(), method.clone())
                        .is_some()
                    {
                        return Err(Error::DuplicateMethod(method.id.clone()));
                    }
                }
                IdentityOperation::RemoveMethod(id) => {
                    if verification_methods.remove(id).is_none() {
                        return Err(Error::UndefinedRemovalTarget(id.clone()));
                    }
                }
                IdentityOperation::SetMethodPurposes { id, purposes } => {
                    reject_duplicates(purposes, "verificationMethods.purposes")?;
                    let mut purposes = purposes.clone();
                    purposes.sort();
                    if purposes.is_empty() {
                        return Err(Error::EmptyPurposes(id.clone()));
                    }
                    let method = verification_methods
                        .get_mut(id)
                        .ok_or_else(|| Error::MissingMethod(id.clone()))?;
                    method.purposes = purposes;
                }
                IdentityOperation::AddAdministrationController(did) => {
                    validate_did(did)?;
                    if administration_controllers.insert(did.clone(), ()).is_some() {
                        return Err(Error::DuplicateAdministrationController(did.clone()));
                    }
                }
                IdentityOperation::RemoveAdministrationController(did) => {
                    if administration_controllers.remove(did).is_none() {
                        return Err(Error::UndefinedRemovalTarget(did.clone()));
                    }
                }
                IdentityOperation::AddRecoveryController(_)
                | IdentityOperation::RemoveRecoveryController(_) => {
                    return Err(Error::RecoveryOperationInAdministration);
                }
                IdentityOperation::AddService(service) => {
                    validate_service(service)?;
                    if services
                        .insert(service.id.clone(), service.clone())
                        .is_some()
                    {
                        return Err(Error::DuplicateService(service.id.clone()));
                    }
                }
                IdentityOperation::RemoveService(id) => {
                    if services.remove(id).is_none() {
                        return Err(Error::UndefinedRemovalTarget(id.clone()));
                    }
                }
            }
        }

        if administration_controllers.is_empty() {
            return Err(Error::NoAdministrationControllers);
        }

        Ok(Self {
            did: self.did.clone(),
            event,
            sequence: self
                .sequence
                .checked_add(1)
                .ok_or(Error::SequenceOverflow)?,
            recovery_epoch: self.recovery_epoch,
            recovery_controllers: self.recovery_controllers.clone(),
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
    #[error("service already exists: {0}")]
    DuplicateService(String),
    #[error("RFC 1 does not yet define removal of an absent target: {0}")]
    UndefinedRemovalTarget(String),
    #[error(transparent)]
    Genesis(#[from] super::did_kan::Error),
    #[error(transparent)]
    Control(#[from] super::control::Error),
}

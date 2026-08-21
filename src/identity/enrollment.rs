//! Daily-device enrollment for a fresh RFC 1 `did:kan` principal.

use atproto_dasl::Cid;

use super::{
    control::{ControlEvent, IdentityVersion, Proof, SigningInput},
    did_kan::{DidKanGenesis, VerificationMethod, VerificationPurpose},
    did_kan_state::{DidKanState, IdentityOperation},
    did_kan_update::DidKanUpdate,
    ledger::IdentityLedger,
    system::{CredentialReference, IdentityProfile, SystemIdentityStore},
};
use crate::sign::Identity;

/// A complete, deterministic enrollment plan. It contains public events and
/// local profile configuration, never either private key.
#[derive(Debug, Clone)]
pub struct DailyDeviceEnrollment {
    genesis: DidKanGenesis,
    genesis_event: ControlEvent,
    administration_event: ControlEvent,
    recovery_method: VerificationMethod,
    recovery_profile: IdentityProfile,
    daily_method: VerificationMethod,
    profile: IdentityProfile,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledDailyDevice {
    pub principal: String,
    pub genesis_event: Cid,
    pub administration_event: Cid,
}

impl DailyDeviceEnrollment {
    /// Build a fresh human principal controlled initially by `recovery`, then
    /// enroll `daily` in the mandatory first administration state. The
    /// credential reference is configuration only and is not accessed here.
    pub fn new(
        nonce: [u8; 32],
        alias: String,
        recovery: &Identity,
        recovery_credential: CredentialReference,
        daily: &Identity,
        daily_credential: CredentialReference,
    ) -> Result<Self, Error> {
        let recovery_did = recovery.did();
        let genesis = DidKanGenesis::new(
            nonce,
            vec![recovery_did.clone()],
            vec![recovery_did],
            vec![],
            vec![],
        )?;
        let genesis_input = genesis.signing_input()?;
        let genesis_event = genesis.proved_event(vec![static_proof(recovery, &genesis_input)?])?;
        let genesis_state = DidKanState::from_genesis(&genesis)?;

        let recovery_method = static_method(
            recovery,
            vec![
                VerificationPurpose::Administration,
                VerificationPurpose::Recovery,
            ],
        )?;
        let recovery_profile = IdentityProfile::new(
            "recovery-bootstrap".to_string(),
            super::system::ActorReference::new(
                recovery_method.controller.clone(),
                recovery_method.id.clone(),
                IdentityVersion::Static,
            )?,
            recovery_credential,
        )?;

        let principal = genesis_state.did.clone();
        let daily_method = daily_method(&principal, daily)?;
        let administration = DidKanUpdate::administration(
            &genesis_state,
            vec![IdentityOperation::AddMethod {
                method: daily_method.clone(),
            }],
        )?;
        let administration_input = administration.signing_input()?;
        let administration_event =
            administration.proved_event(vec![static_proof(recovery, &administration_input)?])?;
        let profile = IdentityProfile::new(
            alias,
            super::system::ActorReference::new(
                principal,
                daily_method.id.clone(),
                IdentityVersion::Event(administration.resulting_state().event.clone()),
            )?,
            daily_credential,
        )?;

        Ok(Self {
            genesis,
            genesis_event,
            administration_event,
            recovery_method,
            recovery_profile,
            daily_method,
            profile,
        })
    }

    pub fn genesis(&self) -> &DidKanGenesis {
        &self.genesis
    }

    pub fn genesis_event(&self) -> &ControlEvent {
        &self.genesis_event
    }

    pub fn administration_event(&self) -> &ControlEvent {
        &self.administration_event
    }

    pub fn daily_method(&self) -> &VerificationMethod {
        &self.daily_method
    }

    pub fn recovery_method(&self) -> &VerificationMethod {
        &self.recovery_method
    }

    pub fn profile(&self) -> &IdentityProfile {
        &self.profile
    }

    /// Install an enrollment whose referenced credential already exists.
    /// The credential is exercised first, both public events are installed
    /// next, and the default profile is selected last. Therefore any returned
    /// error leaves no newly selectable, partially initialized actor.
    pub fn install(&self, config_root: &std::path::Path) -> Result<InstalledDailyDevice, Error> {
        let store = SystemIdentityStore::at(config_root);
        let ledger = IdentityLedger::at(config_root.join("identity").join("ledger"));
        let challenge = self.genesis.signing_input()?;
        store.initialize_with(&self.profile, || {
            // Prove possession and exact method correspondence before
            // publishing identity state. The proof is discarded: it
            // authenticates this installation, not a protocol event.
            store.sign(&self.recovery_profile, &self.recovery_method, &challenge)?;
            store.sign(&self.profile, &self.daily_method, &challenge)?;
            ledger.append(&self.genesis_event)?;
            ledger.append(&self.administration_event)?;
            Ok(())
        })?;
        Ok(InstalledDailyDevice {
            principal: self.profile.principal().to_string(),
            genesis_event: self.genesis_event.proved_cid()?,
            administration_event: self.administration_event.proved_cid()?,
        })
    }
}

fn static_proof(identity: &Identity, input: &SigningInput) -> Result<Proof, Error> {
    let did = identity.did();
    Ok(Proof {
        method: format!("{did}#{}", did.strip_prefix("did:key:").unwrap_or_default()),
        controller_state: IdentityVersion::Static,
        alg: "P256".to_string(),
        sig: identity.sign(&input.canonical_bytes()?)?,
    })
}

fn static_method(
    identity: &Identity,
    purposes: Vec<VerificationPurpose>,
) -> Result<VerificationMethod, Error> {
    let did = identity.did();
    let fingerprint = did
        .strip_prefix("did:key:")
        .ok_or_else(|| Error::DailyKey(did.clone()))?;
    let (_, multikey) =
        atrium_crypto::multibase::decode(fingerprint).map_err(|_| Error::DailyKey(did.clone()))?;
    let public_key = multikey
        .strip_prefix(&[0x80, 0x24])
        .ok_or_else(|| Error::DailyKey(did.clone()))?;
    Ok(VerificationMethod {
        id: format!("{did}#{fingerprint}"),
        controller: did,
        alg: "P256".to_string(),
        public_key: public_key.to_vec(),
        purposes,
    })
}

fn daily_method(principal: &str, daily: &Identity) -> Result<VerificationMethod, Error> {
    let static_method = static_method(
        daily,
        vec![
            VerificationPurpose::Administration,
            VerificationPurpose::Assertion,
            VerificationPurpose::Authentication,
            VerificationPurpose::CapabilityDelegation,
            VerificationPurpose::CapabilityInvocation,
        ],
    )?;
    let fingerprint = static_method
        .controller
        .strip_prefix("did:key:")
        .ok_or_else(|| Error::DailyKey(static_method.controller.clone()))?;
    Ok(VerificationMethod {
        id: format!("{principal}#device-{fingerprint}"),
        controller: principal.to_string(),
        alg: static_method.alg,
        public_key: static_method.public_key,
        purposes: static_method.purposes,
    })
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("daily device key is not a canonical P-256 did:key: {0}")]
    DailyKey(String),
    #[error("daily-device genesis is invalid: {0}")]
    Genesis(#[from] super::did_kan::Error),
    #[error("daily-device state is invalid: {0}")]
    State(#[from] super::did_kan_state::Error),
    #[error("daily-device administration is invalid: {0}")]
    Update(#[from] super::did_kan_update::Error),
    #[error("daily-device profile is invalid: {0}")]
    Profile(#[from] super::system::Error),
    #[error("daily-device signing failed: {0}")]
    Sign(#[from] crate::sign::Error),
    #[error("daily-device control event is invalid: {0}")]
    Control(#[from] super::control::Error),
}

//! RFC 1 `did:kan` genesis payload and self-certifying identifier.

use std::collections::BTreeSet;

use atproto_dasl::Ipld;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    control::{verify_static_did_key_proof, ControlEvent, Proof, SigningInput},
    CryptographicValidity,
};

pub const GENESIS_DOMAIN: &str = "kan.did.genesis.v1";
pub const GENESIS_EVENT_TYPE: &str = "genesis";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum VerificationPurpose {
    Administration,
    Assertion,
    Authentication,
    CapabilityDelegation,
    CapabilityInvocation,
    Recovery,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerificationMethod {
    pub id: String,
    pub controller: String,
    pub alg: String,
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
    pub purposes: Vec<VerificationPurpose>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Service {
    pub id: String,
    #[serde(rename = "type")]
    pub service_type: String,
    pub endpoint: String,
}

/// Unsigned `did:kan` genesis payload. Its canonical bytes, not a proof or
/// proved event, derive the DID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DidKanGenesis {
    pub v: u64,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    pub recovery_epoch: u64,
    pub recovery_controllers: Vec<String>,
    pub administration_controllers: Vec<String>,
    pub verification_methods: Vec<VerificationMethod>,
    pub services: Vec<Service>,
}

impl DidKanGenesis {
    pub fn new(
        nonce: [u8; 32],
        mut recovery_controllers: Vec<String>,
        mut administration_controllers: Vec<String>,
        mut verification_methods: Vec<VerificationMethod>,
        mut services: Vec<Service>,
    ) -> Result<Self, Error> {
        reject_duplicates(&recovery_controllers, "recoveryControllers")?;
        reject_duplicates(&administration_controllers, "administrationControllers")?;
        reject_duplicate_keys(
            verification_methods.iter().map(|method| &method.id),
            "verificationMethods.id",
        )?;
        reject_duplicate_keys(services.iter().map(|service| &service.id), "services.id")?;
        recovery_controllers.sort();
        administration_controllers.sort();
        verification_methods.sort_by(|left, right| left.id.cmp(&right.id));
        services.sort_by(|left, right| left.id.cmp(&right.id));
        for method in &mut verification_methods {
            reject_duplicates(&method.purposes, "verificationMethods.purposes")?;
            method.purposes.sort();
        }
        let genesis = Self {
            v: 1,
            nonce: nonce.to_vec(),
            recovery_epoch: 0,
            recovery_controllers,
            administration_controllers,
            verification_methods,
            services,
        };
        genesis.validate()?;
        Ok(genesis)
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.v != 1 {
            return Err(Error::UnsupportedVersion(self.v));
        }
        if self.nonce.len() != 32 {
            return Err(Error::NonceLength(self.nonce.len()));
        }
        if self.recovery_epoch != 0 {
            return Err(Error::RecoveryEpoch(self.recovery_epoch));
        }
        validate_sorted_unique_nonempty(&self.recovery_controllers, "recoveryControllers")?;
        validate_sorted_unique_nonempty(
            &self.administration_controllers,
            "administrationControllers",
        )?;
        for controller in &self.recovery_controllers {
            if !is_rfc1_did_key(controller) {
                return Err(Error::RecoveryController(controller.clone()));
            }
        }
        for controller in &self.administration_controllers {
            validate_did(controller)?;
        }

        validate_key_order(
            self.verification_methods.iter().map(|method| &method.id),
            "verificationMethods",
        )?;
        for method in &self.verification_methods {
            validate_verification_method(method)?;
        }

        validate_key_order(self.services.iter().map(|service| &service.id), "services")?;
        for service in &self.services {
            validate_service(service)?;
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        Ok(atproto_dasl::to_vec(self)?)
    }

    pub fn did(&self) -> Result<String, Error> {
        let digest = Sha256::digest(self.canonical_bytes()?);
        let mut multihash = Vec::with_capacity(34);
        multihash.extend_from_slice(&[0x12, 0x20]);
        multihash.extend_from_slice(&digest);
        let encoded = atrium_crypto::multibase::encode(
            atrium_crypto::multibase::Base::Base32Lower,
            multihash,
        );
        Ok(format!("did:kan:{encoded}"))
    }

    pub fn signing_input(&self) -> Result<SigningInput, Error> {
        self.validate()?;
        let payload: Ipld = atproto_dasl::from_reader(&self.canonical_bytes()?[..])?;
        Ok(SigningInput::new(
            GENESIS_DOMAIN,
            GENESIS_EVENT_TYPE,
            payload,
        )?)
    }

    pub fn proved_event(&self, proofs: Vec<Proof>) -> Result<ControlEvent, Error> {
        let input = self.signing_input()?;
        let authorized = proofs.iter().any(|proof| {
            let controller = proof.method.split_once('#').map(|(did, _)| did);
            controller.is_some_and(|did| {
                self.recovery_controllers
                    .binary_search_by(|candidate| candidate.as_str().cmp(did))
                    .is_ok()
                    && verify_static_did_key_proof(&input, proof) == CryptographicValidity::Valid
            })
        });
        if !authorized {
            return Err(Error::NoRecoveryProof);
        }
        Ok(ControlEvent::new(input, proofs)?)
    }
}

pub(super) fn validate_sorted_unique_nonempty<T: Ord>(
    values: &[T],
    field: &'static str,
) -> Result<(), Error> {
    if values.is_empty() {
        return Err(Error::Empty(field));
    }
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(Error::NotSortedUnique(field));
    }
    Ok(())
}

fn validate_key_order<'a>(
    values: impl Iterator<Item = &'a String>,
    field: &'static str,
) -> Result<(), Error> {
    let values: Vec<&String> = values.collect();
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(Error::NotSortedUnique(field));
    }
    Ok(())
}

pub(super) fn reject_duplicates<T: Ord + Clone>(
    values: &[T],
    field: &'static str,
) -> Result<(), Error> {
    let mut seen = BTreeSet::new();
    if values.iter().any(|value| !seen.insert(value.clone())) {
        return Err(Error::Duplicate(field));
    }
    Ok(())
}

fn reject_duplicate_keys<'a>(
    values: impl Iterator<Item = &'a String>,
    field: &'static str,
) -> Result<(), Error> {
    let mut seen = BTreeSet::new();
    if values.into_iter().any(|value| !seen.insert(value.clone())) {
        return Err(Error::Duplicate(field));
    }
    Ok(())
}

pub(super) fn validate_did(did: &str) -> Result<(), Error> {
    let Some(rest) = did.strip_prefix("did:") else {
        return Err(Error::Did(did.to_string()));
    };
    let Some((method, identifier)) = rest.split_once(':') else {
        return Err(Error::Did(did.to_string()));
    };
    if method.is_empty() || identifier.is_empty() || did.contains('#') {
        return Err(Error::Did(did.to_string()));
    }
    Ok(())
}

fn validate_did_url(url: &str) -> Result<(), Error> {
    let Some((did, fragment)) = url.split_once('#') else {
        return Err(Error::DidUrl(url.to_string()));
    };
    validate_did(did)?;
    if fragment.is_empty() || fragment.contains('#') {
        return Err(Error::DidUrl(url.to_string()));
    }
    Ok(())
}

pub(super) fn validate_verification_method(method: &VerificationMethod) -> Result<(), Error> {
    validate_did_url(&method.id)?;
    validate_did(&method.controller)?;
    match method.alg.as_str() {
        "Ed25519" if method.public_key.len() == 32 => {}
        "P256"
            if method.public_key.len() == 33
                && atrium_crypto::did::format_did_key(
                    atrium_crypto::Algorithm::P256,
                    &method.public_key,
                )
                .is_ok() => {}
        "Ed25519" | "P256" => {
            return Err(Error::PublicKeyLength {
                alg: method.alg.clone(),
                found: method.public_key.len(),
            });
        }
        _ => return Err(Error::Algorithm(method.alg.clone())),
    }
    validate_sorted_unique_nonempty(&method.purposes, "verificationMethods.purposes")
}

pub(super) fn validate_service(service: &Service) -> Result<(), Error> {
    validate_did_url(&service.id)?;
    if service.service_type.is_empty() {
        return Err(Error::EmptyServiceType);
    }
    if service.endpoint.is_empty() {
        return Err(Error::EmptyServiceEndpoint);
    }
    Ok(())
}

fn is_rfc1_did_key(did: &str) -> bool {
    let Some(fingerprint) = did.strip_prefix("did:key:") else {
        return false;
    };
    let Ok((base, bytes)) = atrium_crypto::multibase::decode(fingerprint) else {
        return false;
    };
    if base != atrium_crypto::multibase::Base::Base58Btc {
        return false;
    }
    match bytes.as_slice() {
        [0xed, 0x01, key @ ..] => key.len() == 32,
        [0x80, 0x24, key @ ..] => key.len() == 33 && atrium_crypto::did::parse_did_key(did).is_ok(),
        _ => false,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unsupported did:kan genesis version {0}")]
    UnsupportedVersion(u64),
    #[error("did:kan nonce must be exactly 32 bytes, found {0}")]
    NonceLength(usize),
    #[error("did:kan genesis recoveryEpoch must be 0, found {0}")]
    RecoveryEpoch(u64),
    #[error("{0} must not be empty")]
    Empty(&'static str),
    #[error("{0} must be sorted and duplicate-free")]
    NotSortedUnique(&'static str),
    #[error("{0} contains a duplicate")]
    Duplicate(&'static str),
    #[error("genesis recovery controller is not a canonical RFC1 did:key: {0}")]
    RecoveryController(String),
    #[error("invalid canonical DID: {0}")]
    Did(String),
    #[error("invalid absolute DID URL: {0}")]
    DidUrl(String),
    #[error("unsupported verification algorithm: {0}")]
    Algorithm(String),
    #[error("{alg} public key has {found} bytes")]
    PublicKeyLength { alg: String, found: usize },
    #[error("service type must not be empty")]
    EmptyServiceType,
    #[error("service endpoint must not be empty")]
    EmptyServiceEndpoint,
    #[error("did:kan genesis needs a valid proof from a listed recovery controller")]
    NoRecoveryProof,
    #[error(transparent)]
    Encode(#[from] atproto_dasl::EncodeError),
    #[error(transparent)]
    Decode(#[from] atproto_dasl::DecodeError),
    #[error(transparent)]
    Control(#[from] super::control::Error),
}

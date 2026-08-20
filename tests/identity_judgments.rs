use std::collections::HashMap;

use kan::{
    cid,
    claim::{Anchor, AuthorId, Claim, ClaimBody, ClaimContent, Rkey, SubjectRef},
    fold::TrustBase,
    identity::{
        evaluate_legacy_claim, scope_admission, AdmissionFacts, CapabilityEvidence,
        CryptographicValidity, GovernanceResolution, IdentityStateStanding, RevocationStanding,
        ScopeAdmission, TrustedTime, ViewTrust,
    },
    sign::Identity,
};

fn signed_legacy(identity: &Identity) -> Claim {
    let content = ClaimContent {
        author: AuthorId {
            did: identity.did(),
            agent: None,
        },
        workspace: Anchor::Workspace("legacy-workspace".to_string()),
        subject: SubjectRef::Local(Rkey::from("identity-kernel")),
        body: ClaimBody::Observation {
            text: "preserved legacy evidence".to_string(),
        },
        cites: vec![],
        artifacts: vec![],
        recorded_at: None,
    };
    let content_cid = cid::content_cid(&content).unwrap();
    let sig = identity.sign(&content_cid.to_bytes()).unwrap();
    Claim { content, sig }
}

fn admitted_facts() -> AdmissionFacts {
    AdmissionFacts {
        scope_scoped: true,
        cryptographic_validity: CryptographicValidity::Valid,
        identity_standing: IdentityStateStanding::Active,
        identity_checkpoint: false,
        governance: GovernanceResolution::Active,
        trusted_time: TrustedTime::Available,
        revocation: RevocationStanding::Clear,
        capability: CapabilityEvidence::CompleteWithCoveringPath,
    }
}

#[test]
fn admission_table_is_ordered_and_total_over_each_failure_class() {
    let cases = [
        (
            AdmissionFacts {
                scope_scoped: false,
                cryptographic_validity: CryptographicValidity::Invalid,
                ..admitted_facts()
            },
            ScopeAdmission::NotApplicable,
        ),
        (
            AdmissionFacts {
                cryptographic_validity: CryptographicValidity::Invalid,
                identity_standing: IdentityStateStanding::Contested,
                ..admitted_facts()
            },
            ScopeAdmission::Unadmitted,
        ),
        (
            AdmissionFacts {
                cryptographic_validity: CryptographicValidity::Unsupported,
                ..admitted_facts()
            },
            ScopeAdmission::Unknown,
        ),
        (
            AdmissionFacts {
                cryptographic_validity: CryptographicValidity::Unknown,
                ..admitted_facts()
            },
            ScopeAdmission::Unknown,
        ),
        (
            AdmissionFacts {
                identity_standing: IdentityStateStanding::Unknown,
                ..admitted_facts()
            },
            ScopeAdmission::Unknown,
        ),
        (
            AdmissionFacts {
                identity_standing: IdentityStateStanding::Contested,
                ..admitted_facts()
            },
            ScopeAdmission::Contested,
        ),
        (
            AdmissionFacts {
                identity_checkpoint: true,
                ..admitted_facts()
            },
            ScopeAdmission::Unadmitted,
        ),
        (
            AdmissionFacts {
                identity_standing: IdentityStateStanding::Superseded,
                ..admitted_facts()
            },
            ScopeAdmission::Unadmitted,
        ),
        (
            AdmissionFacts {
                governance: GovernanceResolution::UnknownHistory,
                ..admitted_facts()
            },
            ScopeAdmission::Unknown,
        ),
        (
            AdmissionFacts {
                governance: GovernanceResolution::Unsupported,
                ..admitted_facts()
            },
            ScopeAdmission::Unknown,
        ),
        (
            AdmissionFacts {
                governance: GovernanceResolution::Contested,
                ..admitted_facts()
            },
            ScopeAdmission::Contested,
        ),
        (
            AdmissionFacts {
                governance: GovernanceResolution::Invalid,
                ..admitted_facts()
            },
            ScopeAdmission::Unadmitted,
        ),
        (
            AdmissionFacts {
                trusted_time: TrustedTime::Unavailable,
                ..admitted_facts()
            },
            ScopeAdmission::Unknown,
        ),
        (
            AdmissionFacts {
                revocation: RevocationStanding::Unknown,
                ..admitted_facts()
            },
            ScopeAdmission::Unknown,
        ),
        (
            AdmissionFacts {
                revocation: RevocationStanding::Contested,
                ..admitted_facts()
            },
            ScopeAdmission::Contested,
        ),
        (
            AdmissionFacts {
                capability: CapabilityEvidence::Missing,
                ..admitted_facts()
            },
            ScopeAdmission::Unknown,
        ),
        (
            AdmissionFacts {
                capability: CapabilityEvidence::CompleteWithoutCoveringPath,
                ..admitted_facts()
            },
            ScopeAdmission::Unadmitted,
        ),
        (admitted_facts(), ScopeAdmission::Admitted),
    ];

    for (facts, expected) in cases {
        assert_eq!(scope_admission(facts), expected, "facts: {facts:?}");
    }
}

#[test]
fn legacy_claim_keeps_validity_standing_admission_and_trust_separate() {
    let identity = Identity::generate();
    let claim = signed_legacy(&identity);
    let trust = TrustBase::solo(claim.content.author.clone());

    let result = evaluate_legacy_claim(&claim, &trust);
    assert_eq!(result.cryptographic_validity, CryptographicValidity::Valid);
    assert_eq!(
        result.identity_state_standing,
        IdentityStateStanding::Static
    );
    assert_eq!(result.scope_admission, ScopeAdmission::Unknown);
    assert_eq!(result.view_trust, ViewTrust::Included);
}

#[test]
fn invalid_signature_does_not_change_static_standing_or_view_trust() {
    let identity = Identity::generate();
    let mut claim = signed_legacy(&identity);
    claim.content.body = ClaimBody::Observation {
        text: "tampered".to_string(),
    };
    let trust = TrustBase::solo(claim.content.author.clone());

    let result = evaluate_legacy_claim(&claim, &trust);
    assert_eq!(
        result.cryptographic_validity,
        CryptographicValidity::Invalid
    );
    assert_eq!(
        result.identity_state_standing,
        IdentityStateStanding::Static
    );
    assert_eq!(result.scope_admission, ScopeAdmission::Unadmitted);
    assert_eq!(result.view_trust, ViewTrust::Included);
}

#[test]
fn consumer_weight_is_reported_without_becoming_admission() {
    let identity = Identity::generate();
    let claim = signed_legacy(&identity);
    let trust = TrustBase::peer_contested(HashMap::from([(claim.content.author.clone(), 0.25)]));

    let result = evaluate_legacy_claim(&claim, &trust);
    assert_eq!(result.scope_admission, ScopeAdmission::Unknown);
    assert_eq!(result.view_trust, ViewTrust::Weighted(0.25));
}

#[test]
fn unsupported_did_method_is_not_misreported_as_a_bad_signature() {
    let identity = Identity::generate();
    let mut claim = signed_legacy(&identity);
    claim.content.author.did = "did:future:alice".to_string();
    let trust = TrustBase::solo(claim.content.author.clone());

    let result = evaluate_legacy_claim(&claim, &trust);
    assert_eq!(
        result.cryptographic_validity,
        CryptographicValidity::Unsupported
    );
    assert_eq!(
        result.identity_state_standing,
        IdentityStateStanding::Unknown
    );
    assert_eq!(result.scope_admission, ScopeAdmission::Unknown);
}

#[test]
fn malformed_did_key_is_invalid_and_has_no_static_standing() {
    let identity = Identity::generate();
    let mut claim = signed_legacy(&identity);
    claim.content.author.did = "did:key:not-multibase".to_string();
    let trust = TrustBase::solo(claim.content.author.clone());

    let result = evaluate_legacy_claim(&claim, &trust);
    assert_eq!(
        result.cryptographic_validity,
        CryptographicValidity::Invalid
    );
    assert_eq!(
        result.identity_state_standing,
        IdentityStateStanding::Unknown
    );
    assert_eq!(result.scope_admission, ScopeAdmission::Unadmitted);
}

#[test]
fn judgments_have_stable_rfc1_json_names() {
    let value = serde_json::to_value(evaluate_legacy_claim(
        &signed_legacy(&Identity::generate()),
        &TrustBase::local([]),
    ))
    .unwrap();

    assert_eq!(value["cryptographicValidity"], "valid");
    assert_eq!(value["identityStateStanding"], "static");
    assert_eq!(value["scopeAdmission"], "unknown");
    assert_eq!(value["viewTrust"], "excluded");
}

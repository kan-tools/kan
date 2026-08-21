use atproto_dasl::Ipld;
use kan::{
    claim::{
        codec::{self, DecodedClaim, SupportedClaim, VerificationContext},
        CanonicalSet, Claim, ClaimBody, ClaimContent, ClaimSigningInput, NarrativeText, RecordedAt,
        SubjectPath, UniqueSequence,
    },
    identity::{
        authorship::Author,
        control::IdentityVersion,
        did_kan::VerificationPurpose,
        enrollment::DailyDeviceEnrollment,
        system::{CredentialReference, SystemIdentityStore},
        CryptographicValidity,
    },
    sign::Identity,
};

fn current_content(author: Author, text: &str) -> ClaimContent {
    let mut scope = [0_u8; 34];
    scope[..2].copy_from_slice(&[0x12, 0x20]);
    ClaimContent::new(
        author,
        kan::identity::scope_inception::ScopeId::from_bytes(scope).unwrap(),
        None,
        SubjectPath::new("identity/authorship".to_string()).unwrap(),
        CanonicalSet::new(vec![]).unwrap(),
        ClaimBody::Observation {
            text: NarrativeText::new(text.to_string()).unwrap(),
        },
        CanonicalSet::new(vec![]).unwrap(),
        UniqueSequence::new(vec![]).unwrap(),
        RecordedAt::new(1).unwrap(),
    )
    .unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn installed_actor(
    root: &std::path::Path,
) -> (
    SystemIdentityStore,
    kan::identity::system::IdentityProfile,
    kan::identity::did_kan_update::ResolvedDidKanState,
    kan::identity::did_kan::VerificationMethod,
) {
    let recovery = Identity::generate();
    let daily = Identity::generate();
    recovery
        .save(&root.join("credentials").join("recovery.key"))
        .unwrap();
    daily
        .save(&root.join("credentials").join("daily.key"))
        .unwrap();
    let enrollment = DailyDeviceEnrollment::new(
        [0x71; 32],
        "daily".to_string(),
        &recovery,
        CredentialReference::OwnerOnlyFile {
            path: "recovery.key".to_string(),
        },
        &daily,
        CredentialReference::OwnerOnlyFile {
            path: "daily.key".to_string(),
        },
    )
    .unwrap();
    enrollment.install(root).unwrap();
    let store = SystemIdentityStore::at(root);
    let profile = store.default_profile().unwrap().unwrap();
    let (state, method) = store.resolve_profile_method(&profile).unwrap();
    (store, profile, state, method)
}

#[test]
fn fixed_author_vector_pins_the_exact_typed_map() {
    let principal = "did:kan:bciqmjeylstwnlm7bwtqgfe3somb7dl2n45pmm636dj747olz6jdek2a".to_string();
    let author = Author::new(
        principal.clone(),
        format!("{principal}#daily"),
        IdentityVersion::Event(
            "bafyreiec2aamsiue2cy5uqgdbxln4fvwywhk3735cwmsrav3jsfgi4ziou"
                .parse()
                .unwrap(),
        ),
    )
    .unwrap();

    assert_eq!(
        hex(&author.canonical_bytes().unwrap()),
        "a3697072696e636970616c78406469643a6b616e3a626369716d6a65796c7374776e6c6d376277747167666533736f6d6237646c326e3435706d6d363336646a3734376f6c7a366a64656b32616f6964656e7469747956657273696f6ea2646b696e64656576656e746576616c7565d82a5825000171122082d000c92284d0b1da40c30dd6de16b6c58eadff7d15992882bb4c8a6473287572766572696669636174696f6e4d6574686f6478466469643a6b616e3a626369716d6a65796c7374776e6c6d376277747167666533736f6d6237646c326e3435706d6d363336646a3734376f6c7a366a64656b3261236461696c79"
    );
}

#[test]
fn author_shape_cannot_represent_a_role_or_legacy_agent() {
    let temp = tempfile::tempdir().unwrap();
    let (_, profile, _, _) = installed_actor(temp.path());
    let author = Author::new(
        profile.principal().to_string(),
        profile.actor().verification_method().to_string(),
        profile.actor().controller_state().clone(),
    )
    .unwrap();
    let mut raw: Ipld = atproto_dasl::from_reader(&author.canonical_bytes().unwrap()[..]).unwrap();
    let Ipld::Map(fields) = &mut raw else {
        unreachable!();
    };
    assert_eq!(
        fields.keys().map(String::as_str).collect::<Vec<_>>(),
        ["identityVersion", "principal", "verificationMethod"]
    );
    fields.insert("role".to_string(), Ipld::String("maintainer".to_string()));
    let decoded: Result<Author, _> =
        atproto_dasl::from_reader(&atproto_dasl::to_vec(&raw).unwrap()[..]);
    assert!(decoded.is_err());
}

#[test]
fn system_profile_signs_a_current_claim_as_its_exact_active_method() {
    let temp = tempfile::tempdir().unwrap();
    let (store, profile, state, method) = installed_actor(temp.path());
    let author = Author::new(
        profile.principal().to_string(),
        profile.actor().verification_method().to_string(),
        profile.actor().controller_state().clone(),
    )
    .unwrap();
    let claim = store
        .sign_claim(
            &profile,
            &method,
            current_content(author.clone(), "current claim signing vector"),
        )
        .unwrap();
    let id = claim.id().unwrap();
    let input = ClaimSigningInput::new(&id).canonical_bytes().unwrap();

    let verified =
        author.verify_active_did_kan_message(&input, claim.signature().as_bytes(), &state);
    assert_eq!(
        verified.cryptographic_validity,
        CryptographicValidity::Valid
    );
    assert!(verified.scope_invocation);
    assert!(matches!(
        codec::decode(
            &codec::encode_claim(&claim, "3jzfcijpj2z2a").unwrap(),
            VerificationContext::ActiveDidKan(&state),
        )
        .unwrap(),
        DecodedClaim::Supported(SupportedClaim::Claim(decoded)) if decoded == claim
    ));
    let changed = current_content(author.clone(), "different claim")
        .id()
        .unwrap();
    let changed_input = ClaimSigningInput::new(&changed).canonical_bytes().unwrap();
    assert_eq!(
        author
            .verify_active_did_kan_message(&changed_input, claim.signature().as_bytes(), &state,)
            .cryptographic_validity,
        CryptographicValidity::Invalid
    );
}

#[test]
fn resolved_identity_context_selects_each_claims_exact_author_state() {
    let first_temp = tempfile::tempdir().unwrap();
    let second_temp = tempfile::tempdir().unwrap();
    let (first_store, first_profile, first_state, first_method) =
        installed_actor(first_temp.path());
    let (second_store, second_profile, second_state, second_method) =
        installed_actor(second_temp.path());
    let first_author = Author::new(
        first_profile.principal().to_string(),
        first_profile.actor().verification_method().to_string(),
        first_profile.actor().controller_state().clone(),
    )
    .unwrap();
    let second_author = Author::new(
        second_profile.principal().to_string(),
        second_profile.actor().verification_method().to_string(),
        second_profile.actor().controller_state().clone(),
    )
    .unwrap();
    let first = first_store
        .sign_claim(
            &first_profile,
            &first_method,
            current_content(first_author, "first resolved author"),
        )
        .unwrap();
    let second = second_store
        .sign_claim(
            &second_profile,
            &second_method,
            current_content(second_author, "second resolved author"),
        )
        .unwrap();
    let static_identity = Identity::generate();
    let static_principal = static_identity.did();
    let static_fingerprint = static_principal.strip_prefix("did:key:").unwrap();
    let static_claim = Claim::sign_static(
        current_content(
            Author::new(
                static_principal.clone(),
                format!("{static_principal}#{static_fingerprint}"),
                IdentityVersion::Static,
            )
            .unwrap(),
            "intrinsically resolved static author",
        ),
        &static_identity,
    )
    .unwrap();
    let states = [first_state, second_state];
    let verification = VerificationContext::ResolvedIdentities { did_kan: &states };

    for claim in [first, second, static_claim] {
        let decoded = codec::decode(
            &codec::encode_claim(&claim, "3jzfcijpj2z2a").unwrap(),
            verification,
        )
        .unwrap();
        assert!(matches!(
            decoded,
            DecodedClaim::Supported(SupportedClaim::Claim(decoded)) if decoded == claim
        ));
    }
}

#[test]
fn resolved_identity_context_fails_closed_when_exact_state_is_absent() {
    let temp = tempfile::tempdir().unwrap();
    let (store, profile, _state, method) = installed_actor(temp.path());
    let author = Author::new(
        profile.principal().to_string(),
        profile.actor().verification_method().to_string(),
        profile.actor().controller_state().clone(),
    )
    .unwrap();
    let claim = store
        .sign_claim(
            &profile,
            &method,
            current_content(author, "missing exact state"),
        )
        .unwrap();

    let error = codec::decode(
        &codec::encode_claim(&claim, "3jzfcijpj2z2a").unwrap(),
        VerificationContext::ResolvedIdentities { did_kan: &[] },
    )
    .unwrap_err();
    assert!(matches!(
        error,
        codec::DecodeError::Claim(kan::claim::Error::UnsupportedIdentityResolver(principal))
            if principal == profile.principal()
    ));
}

#[test]
fn assertion_and_scope_invocation_remain_separate_purpose_checks() {
    let temp = tempfile::tempdir().unwrap();
    let (store, profile, state, method) = installed_actor(temp.path());
    let author = Author::new(
        profile.principal().to_string(),
        profile.actor().verification_method().to_string(),
        profile.actor().controller_state().clone(),
    )
    .unwrap();
    let claim = store
        .sign_claim(
            &profile,
            &method,
            current_content(author.clone(), "purpose separation"),
        )
        .unwrap();
    let input = ClaimSigningInput::new(&claim.id().unwrap())
        .canonical_bytes()
        .unwrap();

    let mut no_invocation = state.clone();
    no_invocation.verification_methods[0]
        .purposes
        .retain(|purpose| *purpose != VerificationPurpose::CapabilityInvocation);
    let verified =
        author.verify_active_did_kan_message(&input, claim.signature().as_bytes(), &no_invocation);
    assert_eq!(
        verified.cryptographic_validity,
        CryptographicValidity::Valid
    );
    assert!(!verified.scope_invocation);

    let mut no_assertion = state;
    no_assertion.verification_methods[0]
        .purposes
        .retain(|purpose| *purpose != VerificationPurpose::Assertion);
    assert_eq!(
        author
            .verify_active_did_kan_message(&input, claim.signature().as_bytes(), &no_assertion,)
            .cryptographic_validity,
        CryptographicValidity::Invalid
    );
    let mut signing_method = method;
    signing_method
        .purposes
        .retain(|purpose| *purpose != VerificationPurpose::Assertion);
    assert!(store
        .sign_claim(
            &profile,
            &signing_method,
            current_content(author, "purpose separation")
        )
        .is_err());
}

#[test]
fn principal_method_and_identity_version_mismatches_fail_before_verification() {
    let principal = "did:kan:bciqmjeylstwnlm7bwtqgfe3somb7dl2n45pmm636dj747olz6jdek2a".to_string();
    assert!(Author::new(
        principal.clone(),
        "did:kan:bciqaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa#daily".to_string(),
        IdentityVersion::Event(
            "bafyreiec2aamsiue2cy5uqgdbxln4fvwywhk3735cwmsrav3jsfgi4ziou"
                .parse()
                .unwrap(),
        ),
    )
    .is_err());
    assert!(Author::new(
        principal.clone(),
        format!("{principal}#daily"),
        IdentityVersion::Static,
    )
    .is_err());
}

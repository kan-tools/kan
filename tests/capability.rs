use std::collections::HashSet;

use atproto_dasl::Ipld;
use kan::{
    cid::content_cid,
    identity::{
        capability::{
            evaluate_path, resolve as resolve_capabilities, resolve_preserved, Capability,
            Coverage, Delegation, Error, GovernanceAuthority, Revocation, CAPABILITY_DELEGATE,
            CLAIM_WRITE, DELEGATION_DOMAIN, DELEGATION_EVENT_TYPE,
        },
        control::{decode_preserving, ControlEvent, IdentityVersion, Proof, SigningInput},
        repository_inception::RepositoryInception,
        CapabilityEvidence, RevocationStanding, TrustedTime,
    },
    sign::Identity,
};

const ROOT: &str = "did:key:zDnaenWDM6qp5Ra829d9wPUzBKBA3V6fm2cg4KVP3WFKqsYTv";
const DELEGATE: &str = "did:key:zDnaeZQRXpcTkQojRMTux2jYL8UDJvJAtLdyP7V3i36KcjjZF";

fn repository(root: &str) -> String {
    RepositoryInception::new([0x61; 32], vec![], vec![root.to_string()], vec![])
        .unwrap()
        .repository_id()
        .unwrap()
}

fn authority(root: &str) -> GovernanceAuthority {
    let active = content_cid(&"active-governance").unwrap();
    let historical = content_cid(&"historical-governance").unwrap();
    GovernanceAuthority::new(
        repository(root),
        active,
        vec![root.to_string()],
        HashSet::from([historical]),
    )
    .unwrap()
}

fn proof(identity: &Identity, input: &SigningInput) -> Proof {
    Proof {
        method: format!(
            "{}#{}",
            identity.did(),
            identity.did().strip_prefix("did:key:").unwrap()
        ),
        controller_state: IdentityVersion::Static,
        alg: "P256".to_string(),
        sig: identity.sign(&input.canonical_bytes().unwrap()).unwrap(),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn capability_coverage_obeys_segment_and_time_boundaries() {
    let repository = repository(ROOT);
    let all = Capability::new(
        repository.clone(),
        None,
        vec![CLAIM_WRITE.to_string()],
        None,
        None,
        true,
    )
    .unwrap();
    assert_eq!(all.covers(CLAIM_WRITE, "anything", None), Coverage::Yes);

    let bug = Capability::new(
        repository.clone(),
        Some("bug".to_string()),
        vec![CLAIM_WRITE.to_string()],
        Some(10),
        Some(20),
        false,
    )
    .unwrap();
    assert_eq!(bug.covers(CLAIM_WRITE, "bug", Some(10)), Coverage::Yes);
    assert_eq!(bug.covers(CLAIM_WRITE, "bug/1", Some(20)), Coverage::Yes);
    assert_eq!(bug.covers(CLAIM_WRITE, "bugfix", Some(15)), Coverage::No);
    assert_eq!(bug.covers(CLAIM_WRITE, "bug", None), Coverage::UnknownTime);

    let empty = Capability::new(
        repository,
        Some(String::new()),
        vec![CLAIM_WRITE.to_string()],
        None,
        None,
        false,
    )
    .unwrap();
    assert_eq!(empty.covers(CLAIM_WRITE, "", None), Coverage::Yes);
    assert_eq!(empty.covers(CLAIM_WRITE, "/child", None), Coverage::No);
}

#[test]
fn attenuation_rejects_every_amplification_axis() {
    let repository = repository(ROOT);
    let parent = Capability::new(
        repository.clone(),
        Some("bug".to_string()),
        vec![CAPABILITY_DELEGATE.to_string(), CLAIM_WRITE.to_string()],
        Some(10),
        Some(20),
        true,
    )
    .unwrap();
    let child = Capability::new(
        repository.clone(),
        Some("bug/1".to_string()),
        vec![CLAIM_WRITE.to_string()],
        Some(11),
        Some(19),
        false,
    )
    .unwrap();
    assert!(child.attenuates(&parent).is_ok());

    let cases = [
        Capability::new(
            repository.clone(),
            Some("feature".to_string()),
            vec![CLAIM_WRITE.to_string()],
            Some(11),
            Some(19),
            false,
        )
        .unwrap(),
        Capability::new(
            repository.clone(),
            Some("bug/1".to_string()),
            vec!["role.name".to_string()],
            Some(11),
            Some(19),
            false,
        )
        .unwrap(),
        Capability::new(
            repository,
            Some("bug/1".to_string()),
            vec![CLAIM_WRITE.to_string()],
            Some(9),
            Some(21),
            false,
        )
        .unwrap(),
    ];
    assert!(matches!(
        cases[0].attenuates(&parent),
        Err(Error::SubjectAmplification)
    ));
    assert!(matches!(
        cases[1].attenuates(&parent),
        Err(Error::OperationAmplification)
    ));
    assert!(matches!(
        cases[2].attenuates(&parent),
        Err(Error::TimeAmplification)
    ));

    let nondelegable = Capability::new(
        parent.repository().to_string(),
        Some("bug".to_string()),
        vec![CAPABILITY_DELEGATE.to_string(), CLAIM_WRITE.to_string()],
        Some(10),
        Some(20),
        false,
    )
    .unwrap();
    assert!(matches!(
        child.attenuates(&nondelegable),
        Err(Error::ParentNotDelegable)
    ));
}

#[test]
fn fixed_root_delegation_vector_pins_bytes_and_logical_identifier() {
    let governance = authority(ROOT);
    let capability = Capability::new(
        governance.repository.clone(),
        Some("bug".to_string()),
        vec![CLAIM_WRITE.to_string()],
        None,
        None,
        true,
    )
    .unwrap();
    let delegation = Delegation::root(
        &governance,
        ROOT.to_string(),
        IdentityVersion::Static,
        governance.active_event.clone(),
        DELEGATE.to_string(),
        capability,
    )
    .unwrap();
    let input = delegation.signing_input().unwrap();

    assert_eq!(input.domain, DELEGATION_DOMAIN);
    assert_eq!(input.event_type, DELEGATION_EVENT_TYPE);
    assert_eq!(
        hex(&delegation.canonical_bytes().unwrap()),
        "a861760166706172656e74f6676772616e746f7278396469643a6b65793a7a446e61656e57444d36717035526138323964397750557a424b4241335636666d326367344b56503357464b71735954766864656c656761746578396469643a6b65793a7a446e61655a5152587063546b516f6a524d547578326a594c3855444a764a41744c6479503756336933364b636a6a5a466a6361706162696c697479a6686e6f744166746572f66964656c656761626c65f5696e6f744265666f7265f66a6f7065726174696f6e73816b636c61696d2e77726974656a7265706f7369746f727978416b616e2d7265706f3a62636971676134697071706172727876627833626836637962616d67786774346d377371706369377272747264346861766c68776a726a616d7375626a656374507265666978636275676a7265706f7369746f727978416b616e2d7265706f3a62636971676134697071706172727876627833626836637962616d67786774346d377371706369377272747264346861766c68776a726a616f676f7665726e616e63654576656e74d82a58250001711220f2e643cc61f942bf053831417d03e715e1f7f5639dcaa8e8bf3ce1480c3b4ebf766772616e746f724964656e7469747956657273696f6ea2646b696e64667374617469636576616c7565f6"
    );
    assert_eq!(
        input.logical_cid().unwrap().to_string(),
        "bafyreig2ib5u3olni3k2hiyslivtvboqco4pzrcztpmfld5cmzummpzixu"
    );
}

#[test]
fn delegation_proofs_bind_the_exact_grantor() {
    let root = Identity::generate();
    let stranger = Identity::generate();
    let delegate = Identity::generate();
    let governance = authority(&root.did());
    let capability = Capability::new(
        governance.repository.clone(),
        None,
        vec![CLAIM_WRITE.to_string()],
        None,
        None,
        true,
    )
    .unwrap();
    let delegation = Delegation::root(
        &governance,
        root.did(),
        IdentityVersion::Static,
        governance.active_event.clone(),
        delegate.did(),
        capability,
    )
    .unwrap();
    let input = delegation.signing_input().unwrap();

    assert!(delegation.proved_event(vec![proof(&root, &input)]).is_ok());
    assert!(matches!(
        delegation.proved_event(vec![proof(&stranger, &input)]),
        Err(Error::NoAuthorization)
    ));
}

#[test]
fn child_delegation_requires_one_attenuated_parent_path() {
    let root = Identity::generate();
    let delegate = Identity::generate();
    let child = Identity::generate();
    let governance = authority(&root.did());
    let parent = Delegation::root(
        &governance,
        root.did(),
        IdentityVersion::Static,
        governance.active_event.clone(),
        delegate.did(),
        Capability::new(
            governance.repository.clone(),
            None,
            vec![CAPABILITY_DELEGATE.to_string(), CLAIM_WRITE.to_string()],
            None,
            None,
            true,
        )
        .unwrap(),
    )
    .unwrap()
    .state()
    .unwrap();
    let delegated = Delegation::child(
        &governance,
        &parent,
        IdentityVersion::Static,
        child.did(),
        Capability::new(
            governance.repository.clone(),
            Some("bug".to_string()),
            vec![CLAIM_WRITE.to_string()],
            None,
            None,
            false,
        )
        .unwrap(),
    )
    .unwrap();
    let input = delegated.signing_input().unwrap();
    assert!(delegated
        .proved_event(vec![proof(&delegate, &input)])
        .is_ok());
}

#[test]
fn path_evaluation_distinguishes_missing_time_scope_and_revocation() {
    let root = Identity::generate();
    let delegate = Identity::generate();
    let child = Identity::generate();
    let governance = authority(&root.did());
    let parent = Delegation::root(
        &governance,
        root.did(),
        IdentityVersion::Static,
        governance.active_event.clone(),
        delegate.did(),
        Capability::new(
            governance.repository.clone(),
            None,
            vec![CAPABILITY_DELEGATE.to_string(), CLAIM_WRITE.to_string()],
            None,
            None,
            true,
        )
        .unwrap(),
    )
    .unwrap()
    .state()
    .unwrap();
    let head = Delegation::child(
        &governance,
        &parent,
        IdentityVersion::Static,
        child.did(),
        Capability::new(
            governance.repository.clone(),
            Some("bug".to_string()),
            vec![CLAIM_WRITE.to_string()],
            Some(10),
            Some(20),
            false,
        )
        .unwrap(),
    )
    .unwrap()
    .state()
    .unwrap();
    let path = [parent.clone(), head.clone()];

    let admitted = evaluate_path(
        &governance,
        &head.event,
        &path,
        &[],
        CLAIM_WRITE,
        "bug/1",
        Some(15),
    );
    assert_eq!(
        admitted.capability,
        CapabilityEvidence::CompleteWithCoveringPath
    );
    assert_eq!(admitted.trusted_time, TrustedTime::Available);

    let missing_time = evaluate_path(
        &governance,
        &head.event,
        &path,
        &[],
        CLAIM_WRITE,
        "bug",
        None,
    );
    assert_eq!(missing_time.trusted_time, TrustedTime::Unavailable);
    assert_eq!(
        evaluate_path(
            &governance,
            &head.event,
            &path,
            &[],
            CLAIM_WRITE,
            "bugfix",
            Some(15),
        )
        .capability,
        CapabilityEvidence::CompleteWithoutCoveringPath
    );
    assert_eq!(
        evaluate_path(
            &governance,
            &content_cid(&"missing-head").unwrap(),
            &path,
            &[],
            CLAIM_WRITE,
            "bug",
            Some(15),
        )
        .capability,
        CapabilityEvidence::Missing
    );

    let revocation = Revocation::new(
        &governance,
        &head,
        delegate.did(),
        IdentityVersion::Static,
        governance.active_event.clone(),
        Some(17),
    )
    .unwrap()
    .state()
    .unwrap();
    assert_eq!(
        evaluate_path(
            &governance,
            &head.event,
            &path,
            std::slice::from_ref(&revocation),
            CLAIM_WRITE,
            "bug",
            Some(16),
        )
        .capability,
        CapabilityEvidence::CompleteWithCoveringPath
    );
    assert_eq!(
        evaluate_path(
            &governance,
            &head.event,
            &path,
            std::slice::from_ref(&revocation),
            CLAIM_WRITE,
            "bug",
            Some(17),
        )
        .capability,
        CapabilityEvidence::CompleteWithoutCoveringPath
    );
    let unknown_revocation = evaluate_path(
        &governance,
        &head.event,
        &path,
        std::slice::from_ref(&revocation),
        CLAIM_WRITE,
        "bug",
        None,
    );
    assert_eq!(unknown_revocation.trusted_time, TrustedTime::Unavailable);
    assert_eq!(unknown_revocation.revocation, RevocationStanding::Unknown);

    let parent_revocation = Revocation::new(
        &governance,
        &parent,
        root.did(),
        IdentityVersion::Static,
        governance.active_event.clone(),
        Some(17),
    )
    .unwrap()
    .state()
    .unwrap();
    assert_eq!(
        evaluate_path(
            &governance,
            &head.event,
            &path,
            &[parent_revocation],
            CLAIM_WRITE,
            "bug",
            Some(17),
        )
        .capability,
        CapabilityEvidence::CompleteWithoutCoveringPath
    );
}

#[test]
fn removed_governance_root_cannot_anchor_a_delegation_path() {
    let replacement = Identity::generate();
    let original = authority(ROOT);
    let delegation = Delegation::root(
        &original,
        ROOT.to_string(),
        IdentityVersion::Static,
        original.active_event.clone(),
        DELEGATE.to_string(),
        Capability::new(
            original.repository.clone(),
            None,
            vec![CLAIM_WRITE.to_string()],
            None,
            None,
            false,
        )
        .unwrap(),
    )
    .unwrap();
    let replacement_governance = GovernanceAuthority::new(
        original.repository.clone(),
        original.active_event.clone(),
        vec![replacement.did()],
        original.ancestors.clone(),
    )
    .unwrap();

    assert!(matches!(
        delegation.validate_governance(&replacement_governance),
        Err(Error::GrantorNotRoot)
    ));
    let state = delegation.state().unwrap();
    assert_eq!(
        evaluate_path(
            &replacement_governance,
            &state.event,
            std::slice::from_ref(&state),
            &[],
            CLAIM_WRITE,
            "anything",
            None,
        )
        .capability,
        CapabilityEvidence::CompleteWithoutCoveringPath
    );
}

#[test]
fn revocation_requires_original_grantor_or_current_root_and_a_matching_target() {
    let root = Identity::generate();
    let delegate = Identity::generate();
    let outsider = Identity::generate();
    let governance = authority(&root.did());
    let delegation = Delegation::root(
        &governance,
        root.did(),
        IdentityVersion::Static,
        governance.active_event.clone(),
        delegate.did(),
        Capability::new(
            governance.repository.clone(),
            None,
            vec![CLAIM_WRITE.to_string()],
            None,
            None,
            false,
        )
        .unwrap(),
    )
    .unwrap()
    .state()
    .unwrap();
    let revocation = Revocation::new(
        &governance,
        &delegation,
        root.did(),
        IdentityVersion::Static,
        governance.active_event.clone(),
        None,
    )
    .unwrap();
    let input = revocation.signing_input().unwrap();
    assert!(revocation
        .proved_event(&governance, &delegation, vec![proof(&root, &input)])
        .is_ok());
    assert!(matches!(
        Revocation::new(
            &governance,
            &delegation,
            outsider.did(),
            IdentityVersion::Static,
            governance.active_event.clone(),
            None,
        ),
        Err(Error::RevokerNotAuthorized)
    ));
}

#[test]
fn raw_evidence_resolution_is_order_independent_and_collapses_proof_variants() {
    let root = Identity::generate();
    let delegate = Identity::generate();
    let child = Identity::generate();
    let stranger = Identity::generate();
    let governance = authority(&root.did());
    let parent = Delegation::root(
        &governance,
        root.did(),
        IdentityVersion::Static,
        governance.active_event.clone(),
        delegate.did(),
        Capability::new(
            governance.repository.clone(),
            None,
            vec![CAPABILITY_DELEGATE.to_string(), CLAIM_WRITE.to_string()],
            None,
            None,
            true,
        )
        .unwrap(),
    )
    .unwrap();
    let parent_input = parent.signing_input().unwrap();
    let parent_event = parent
        .proved_event(vec![proof(&root, &parent_input)])
        .unwrap();
    let invalid_parent_variant =
        ControlEvent::new(parent_input.clone(), vec![proof(&stranger, &parent_input)]).unwrap();
    let parent_state = parent.state().unwrap();
    let child_delegation = Delegation::child(
        &governance,
        &parent_state,
        IdentityVersion::Static,
        child.did(),
        Capability::new(
            governance.repository.clone(),
            Some("bug".to_string()),
            vec![CLAIM_WRITE.to_string()],
            None,
            None,
            false,
        )
        .unwrap(),
    )
    .unwrap();
    let child_input = child_delegation.signing_input().unwrap();
    let child_event = child_delegation
        .proved_event(vec![proof(&delegate, &child_input)])
        .unwrap();
    let child_id = child_event.logical_cid().unwrap();
    let revocation = Revocation::new(
        &governance,
        &parent_state,
        root.did(),
        IdentityVersion::Static,
        governance.active_event.clone(),
        None,
    )
    .unwrap();
    let revocation_input = revocation.signing_input().unwrap();
    let revocation_event = revocation
        .proved_event(
            &governance,
            &parent_state,
            vec![proof(&root, &revocation_input)],
        )
        .unwrap();

    let forward = resolve_capabilities(
        &governance,
        &[
            parent_event.clone(),
            invalid_parent_variant.clone(),
            child_event.clone(),
            revocation_event.clone(),
        ],
    );
    let reverse = resolve_capabilities(
        &governance,
        &[
            revocation_event,
            child_event,
            invalid_parent_variant,
            parent_event,
        ],
    );
    assert_eq!(forward, reverse);
    assert_eq!(forward.delegations.len(), 2);
    assert_eq!(forward.revocations.len(), 1);
    assert!(forward.orphans.is_empty());
    assert_eq!(
        forward
            .evaluate(&governance, &child_id, CLAIM_WRITE, "bug/1", None,)
            .capability,
        CapabilityEvidence::CompleteWithoutCoveringPath
    );
}

#[test]
fn raw_evidence_resolution_separates_missing_unsupported_and_invalid() {
    let root = Identity::generate();
    let delegate = Identity::generate();
    let child = Identity::generate();
    let governance = authority(&root.did());
    let parent = Delegation::root(
        &governance,
        root.did(),
        IdentityVersion::Static,
        governance.active_event.clone(),
        delegate.did(),
        Capability::new(
            governance.repository.clone(),
            None,
            vec![CLAIM_WRITE.to_string()],
            None,
            None,
            true,
        )
        .unwrap(),
    )
    .unwrap();
    let parent_state = parent.state().unwrap();
    let child_delegation = Delegation::child(
        &governance,
        &parent_state,
        IdentityVersion::Static,
        child.did(),
        Capability::new(
            governance.repository.clone(),
            None,
            vec![CLAIM_WRITE.to_string()],
            None,
            None,
            false,
        )
        .unwrap(),
    )
    .unwrap();
    let child_input = child_delegation.signing_input().unwrap();
    let child_event = child_delegation
        .proved_event(vec![proof(&delegate, &child_input)])
        .unwrap();
    let missing = resolve_capabilities(&governance, std::slice::from_ref(&child_event));
    assert_eq!(missing.missing_references, vec![parent_state.event.clone()]);
    assert_eq!(missing.orphans, vec![child_event.logical_cid().unwrap()]);

    let root_input = parent.signing_input().unwrap();
    let mut future_payload = root_input.payload.clone();
    let Ipld::Map(fields) = &mut future_payload else {
        unreachable!();
    };
    fields.insert("futureField".to_string(), Ipld::Bool(true));
    let future_input =
        SigningInput::new(DELEGATION_DOMAIN, DELEGATION_EVENT_TYPE, future_payload).unwrap();
    let future_event =
        ControlEvent::new(future_input.clone(), vec![proof(&root, &future_input)]).unwrap();
    let mut nested_future_payload = root_input.payload.clone();
    let Ipld::Map(fields) = &mut nested_future_payload else {
        unreachable!();
    };
    let Some(Ipld::Map(capability)) = fields.get_mut("capability") else {
        unreachable!();
    };
    capability.insert("futureLimit".to_string(), Ipld::Integer(1));
    let nested_future_input = SigningInput::new(
        DELEGATION_DOMAIN,
        DELEGATION_EVENT_TYPE,
        nested_future_payload,
    )
    .unwrap();
    let nested_future_event = ControlEvent::new(
        nested_future_input.clone(),
        vec![proof(&root, &nested_future_input)],
    )
    .unwrap();
    let mut invalid_event = parent
        .proved_event(vec![proof(&root, &root_input)])
        .unwrap();
    invalid_event.domain = "wrong.domain".to_string();
    let invalid_id = invalid_event.logical_cid().unwrap();
    let result = resolve_capabilities(
        &governance,
        &[
            future_event.clone(),
            nested_future_event.clone(),
            invalid_event,
        ],
    );
    assert_eq!(result.unsupported.len(), 2);
    assert!(result
        .unsupported
        .contains(&future_event.logical_cid().unwrap()));
    assert!(result
        .unsupported
        .contains(&nested_future_event.logical_cid().unwrap()));
    assert_eq!(result.invalid, vec![invalid_id]);
    assert_eq!(result.orphans.len(), 3);
    assert!(result.missing_references.is_empty());
}

#[test]
fn preserved_additive_envelope_fields_are_not_narrowed_into_typed_events() {
    let root = Identity::generate();
    let delegate = Identity::generate();
    let governance = authority(&root.did());
    let delegation = Delegation::root(
        &governance,
        root.did(),
        IdentityVersion::Static,
        governance.active_event.clone(),
        delegate.did(),
        Capability::new(
            governance.repository.clone(),
            None,
            vec![CLAIM_WRITE.to_string()],
            None,
            None,
            false,
        )
        .unwrap(),
    )
    .unwrap();
    let input = delegation.signing_input().unwrap();
    let event = delegation.proved_event(vec![proof(&root, &input)]).unwrap();
    let encoded = event.canonical_bytes().unwrap();
    let mut raw: Ipld = atproto_dasl::from_reader(&encoded[..]).unwrap();
    let Ipld::Map(fields) = &mut raw else {
        unreachable!();
    };
    fields.insert("futureEnvelopeField".to_string(), Ipld::Bool(true));
    let future_bytes = atproto_dasl::to_vec(&raw).unwrap();
    let preserved = decode_preserving(&future_bytes).unwrap();
    let future_id = preserved.logical_cid().unwrap();
    assert_eq!(preserved.canonical_bytes(), future_bytes);

    let resolution = resolve_preserved(&governance, &[preserved]);
    assert!(resolution.delegations.is_empty());
    assert_eq!(resolution.unsupported, vec![future_id]);
    assert!(resolution.invalid.is_empty());
}

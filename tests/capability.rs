use std::collections::HashSet;

use kan::{
    cid::content_cid,
    identity::{
        capability::{
            evaluate_path, Capability, Coverage, Delegation, Error, GovernanceAuthority,
            Revocation, CAPABILITY_DELEGATE, CLAIM_WRITE, DELEGATION_DOMAIN, DELEGATION_EVENT_TYPE,
        },
        control::{IdentityVersion, Proof, SigningInput},
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

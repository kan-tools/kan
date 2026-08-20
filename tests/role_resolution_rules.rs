//! AC-8 and AC-10b — the two fold rules `roles::declared` applies, tested
//! against the **pure function** rather than through the CLI.
//!
//! Both rules are unreachable from the command line by design: `role add`
//! refuses a duplicate name as affordance (REQ-6), and kan never writes a
//! `Rejects` claim against a declaration. Driving them through the binary
//! would mean bypassing a guard to reach the rule underneath it, and the test
//! would be about the bypass. `roles::declared` takes its inputs as arguments
//! precisely so the rule can be stated directly — that is what the seam was
//! drawn for.
//!
//! A cold review found both of these ACs naming witnesses that did not exist;
//! these are those witnesses.

use kan::claim::v1::{Anchor, AuthorId, ClaimBody, ClaimContent, Rkey, SubjectRef};
use kan::roles::{declared, Declared};
use kan::sign::Identity;
use kan::store::log::StoredClaim;

use atproto_dasl::Cid;

/// A signed, stored claim — the shape `roles::declared` reads.
fn stored(identity: &Identity, subject: &str, body: ClaimBody) -> (Cid, StoredClaim) {
    let content = ClaimContent {
        author: AuthorId {
            did: identity.did(),
            agent: None,
        },
        workspace: Anchor::Workspace("g".to_string()),
        subject: SubjectRef::Local(Rkey::from(subject)),
        body,
        cites: vec![],
        artifacts: vec![],
        recorded_at: Some(1_700_000_000_000_000),
    };
    let cid = kan::cid::content_cid(&content).unwrap();
    let sig = identity.sign(&cid.to_bytes()).unwrap();
    (
        cid,
        StoredClaim {
            claim: kan::claim::v1::Claim { content, sig },
            rev: "r".to_string(),
        },
    )
}

fn declaration(identity: &Identity, name: &str, did: &str) -> (Cid, StoredClaim) {
    stored(
        identity,
        &format!("role/{name}"),
        ClaimBody::RoleDeclaration {
            did: did.to_string(),
            name: name.to_string(),
        },
    )
}

/// **AC-8**: a name declared twice for different DIDs resolves to the **later**
/// declaration, in log order.
///
/// An append-only log cannot refuse a duplicate the way the file's
/// `RoleNameTaken` check did, so the projection needs a tiebreak. This is not
/// hypothetical: the `role add primary` defect a cold review found traversed
/// exactly this rule, and it is what turned a second declaration into the
/// silent loss of the workspace's own identity from `--trust roles`.
#[test]
fn latest_declaration_wins_per_name() {
    let workspace = Identity::generate();
    let first = Identity::generate().did();
    let second = Identity::generate().did();
    assert_ne!(first, second);

    let claims = vec![
        declaration(&workspace, "reviewer", &first),
        declaration(&workspace, "reviewer", &second),
    ];

    let Declared::Roles(roles) = declared(&claims, Some(&workspace.did())) else {
        panic!("two declarations by the workspace identity should resolve to roles");
    };
    assert_eq!(roles.len(), 1, "one name is one role: {roles:?}");
    assert_eq!(
        roles[0].did, second,
        "the LATER declaration must win; got the earlier one"
    );

    // ...and reversing the log order reverses the answer, which is what makes
    // this a test of the ordering rule rather than of which DID sorts first.
    let reversed = vec![
        declaration(&workspace, "reviewer", &second),
        declaration(&workspace, "reviewer", &first),
    ];
    let Declared::Roles(roles) = declared(&reversed, Some(&workspace.did())) else {
        panic!("expected roles");
    };
    assert_eq!(
        roles[0].did, first,
        "the rule must follow log order, not something incidental to the DIDs"
    );
}

/// **AC-10b**: a `Rejects` claim **cannot revoke a role**.
///
/// Retraction is the author withdrawing their own claim, and is how a role is
/// revoked (AC-3). A rejection is a *different* author suppressing a claim in
/// their own view — honouring it here would hand a third party a revocation
/// power over a registry the declaring workspace never delegated.
///
/// The design calls this "the negative control for the hole a later
/// symmetry-minded reader would open", because adding rejection handling
/// alongside retraction looks like tidying up. Nothing else in the suite pins
/// it, and a cold review found the named witness missing.
#[test]
fn a_rejection_cannot_revoke_a_role() {
    let workspace = Identity::generate();
    let other = Identity::generate();
    let role_did = Identity::generate().did();

    let (declaration_cid, declaration_claim) = declaration(&workspace, "reviewer", &role_did);

    // A rejection of that declaration, by another author, on the same subject.
    let rejection = stored(
        &other,
        "role/reviewer",
        ClaimBody::Rejects {
            claim: declaration_cid.clone(),
        },
    );

    let claims = vec![(declaration_cid, declaration_claim), rejection];

    let Declared::Roles(roles) = declared(&claims, Some(&workspace.did())) else {
        panic!("a rejection must not remove the role");
    };
    assert_eq!(roles.len(), 1);
    assert_eq!(
        roles[0].did, role_did,
        "a third party's rejection revoked a role declaration"
    );

    // The contrast that gives the assertion meaning: a RETRACTION by the
    // declaring author does remove it. Without this, the test above would
    // pass against a resolver that ignored suppression entirely.
    let (declaration_cid_2, declaration_claim_2) = declaration(&workspace, "auditor", &role_did);
    let retraction = stored(
        &workspace,
        "role/auditor",
        ClaimBody::Retraction {
            supersedes: declaration_cid_2.clone(),
        },
    );
    let retracted = vec![(declaration_cid_2, declaration_claim_2), retraction];
    assert!(
        matches!(
            declared(&retracted, Some(&workspace.did())),
            Declared::Nothing
        ),
        "a self-retraction must remove the role -- otherwise the rejection assertion \
         above proves only that nothing is honoured"
    );
}

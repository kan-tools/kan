//! `.design/v0.7-milestone.md` section C (REQ-17–24) — whether kan's read
//! surfaces tell the truth about the log.
//!
//! The adversarial review's verdict on these was: "using only kan's read
//! verbs, a user or agent cannot detect that any known write-side defect
//! happened. Every read surface reports its filtered view as if it were the
//! whole log."

use kan::{
    claim::v1::{Anchor, AuthorId, ClaimBody, ClaimContent, Rkey, StatusValue, SubjectRef},
    context::{self, TokenEstimator},
    fold::{self, TrustBase},
};

/// One token per whitespace-separated word — enough to make budgets
/// predictable in a test without depending on tiktoken's exact numbers.
struct Words;
impl TokenEstimator for Words {
    fn estimate(&self, text: &str) -> usize {
        text.split_whitespace().count()
    }
}

fn author() -> AuthorId {
    AuthorId {
        did: "did:key:zTest".to_string(),
        agent: None,
    }
}

fn claim(subject: &str, body: ClaimBody) -> (atproto_dasl::Cid, kan::claim::v1::Claim) {
    let content = ClaimContent {
        author: author(),
        workspace: Anchor::Workspace("g".to_string()),
        subject: SubjectRef::Local(Rkey::from(subject)),
        body,
        cites: vec![],
        artifacts: vec![],
        recorded_at: Some(1_700_000_000_000_000),
    };
    let cid = kan::cid::content_cid(&content).unwrap();
    (
        cid,
        kan::claim::v1::Claim {
            content,
            sig: vec![],
        },
    )
}

fn observation(text: &str) -> ClaimBody {
    ClaimBody::Observation {
        text: text.to_string(),
    }
}

/// Build a `FoldedView` directly, so these tests exercise the read surfaces
/// rather than the log.
fn view_of(claims: Vec<(atproto_dasl::Cid, kan::claim::v1::Claim)>) -> fold::FoldedView {
    let stored: Vec<(atproto_dasl::Cid, kan::store::log::StoredClaim)> = claims
        .into_iter()
        .enumerate()
        .map(|(i, (cid, claim))| {
            (
                cid,
                kan::store::log::StoredClaim {
                    claim,
                    rev: format!("{i:013}"),
                },
            )
        })
        .collect();
    fold::fold(stored, &TrustBase::solo(author()))
}

/// AC-20, first half: a `Status{Blocked}` must outrank an `Observation`
/// regardless of the two subjects' names.
///
/// `assemble` round-robins one claim per class in `view.classes` order, which
/// is lexical by subject. `kind_value` scores `Status` at 5 and `Observation`
/// at 2 — but only *within* a class, so `task-1`'s observation was taken
/// before `task-3`'s blocker purely because the string sorts first. At budget
/// 150 over 14 claims the live binary emitted five observations and dropped
/// the only blocker.
#[test]
fn a_blocker_outranks_an_observation_regardless_of_subject_name() {
    let mut claims = Vec::new();
    for i in 1..=9 {
        claims.push(claim(
            &format!("task-{i}"),
            observation("some observation here"),
        ));
    }
    claims.push(claim(
        "task-3",
        ClaimBody::Status {
            value: StatusValue::Blocked,
        },
    ));

    let view = view_of(claims);
    // Room for only a couple of claims.
    let selected = context::assemble(&view, 6, &Words);

    let has_blocked = selected.iter().any(|(_, c)| {
        matches!(
            c.content.body,
            ClaimBody::Status {
                value: StatusValue::Blocked
            }
        )
    });
    assert!(
        has_blocked,
        "the only Blocked status must survive a tight budget -- it lost to \
         `task-1`'s observation purely on subject-name sort order"
    );
}

/// AC-20, second half: what was dropped is reported. A budgeted view that
/// cannot say what it withheld is indistinguishable from a complete one.
#[test]
fn omitted_claims_and_subjects_are_reported() {
    let claims: Vec<_> = (1..=8)
        .map(|i| {
            claim(
                &format!("task-{i}"),
                observation("a fairly wordy observation here"),
            )
        })
        .collect();
    let view = view_of(claims);

    let assembled = context::assemble_reporting(&view, 6, &Words);
    assert!(
        assembled.omitted_claims > 0,
        "this budget cannot fit everything, so something must be reported omitted"
    );
    assert!(
        !assembled.omitted_subjects.is_empty(),
        "the subjects with dropped claims must be nameable, not just counted"
    );
    assert_eq!(
        assembled.selected.len() + assembled.omitted_claims,
        8,
        "every claim must be either selected or accounted for as omitted"
    );
}

/// Budget 0 must be distinguishable from an empty log.
#[test]
fn a_zero_budget_still_reports_what_it_withheld() {
    let view = view_of(vec![claim("task-1", observation("something"))]);
    let assembled = context::assemble_reporting(&view, 0, &Words);
    assert!(assembled.selected.is_empty());
    assert_eq!(
        assembled.omitted_claims, 1,
        "budget 0 rendered identically to an empty log -- it must say it \
         dropped something instead"
    );
}

/// AC-21: a superseded status must not be presented as a peer of the one
/// that replaced it.
#[test]
fn a_superseded_status_is_distinguishable_from_the_live_one() {
    let blocked = claim(
        "s",
        ClaimBody::Status {
            value: StatusValue::Blocked,
        },
    );
    let resolved = claim(
        "s",
        ClaimBody::Status {
            value: StatusValue::Resolved,
        },
    );
    let view = view_of(vec![blocked.clone(), resolved.clone()]);
    let class = view
        .subject(&SubjectRef::Local(Rkey::from("s")))
        .expect("subject present");

    let live = fold::state::classify(&class.claims, &[]).live_cids();
    assert!(
        live.contains(&resolved.0) && !live.contains(&blocked.0),
        "the later status is live and the earlier one superseded -- read \
         surfaces need exactly this to stop listing them side by side"
    );
}

/// Determinism is not a casualty of the new ordering (the existing AC-7
/// guarantee, re-checked because `assemble`'s pass ordering changed).
#[test]
fn assembly_stays_deterministic() {
    let claims: Vec<_> = (1..=6)
        .map(|i| claim(&format!("task-{i}"), observation("observation text")))
        .collect();
    let view = view_of(claims);
    let first = context::assemble(&view, 10, &Words);
    for _ in 0..5 {
        let again = context::assemble(&view, 10, &Words);
        assert_eq!(
            first.iter().map(|(c, _)| c).collect::<Vec<_>>(),
            again.iter().map(|(c, _)| c).collect::<Vec<_>>()
        );
    }
}

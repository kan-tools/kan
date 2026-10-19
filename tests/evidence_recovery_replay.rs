#![cfg(feature = "v2-storage")]
use atproto_dasl::Cid;
use kan::{
    evidence_recovery_commitment::Limits,
    evidence_recovery_member::{Input, Membership, Object, Row},
    evidence_recovery_observation::Context,
    evidence_recovery_replay::{self as replay, Checkpoint, Error, Replay},
    evidence_service::{hex, unhex},
};
use serde_json::Value;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
fn limits() -> Limits {
    Limits {
        items: 10000,
        bytes: 64 * 1024 * 1024,
        duration: Duration::from_secs(10),
        cancelled: Arc::new(AtomicBool::new(false)),
    }
}
fn raw(v: &Value) -> Vec<u8> {
    unhex(v.as_str().unwrap(), 4 * 1024 * 1024).unwrap()
}
type EncodedRow = (u64, Vec<u8>, Vec<u8>, Vec<u8>);
struct Case {
    context: Context,
    plan: Option<Vec<u8>>,
    membership: Vec<(Cid, u64)>,
    records: Vec<EncodedRow>,
    objects: Vec<(Cid, Vec<u8>)>,
    candidates: Vec<(Cid, Vec<u8>)>,
    observations: Vec<Vec<u8>>,
    checkpoint: Option<Checkpoint>,
    value: Value,
}
impl Case {
    fn parse(value: Value) -> Self {
        let m = &value["member"];
        let c = &m["context"];
        let context = Context {
            bundle: raw(&c["bundle"]).try_into().unwrap(),
            profile: c["profile"].as_u64().unwrap() as u8,
            archive: raw(&c["archive"]).try_into().unwrap(),
            scope: raw(&c["scope"]).try_into().unwrap(),
            issuer: c["issuer"].as_str().unwrap().into(),
            observer: c["observer"].as_str().unwrap().into(),
        };
        let objects = |v: &Value| {
            v.as_array()
                .unwrap()
                .iter()
                .map(|o| (o[0].as_str().unwrap().parse().unwrap(), raw(&o[1])))
                .collect()
        };
        let checkpoint = (!value["checkpoint"].is_null()).then(|| Checkpoint {
            context: context.clone(),
            sequence: value["checkpoint"][0].as_u64().unwrap(),
            statement: value["checkpoint"][1].as_str().unwrap().parse().unwrap(),
        });
        Self {
            context,
            plan: (!m["plan"].is_null()).then(|| raw(&m["plan"])),
            membership: m["membership"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| {
                    (
                        a[0].as_str().unwrap().parse().unwrap(),
                        a[1].as_u64().unwrap(),
                    )
                })
                .collect(),
            records: m["records"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| (a[0].as_u64().unwrap(), raw(&a[1]), raw(&a[2]), raw(&a[3])))
                .collect(),
            objects: objects(&m["objects"]),
            candidates: objects(&value["candidates"]),
            observations: value["observations"]
                .as_array()
                .unwrap()
                .iter()
                .map(raw)
                .collect(),
            checkpoint,
            value,
        }
    }
    fn named(name: &str) -> Self {
        let f: Value =
            serde_json::from_str(include_str!("../.design/fixtures/recovery-replay-v1.json"))
                .unwrap();
        Self::parse(
            f["cases"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["name"] == name)
                .unwrap()
                .clone(),
        )
    }
    fn verify(&self, limits: Limits) -> Result<Replay, Error> {
        let membership: Vec<_> = self
            .membership
            .iter()
            .map(|(cid, length)| Membership {
                cid,
                length: *length,
            })
            .collect();
        let records: Vec<_> = self
            .records
            .iter()
            .map(|(sequence, manifest, receipt, proof)| Row {
                sequence: *sequence,
                manifest,
                receipt,
                proof,
            })
            .collect();
        let objects: Vec<_> = self
            .objects
            .iter()
            .map(|(cid, bytes)| Object { cid, bytes })
            .collect();
        let candidates: Vec<_> = self
            .candidates
            .iter()
            .map(|(cid, bytes)| Object { cid, bytes })
            .collect();
        let observations: Vec<_> = self.observations.iter().map(Vec::as_slice).collect();
        replay::verify(
            Input {
                context: &self.context,
                plan: self.plan.as_deref(),
                membership: &membership,
                records: &records,
                objects: &objects,
            },
            &candidates,
            &observations,
            self.checkpoint.as_ref(),
            limits,
        )
    }
}
#[test]
fn independent_state_vectors_match_acceptance_commitments_attempts_and_checkpoints() {
    let f: Value =
        serde_json::from_str(include_str!("../.design/fixtures/recovery-replay-v1.json")).unwrap();
    let mut passed = 0;
    let mut refused = 0;
    for v in f["cases"].as_array().unwrap() {
        let c = Case::parse(v.clone());
        let result = c.verify(limits());
        if let Some(reason) = v.get("error") {
            let error = result.err().expect("hostile history must refuse");
            let Error::Invalid(actual) = error else {
                panic!("{}: wrong error {error}", v["name"])
            };
            assert_eq!(actual, reason.as_str().unwrap(), "{}", v["name"]);
            refused += 1;
            continue;
        }
        let result = result.unwrap_or_else(|e| panic!("{}: {e}", v["name"]));
        let e = &v["expected"];
        assert_eq!(
            result.latest().sequence,
            e["latestSequence"].as_u64().unwrap()
        );
        assert_eq!(result.latest().statement.to_string(), e["latestCid"]);
        assert_eq!(result.latest().context, c.context);
        assert_eq!(result.external(), c.checkpoint.as_ref());
        assert_eq!(result.restored(), e["restored"].as_u64().unwrap());
        let restored:Vec<_>=result.restorations().iter().map(|r|serde_json::json!({"cid":r.cid.to_string(),"length":r.length,"basis":format!("{:?}",r.basis)})).collect();
        assert_eq!(
            serde_json::json!(restored),
            e["restoredObjects"],
            "{}",
            v["name"]
        );

        assert_eq!(
            hex(result.member().commitment()),
            v["member"]["expected"]["member"]
        );
        let attempts:Vec<_>=result.attempts().iter().map(|a|serde_json::json!({"id":hex(&a.id),"intent":a.intent.to_string(),"output":hex(&a.output),"restorations":hex(&a.restorations),"failureCount":a.failure_count,"observedAt":a.observed_at_sequence})).collect();
        assert_eq!(serde_json::json!(attempts), e["attempts"], "{}", v["name"]);
        passed += 1;
    }
    assert_eq!((passed, refused), (13, 32));
}
#[test]
fn restoration_does_not_rewrite_original_loss_or_assert_current_output_exists() {
    let c = Case::named("profile2-restored-failure-observed");
    let before = c.value.clone();
    let r = c.verify(limits()).unwrap();
    assert_eq!(r.member().losses().len(), 2);
    assert_eq!(r.member().verified_requests(), 0);
    assert_eq!(r.restored(), 2);
    assert_eq!(r.attempts()[0].failure_count, 1);
    assert!(r.attempts()[0].observed_at_sequence.is_some());
    assert_eq!(c.value, before);
    assert!(r.external().is_none());
}
#[test]
fn historical_intents_keep_distinct_candidate_sets_and_independent_attempts() {
    let c = Case::named("later-candidate-keeps-earlier-intent-history");
    let r = c.verify(limits()).unwrap();
    let a = r.attempts();
    assert_eq!(a.len(), 2);
    assert_eq!(a[0].output, a[1].output);
    assert_ne!(a[0].restorations, a[1].restorations);
    assert!(a.iter().all(|a| a.observed_at_sequence.is_some()));
}
#[test]
fn rollback_before_external_checkpoint_and_foreign_checkpoint_refuse() {
    let mut c = Case::named("profile2-restored-failure-observed");
    let r = c.verify(limits()).unwrap();
    c.checkpoint = Some(r.latest().clone());
    c.observations.pop();
    assert_eq!(
        c.verify(limits()).err(),
        Some(Error::Invalid("external checkpoint absent"))
    );
    c.checkpoint.as_mut().unwrap().context.bundle[0] ^= 1;
    assert_eq!(
        c.verify(limits()).err(),
        Some(Error::Invalid("external checkpoint context"))
    );
}
#[test]
fn retained_checkpoint_cannot_detect_removal_of_a_later_unpinned_suffix() {
    let mut c = Case::named("profile2-external-prefix-and-extension");
    let full = c.verify(limits()).unwrap();
    let pin = c.checkpoint.clone().unwrap();
    assert!(full.latest().sequence > pin.sequence);
    assert!(!full.attempts().is_empty());
    // This is the earlier, internally complete bundle state, including the
    // earlier candidate table. There is no later external fact to compare.
    c.observations.truncate(pin.sequence as usize);
    c.candidates.clear();
    let earlier = c.verify(limits()).unwrap();
    assert_eq!(earlier.latest(), &pin);
    assert_eq!(earlier.external(), Some(&pin));
    assert!(earlier.attempts().is_empty());
    assert_eq!(earlier.restored(), 0);
    assert_eq!(earlier.member().losses().len(), 2);
}
#[test]
fn matching_external_checkpoint_does_not_skip_verification_of_the_suffix() {
    let mut c = Case::named("profile2-external-prefix-and-extension");
    c.verify(limits()).unwrap();
    let last = c.observations.last_mut().unwrap();
    *last.last_mut().unwrap() ^= 1;
    assert_eq!(
        c.verify(limits()).err(),
        Some(Error::Invalid("observation authentication"))
    );
}
#[test]
fn wrong_bundle_or_observer_never_selects_unsigned_history() {
    let mut c = Case::named("profile2-initial-loss");
    c.context.bundle[0] ^= 1;
    assert_eq!(
        c.verify(limits()).err(),
        Some(Error::Invalid("observation authentication"))
    );
    let mut c = Case::named("profile2-initial-loss");
    c.context.observer = c.context.issuer.clone();
    assert_eq!(
        c.verify(limits()).err(),
        Some(Error::Invalid("observation authentication"))
    );
}
#[test]
fn item_scan_byte_time_and_cancel_limits_refuse_without_partial_acceptance() {
    let c = Case::named("profile2-restored-failure-observed");
    let mut l = limits();
    l.items = 0;
    assert_eq!(c.verify(l).err(), Some(Error::Budget));
    let mut l = limits();
    l.bytes = 0;
    assert_eq!(c.verify(l).err(), Some(Error::Budget));
    let mut l = limits();
    l.duration = Duration::from_nanos(1);
    assert_eq!(c.verify(l).err(), Some(Error::Budget));
    let l = limits();
    l.cancelled.store(true, Ordering::Relaxed);
    assert_eq!(c.verify(l).err(), Some(Error::Cancelled));
}
#[test]
fn physical_candidate_duplicates_and_oversized_envelopes_refuse() {
    let mut c = Case::named("profile2-restored-failure-observed");
    c.candidates.insert(0, c.candidates[0].clone());
    assert_eq!(
        c.verify(limits()).err(),
        Some(Error::Invalid("candidate order or duplicate"))
    );
    let mut c = Case::named("profile2-initial-loss");
    c.observations[0] = vec![0; 16385];
    assert_eq!(
        c.verify(limits()).err(),
        Some(Error::Invalid("observation authentication"))
    );
}

#[test]
fn partial_membership_restoration_keeps_the_original_unverified_basis() {
    use kan::evidence_recovery_member::Basis;
    let c = Case::named("partial-membership-restoration-does-not-promote-source-authority");
    let r = c.verify(limits()).unwrap();
    assert!(!r.member().recipe_metadata_complete());
    assert_eq!(r.restored(), 2);
    assert!(r
        .restorations()
        .iter()
        .all(|r| r.basis == Basis::UnverifiedMembership && r.length > 0));
    assert_eq!(r.member().losses().len(), 1);
    // One restored key was already available and had no initial loss.
    assert!(r.attempts().is_empty());
    let loss = &r.member().losses()[0];
    assert_eq!(loss.basis, Basis::UnverifiedMembership);
    assert_eq!(loss.expected_length, None);
    assert_eq!(loss.occurrence, None);
}

#![cfg(feature = "v2-storage")]
//! REVIEWER PROBE (temporary copy in tests/, removed after runs). Reads the
//! reviewer-generated corpus at $REVIEW_PROBES and the frozen author fixture.
//! Prints one classified trace line per case; panics at the end on mismatch.
use atproto_dasl::Cid;
use kan::{
    evidence::MAX_SAFE_INTEGER,
    evidence_recovery_commitment::Limits,
    evidence_recovery_member::{Input, Membership, Object, Row},
    evidence_recovery_observation::Context,
    evidence_recovery_replay::{self as replay, Checkpoint, Error, Replay},
    evidence_service::{hex, unhex},
};
use serde_json::{json, Value};
use std::{
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};
fn limits() -> Limits {
    Limits {
        items: 10000,
        bytes: 64 * 1024 * 1024,
        duration: Duration::from_secs(30),
        cancelled: Arc::new(AtomicBool::new(false)),
    }
}
fn raw(v: &Value) -> Vec<u8> {
    unhex(v.as_str().unwrap(), 4 * 1024 * 1024).unwrap()
}
type EncodedRow = (u64, Vec<u8>, Vec<u8>, Vec<u8>);
#[derive(Clone)]
struct Case {
    name: String,
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
            name: value["name"].as_str().unwrap().into(),
            context,
            plan: (!m["plan"].is_null()).then(|| raw(&m["plan"])),
            membership: m["membership"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| (a[0].as_str().unwrap().parse().unwrap(), a[1].as_u64().unwrap()))
                .collect(),
            records: m["records"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| (a[0].as_u64().unwrap(), raw(&a[1]), raw(&a[2]), raw(&a[3])))
                .collect(),
            objects: objects(&m["objects"]),
            candidates: objects(&value["candidates"]),
            observations: value["observations"].as_array().unwrap().iter().map(raw).collect(),
            checkpoint,
            value,
        }
    }
    fn verify(&self, limits: Limits) -> Result<Replay, Error> {
        let membership: Vec<_> = self
            .membership
            .iter()
            .map(|(cid, length)| Membership { cid, length: *length })
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
        let objects: Vec<_> = self.objects.iter().map(|(cid, bytes)| Object { cid, bytes }).collect();
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
fn project(r: &Replay) -> Value {
    json!({
        "latestSequence": r.latest().sequence,
        "latestCid": r.latest().statement.to_string(),
        "restoredObjects": r.restorations().iter().map(|x| json!({"cid": x.cid.to_string(), "length": x.length, "basis": format!("{:?}", x.basis)})).collect::<Vec<_>>(),
        "attempts": r.attempts().iter().map(|a| json!({"id": hex(&a.id), "intent": a.intent.to_string(), "output": hex(&a.output), "restorations": hex(&a.restorations), "failureCount": a.failure_count, "observedAt": a.observed_at_sequence})).collect::<Vec<_>>(),
    })
}
fn error_label(e: &Error) -> String {
    match e {
        Error::Invalid(s) => s.to_string(),
        Error::Member(m) => format!("member:{}", m.to_string().trim_start_matches("invalid recovery member: ")),
        Error::Budget => "budget".into(),
        Error::Cancelled => "cancelled".into(),
    }
}
/// Classify: MATCH, ACCEPTED_HOSTILE (incorrect acceptance), REFUSED_POSITIVE,
/// PROJECTION_MISMATCH (accepted with wrong result), DIAG (refused, other label).
fn classify(expect: &Value, got: &Result<Replay, Error>) -> (String, String) {
    match (expect["accept"].as_bool().unwrap_or(false), got) {
        (true, Ok(r)) => {
            let p = project(r);
            let mut bad = vec![];
            for k in ["latestSequence", "latestCid", "restoredObjects", "attempts"] {
                if p[k] != expect[k] {
                    bad.push(format!("{k}: got {} want {}", p[k], expect[k]));
                }
            }
            if bad.is_empty() {
                ("MATCH".into(), p.to_string())
            } else {
                ("PROJECTION_MISMATCH".into(), bad.join("; "))
            }
        }
        (true, Err(e)) => ("REFUSED_POSITIVE".into(), error_label(e)),
        (false, Ok(r)) => ("ACCEPTED_HOSTILE".into(), project(r).to_string()),
        (false, Err(e)) => {
            let l = error_label(e);
            if l == expect["error"].as_str().unwrap() {
                ("MATCH".into(), l)
            } else {
                ("DIAG".into(), format!("got {l} want {}", expect["error"]))
            }
        }
    }
}
#[test]
fn reviewer_probe_corpus() {
    let path = std::env::var("REVIEW_PROBES").expect("REVIEW_PROBES");
    let f: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut failures = vec![];
    for v in f["cases"].as_array().unwrap() {
        let c = Case::parse(v.clone());
        let got = c.verify(limits());
        let (class, detail) = classify(&v["expect"], &got);
        println!("PROBE {} class={} detail={}", c.name, class, detail);
        if class != "MATCH" {
            failures.push(format!("{} {}", c.name, class));
        }
        // Determinism: a second run gives the same projection/error.
        let again = c.verify(limits());
        let same = match (&got, &again) {
            (Ok(a), Ok(b)) => project(a) == project(b),
            (Err(a), Err(b)) => a == b,
            _ => false,
        };
        if !same {
            failures.push(format!("{} NONDETERMINISTIC", c.name));
        }
    }
    println!("PROBE-SUMMARY failures={:?}", failures);
    assert!(failures.is_empty(), "{failures:?}");
}
fn author(name: &str) -> Case {
    let f: Value =
        serde_json::from_str(include_str!("../.design/fixtures/recovery-replay-v1.json")).unwrap();
    Case::parse(f["cases"].as_array().unwrap().iter().find(|c| c["name"] == name).unwrap().clone())
}
#[test]
fn reviewer_checkpoint_context_and_range_probes() {
    let base = author("profile2-restored-failure-observed");
    let tip = base.verify(limits()).unwrap().latest().clone();
    let mut out = vec![];
    let mut run = |label: &str, edit: &dyn Fn(&mut Checkpoint)| {
        let mut c = base.clone();
        let mut p = tip.clone();
        edit(&mut p);
        c.checkpoint = Some(p);
        let r = c.verify(limits());
        let s = match &r {
            Ok(r) => format!("ACCEPT latest={} external={:?}", r.latest().sequence, r.external().map(|e| e.sequence)),
            Err(e) => format!("REFUSE {}", error_label(e)),
        };
        println!("CHECKPOINT {label}: {s}");
        out.push((label.to_string(), s));
    };
    run("tip-exact", &|_| {});
    run("observer-differs", &|p| p.context.observer = p.context.issuer.clone());
    run("issuer-differs", &|p| p.context.issuer = p.context.observer.clone());
    run("profile-differs", &|p| p.context.profile = 3);
    run("scope-differs", &|p| p.context.scope[0] ^= 1);
    run("archive-differs", &|p| p.context.archive[0] ^= 1);
    run("sequence-zero", &|p| p.sequence = 0);
    run("sequence-max-safe-plus-one", &|p| p.sequence = MAX_SAFE_INTEGER as u64 + 1);
    run("sequence-tip-plus-one", &|p| p.sequence += 1);
    run("sequence-one-with-tip-cid", &|p| p.sequence = 1);
    let created = {
        let mut c = base.clone();
        c.observations.truncate(1);
        c.candidates.clear();
        // 2 initial losses -> truncated history is invalid; use the CID from a
        // separate valid prefix instead (sequence 3 = last unavailable/first restored).
        c
    };
    drop(created);
    let expect = [
        ("tip-exact", "ACCEPT"),
        ("observer-differs", "REFUSE external checkpoint context"),
        ("issuer-differs", "REFUSE external checkpoint context"),
        ("profile-differs", "REFUSE external checkpoint context"),
        ("scope-differs", "REFUSE external checkpoint context"),
        ("archive-differs", "REFUSE external checkpoint context"),
        ("sequence-zero", "REFUSE external checkpoint context"),
        ("sequence-max-safe-plus-one", "REFUSE external checkpoint context"),
        ("sequence-tip-plus-one", "REFUSE external checkpoint absent"),
        ("sequence-one-with-tip-cid", "REFUSE external checkpoint statement"),
    ];
    for ((l, s), (el, es)) in out.iter().zip(expect) {
        assert_eq!(l, el);
        assert!(s.starts_with(es), "{l}: {s}");
    }
}
#[test]
fn reviewer_budget_monotonicity_and_bounds() {
    for name in [
        "profile2-restored-failure-observed",
        "later-candidate-keeps-earlier-intent-history",
        "greedy-32-plus-2-loss-partition",
        "profile3-restored-failure-observed",
    ] {
        let c = author(name);
        let full = project(&c.verify(limits()).unwrap());
        // Minimal items.
        let (mut lo, mut hi) = (0u64, 10000u64);
        while lo < hi {
            let mid = (lo + hi) / 2;
            let mut l = limits();
            l.items = mid;
            if c.verify(l).is_ok() { hi = mid } else { lo = mid + 1 }
        }
        let min_items = lo;
        let mut l = limits();
        l.items = min_items - 1;
        let below_items = c.verify(l).err();
        // Minimal bytes.
        let (mut lo, mut hi) = (0u64, 64 * 1024 * 1024u64);
        while lo < hi {
            let mid = (lo + hi) / 2;
            let mut l = limits();
            l.bytes = mid;
            if c.verify(l).is_ok() { hi = mid } else { lo = mid + 1 }
        }
        let min_bytes = lo;
        let mut l = limits();
        l.bytes = min_bytes - 1;
        let below_bytes = c.verify(l).err();
        let mut l = limits();
        l.items = min_items;
        l.bytes = min_bytes;
        let at_min = project(&c.verify(l).unwrap());
        let input: u64 = c.records.iter().map(|r| (r.1.len() + r.2.len() + r.3.len()) as u64).sum::<u64>()
            + c.objects.iter().map(|o| o.1.len() as u64).sum::<u64>()
            + c.plan.as_ref().map_or(0, |p| p.len() as u64)
            + 44 * c.membership.len() as u64;
        let obs: u64 = c.observations.iter().map(|o| o.len() as u64).sum();
        let cand: u64 = c.candidates.iter().map(|o| o.1.len() as u64).sum();
        println!(
            "BUDGET {name}: min_items={min_items} below={below_items:?} min_bytes={min_bytes} below={below_bytes:?} same_projection_at_min={} member_input_bytes={input} observation_bytes={obs} candidate_bytes={cand} observations={} candidates={}",
            at_min == full, c.observations.len(), c.candidates.len()
        );
        assert_eq!(below_items, Some(Error::Budget));
        assert_eq!(below_bytes, Some(Error::Budget));
        assert_eq!(at_min, full);
    }
    // Duration and cancellation bounds.
    let c = author("profile2-initial-loss");
    for (label, d) in [("zero", Duration::ZERO), ("3601s", Duration::from_secs(3601)), ("3600s", Duration::from_secs(3600))] {
        let mut l = limits();
        l.duration = d;
        println!("DURATION {label}: {:?}", c.verify(l).map(|r| r.latest().sequence));
    }
    // Candidate bounds and shapes.
    let base = author("profile2-restored-failure-observed");
    let mut c = base.clone();
    c.candidates[0].1.clear();
    println!("CANDIDATE empty: {:?}", c.verify(limits()).err());
    let mut c = base.clone();
    c.candidates[0].1 = vec![0; 4 * 1024 * 1024 + 1];
    println!("CANDIDATE >4MiB: {:?}", c.verify(limits()).err());
    let mut c = base.clone();
    c.candidates[0].0 = c.observations.len().to_string().parse::<Cid>().unwrap_or_else(|_| {
        // A DAG-CBOR statement CID: valid CID, wrong codec for an object.
        "bafyreiaezpl7wcys53cfymonkwizs6qb6tb65ckupjkhcrsyi4gfwqbeyy".parse().unwrap()
    });
    println!("CANDIDATE dag-cbor CID: {:?}", c.verify(limits()).err());
    let mut c = base.clone();
    c.observations.push(vec![]);
    println!("OBSERVATION empty slice appended: {:?}", c.verify(limits()).err());
    let mut c = base.clone();
    c.observations.swap(3, 4);
    println!("OBSERVATION reordered restored rows: {:?}", c.verify(limits()).err());
}

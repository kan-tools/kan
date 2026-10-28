#![cfg(feature = "v2-storage")]
//! Reviewer probes for 1833ee5 (temporary; copied into tests/ only while run).
use atproto_dasl::Ipld;
use kan::{
    evidence_recovery_observation as observation,
    evidence_service::{hex, unhex},
    sign::Identity,
};
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("../.design/fixtures/recovery-observation-v1.json")).unwrap()
}
fn raw(v: &Value) -> Vec<u8> {
    unhex(v.as_str().unwrap(), 65536).unwrap()
}
fn context(c: &Value) -> observation::Context {
    observation::Context {
        bundle: raw(&c["bundle"]["$bytes"]).try_into().unwrap(),
        profile: c["profile"].as_u64().unwrap() as u8,
        archive: raw(&c["archive"]["$bytes"]).try_into().unwrap(),
        scope: raw(&c["scope"]["$bytes"]).try_into().unwrap(),
        issuer: c["issuer"].as_str().unwrap().into(),
        observer: c["observer"].as_str().unwrap().into(),
    }
}
fn chain(f: &Value, ctx: &observation::Context) -> Vec<observation::Authenticated> {
    let mut chain = Vec::new();
    for row in f["positive"].as_array().unwrap() {
        chain.push(observation::authenticate(&raw(&row["envelopeHex"]), ctx, chain.last()).unwrap());
    }
    chain
}
fn key(scalar: u8) -> Identity {
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut bytes = [0; 32];
    bytes[31] = scalar;
    std::fs::write(file.path(), bytes).unwrap();
    Identity::load_existing(file.path()).unwrap()
}
fn label(r: &Result<observation::Authenticated, kan::evidence::Error>) -> String {
    match r {
        Ok(_) => "OK".into(),
        Err(kan::evidence::Error::Schema(reason)) => reason.clone(),
        Err(e) => format!("OTHER:{e:?}"),
    }
}
fn out(name: &str, body: &str) {
    if let Ok(path) = std::env::var("REVIEW_OUT") {
        std::fs::write(format!("{path}/{name}"), body).unwrap();
    }
}

/// Differential: reviewer-generated hostile/semantic probes, Python verdicts recorded.
#[test]
fn review_pb1_python_generated_probes_match_named_rust_outcomes() {
    let f = fixture();
    let ctx = context(&f["context"]);
    let chain = chain(&f, &ctx);
    let path = std::env::var("REVIEW_PROBES").expect("REVIEW_PROBES");
    let probes: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut table = String::from("name\tclass\texpect\tpython\trust\tagree\n");
    let mut bad = Vec::new();
    for p in probes["probes"].as_array().unwrap() {
        let mut c = ctx.clone();
        for (k, v) in p["contextOverride"].as_object().unwrap() {
            match k.as_str() {
                "observer" => c.observer = v.as_str().unwrap().into(),
                "issuer" => c.issuer = v.as_str().unwrap().into(),
                _ => panic!("override {k}"),
            }
        }
        let base = p["base"].as_u64().unwrap() as usize;
        let previous = base.checked_sub(1).map(|i| &chain[i]);
        let rust = label(&observation::authenticate(&raw(&p["envelopeHex"]), &c, previous));
        let expect = p["expect"].as_str().unwrap();
        let python = p["python"].as_str().unwrap();
        let agree = rust == expect && rust == python;
        table.push_str(&format!("{}\t{}\t{expect}\t{python}\t{rust}\t{agree}\n", p["name"].as_str().unwrap(), p["class"].as_str().unwrap()));
        if !agree {
            bad.push(format!("{} expect={expect} python={python} rust={rust}", p["name"]));
        }
    }
    table.push_str(&format!("disagreements={}\n", bad.len()));
    out("pb1-differential.tsv", &table);
    assert!(bad.is_empty(), "{bad:#?}");
}

/// Rust-only: authenticated predecessors from a foreign context, replays and sign_claim bounds.
#[test]
fn review_pb2_predecessor_context_and_private_signer_bounds() {
    let f = fixture();
    let ctx = context(&f["context"]);
    let chain = chain(&f, &ctx);
    let signer = key(3);
    let mut log = String::new();
    let mut check = |name: &str, r: Result<observation::Authenticated, kan::evidence::Error>, expect: &str| {
        let l = label(&r);
        log.push_str(&format!("{name}\t{expect}\t{l}\n"));
        assert_eq!(l, expect, "{name}");
    };
    // A wholly valid foreign-context genesis, authenticated under its own pins.
    for (i, mutate) in ["bundle", "archive", "scope", "profile"].iter().enumerate() {
        let mut fc = ctx.clone();
        let mut st = chain[0].statement().clone();
        let Ipld::Map(ref mut m) = st else { panic!() };
        match *mutate {
            "bundle" => { fc.bundle[1] ^= 0x80; m.insert("bundle".into(), Ipld::Bytes(fc.bundle.to_vec())); }
            "archive" => { fc.archive[1] ^= 0x80; m.insert("archive".into(), Ipld::Bytes(fc.archive.to_vec())); }
            "scope" => { fc.scope[1] ^= 0x80; m.insert("scope".into(), Ipld::Bytes(fc.scope.to_vec())); }
            _ => { fc.profile = 3; m.insert("profile".into(), Ipld::Integer(3)); }
        }
        let foreign = observation::sign_claim(&atproto_dasl::to_vec(&st).unwrap(), &signer, &fc, None).unwrap();
        // The next statement under OUR pins citing the foreign genesis CID.
        let mut next = chain[1].statement().clone();
        let Ipld::Map(ref mut m) = next else { panic!() };
        m.insert("previous".into(), Ipld::Link(foreign.statement_cid().clone()));
        let bytes = atproto_dasl::to_vec(&next).unwrap();
        check(&format!("foreign-{i}-{mutate}-sign"), observation::sign_claim(&bytes, &signer, &ctx, Some(&foreign)), "previous-context");
        // The foreign genesis is not accepted under our pins either.
        check(&format!("foreign-{i}-{mutate}-genesis-under-ours"), observation::authenticate(foreign.bytes(), &ctx, None), "context-binding");
    }
    // Replays.
    check("replay-genesis-after-itself", observation::authenticate(chain[0].bytes(), &ctx, Some(&chain[0])), "sequence");
    check("replay-seq2-after-seq2", observation::authenticate(chain[1].bytes(), &ctx, Some(&chain[1])), "sequence");
    check("skip-seq3-after-seq1", observation::authenticate(chain[2].bytes(), &ctx, Some(&chain[0])), "sequence");
    // Context pins that are themselves invalid fail before reading the envelope.
    let mut bad = ctx.clone();
    bad.profile = 4;
    check("context-profile-4", observation::authenticate(chain[0].bytes(), &bad, None), "profile");
    // sign_claim: canonical/bounded input before signing; signer must equal pinned observer.
    let good = chain[0].statement_bytes().to_vec();
    let mut nonminimal = good.clone();
    nonminimal.push(0);
    check("sign-trailing-byte", observation::sign_claim(&nonminimal, &signer, &ctx, None), "statement-canonical");
    check("sign-oversize", observation::sign_claim(&vec![0x40; observation::MAX_ENVELOPE + 1], &signer, &ctx, None), "statement-canonical");
    check("sign-wrong-identity", observation::sign_claim(&good, &key(2), &ctx, None), "signer-context");
    // A statement within the statement bound whose envelope exceeds 16 KiB.
    let mut padded = chain[0].statement().clone();
    let Ipld::Map(ref mut m) = padded else { panic!() };
    m.insert("pad".into(), Ipld::Bytes(vec![0; 15_900]));
    let pbytes = atproto_dasl::to_vec(&padded).unwrap();
    assert!(pbytes.len() <= observation::MAX_ENVELOPE);
    check("sign-envelope-over-bound", observation::sign_claim(&pbytes, &signer, &ctx, None), "envelope-bound");
    // Semantically false created claim still signs (caller duty), documenting the boundary.
    let mut fake = chain[0].statement().clone();
    let Ipld::Map(ref mut m) = fake else { panic!() };
    let Some(Ipld::Map(body)) = m.get_mut("body") else { panic!() };
    body.insert("member".into(), Ipld::Bytes(vec![0xee; 32]));
    check("sign-false-member-digest", observation::sign_claim(&atproto_dasl::to_vec(&fake).unwrap(), &signer, &ctx, None), "OK");
    // Exact bytes: the returned Authenticated echoes only canonical inputs.
    let a = observation::sign_claim(&good, &signer, &ctx, None).unwrap();
    assert_eq!(a.bytes(), chain[0].bytes());
    assert_eq!(hex(a.statement_bytes()), hex(&good));
    out("pb2-rust-only.tsv", &log);
}

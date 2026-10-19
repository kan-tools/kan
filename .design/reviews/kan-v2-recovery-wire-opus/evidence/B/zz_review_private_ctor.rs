#![cfg(feature = "v2-storage")]
// Expected NOT to compile: callers cannot forge an authenticated predecessor.
use kan::evidence_recovery_observation::{Authenticated, Context};
#[test]
fn forge() {
    let _ = Authenticated { context: unimplemented!(), bytes: vec![], statement: vec![], value: unimplemented!(), cid: unimplemented!(), sequence: 1 };
    let _: Option<Context> = None;
}

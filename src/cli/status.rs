//! `kan status` — M4a's version is still thin: `Solo` trust never contests
//! (nothing to reconcile against a single timeline), so "status" here still
//! just means "the most recent live claim." Real `Settled | Confirmed |
//! Contested` classification over `Status`-kind claims is M4b's state fold.

use crate::{
    claim::{Rkey, SubjectRef},
    fold,
};

use super::{Error, Workspace};

pub async fn status(ws: &mut Workspace, subject: Option<&str>) -> Result<(), Error> {
    let claims = ws.index.all_stored_claims()?;
    let trust = ws.solo_trust();
    let view = fold::fold(claims, &trust);

    match subject {
        Some(subject) => {
            let subject_ref = SubjectRef::Local(Rkey::from(subject));
            match view.subject(&subject_ref).and_then(|v| v.claims.last()) {
                None => println!("{subject}: no claims"),
                Some((cid, claim)) => {
                    println!(
                        "{subject}: {:?} — {:?}  ({cid})",
                        claim.content.body.kind(),
                        claim.content.body
                    )
                }
            }
        }
        None => {
            if view.classes.is_empty() {
                println!("no subjects yet");
            }
            for subject_view in &view.classes {
                if let Some((cid, claim)) = subject_view.claims.last() {
                    println!(
                        "{:?}: {:?} — {:?}  ({cid})",
                        subject_view.subjects,
                        claim.content.body.kind(),
                        claim.content.body
                    );
                }
            }
        }
    }
    Ok(())
}

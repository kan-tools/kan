//! `kan status` — M3's version is deliberately thin: the trivial fold never
//! contests (`SoloTrust`), so "status" here just means "the most recent live
//! claim." Real `Settled | Confirmed | Contested` classification is M4's
//! state fold, once there's more than one author's timeline to reconcile.

use crate::{
    claim::{Rkey, SubjectRef},
    fold::{self, trust::SoloTrust},
};

use super::{Error, Workspace};

pub async fn status(ws: &mut Workspace, subject: Option<&str>) -> Result<(), Error> {
    let claims = ws.index.all_stored_claims()?;
    let view = fold::fold(claims, &SoloTrust);

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
            if view.subjects.is_empty() {
                println!("no subjects yet");
            }
            for subject_view in view.subjects.values() {
                if let Some((cid, claim)) = subject_view.claims.last() {
                    println!(
                        "{:?}: {:?} — {:?}  ({cid})",
                        subject_view.subject,
                        claim.content.body.kind(),
                        claim.content.body
                    );
                }
            }
        }
    }
    Ok(())
}

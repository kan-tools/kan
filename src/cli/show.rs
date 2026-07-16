use crate::{
    claim::{Rkey, SubjectRef},
    fold::{self, trust::SoloTrust},
};

use super::{Error, Workspace};

pub async fn show(ws: &mut Workspace, subject: &str) -> Result<(), Error> {
    let claims = ws.index.all_stored_claims()?;
    let view = fold::fold(claims, &SoloTrust);
    let subject_ref = SubjectRef::Local(Rkey::from(subject));

    match view.subject(&subject_ref) {
        None => println!("{subject}: no claims"),
        Some(subject_view) => {
            println!("{subject} ({} live claim(s)):", subject_view.claims.len());
            for (cid, claim) in &subject_view.claims {
                println!(
                    "  {cid}  {:?}  {:?}",
                    claim.content.body.kind(),
                    claim.content.body
                );
            }
        }
    }
    Ok(())
}

use crate::{
    claim::{Rkey, SubjectRef},
    fold,
};

use super::{Error, Workspace};

pub async fn show(ws: &mut Workspace, subject: &str) -> Result<(), Error> {
    let claims = ws.index.all_stored_claims()?;
    let trust = ws.solo_trust();
    let view = fold::fold(claims, &trust);
    let subject_ref = SubjectRef::Local(Rkey::from(subject));

    match view.subject(&subject_ref) {
        None => println!("{subject}: no claims"),
        Some(subject_view) => {
            if subject_view.subjects.len() > 1 {
                println!("{subject} (merged with {:?}):", subject_view.subjects);
            }
            if subject_view.flagged_oversized {
                println!(
                    "  warning: this merge-class bridges an unusually large number of \
                     subjects — probable erroneous SameAs assertion, review before trusting it"
                );
            }
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

//! `kan status` — real `Settled | Confirmed | Contested` classification
//! (M4b's state fold, `fold::state`) over each merge-class's `Status`-kind
//! claims. Subjects with no `Status` claims yet (everything narrative:
//! `Observation`/`Plan`/…) fall back to "most recent live claim", same as
//! M4a.

use crate::{
    claim::{Rkey, SubjectRef},
    fold::{self, state::StateView, SubjectView},
    relations,
};

use super::{Error, Workspace};

pub async fn status(ws: &mut Workspace, subject: Option<&str>) -> Result<(), Error> {
    let claims = ws.index.all_stored_claims()?;
    let trust = ws.solo_trust();
    let view = fold::fold(claims, &trust);

    match subject {
        Some(subject) => {
            let subject_ref = SubjectRef::Local(Rkey::from(subject));
            match view.subject(&subject_ref) {
                None => println!("{subject}: no claims"),
                Some(subject_view) => print_state(ws, subject, subject_view),
            }
        }
        None => {
            if view.classes.is_empty() {
                println!("no subjects yet");
            }
            for subject_view in &view.classes {
                let label = format!("{:?}", subject_view.subjects);
                print_state(ws, &label, subject_view);
            }
        }
    }
    Ok(())
}

fn print_state(ws: &Workspace, label: &str, subject_view: &SubjectView) {
    let edges = relations::compute_default(&subject_view.claims, &ws.git);
    match fold::state::classify(&subject_view.claims, &edges) {
        StateView::Unclassified => match subject_view.claims.last() {
            None => println!("{label}: no claims"),
            Some((cid, claim)) => println!(
                "{label}: {:?} — {:?}  ({cid})",
                claim.content.body.kind(),
                claim.content.body
            ),
        },
        StateView::Settled { value, claim } => {
            println!("{label}: Settled({value:?})  ({})", claim.as_ref().0);
        }
        StateView::Confirmed { value, by } => {
            let cids: Vec<String> = by.iter().map(|(cid, _)| cid.to_string()).collect();
            println!("{label}: Confirmed({value:?}, by: {cids:?})");
        }
        StateView::Contested { resolved, open } => {
            let open_desc: Vec<String> = open
                .iter()
                .map(|(cid, c)| format!("{:?}@{cid}", fold::state::value_of(c)))
                .collect();
            let resolved_desc: Vec<String> =
                resolved.iter().map(|(cid, _)| cid.to_string()).collect();
            println!("{label}: Contested(open: {open_desc:?}, resolved: {resolved_desc:?})");
        }
    }
}

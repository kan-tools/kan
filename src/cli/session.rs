//! `kan session start`/`end` — the type model (`src/claim.rs`) has no
//! dedicated `Session` claim kind; `docs/HANDOFF.md`'s CLI vocabulary table
//! names the verbs but doesn't specify a body shape. This was missed during
//! the design pass rather than a deliberate deferral. M3's stand-in:
//! sessions are `Observation` claims on a fixed "session" subject. Worth a
//! real decision later (its own kind vs. staying a convention) once there's
//! a use case that needs to query "all sessions" structurally.

use crate::claim::{AuthorId, ClaimBody, ClaimContent, Rkey, SubjectRef};

use super::{Error, Workspace};

const SESSION_SUBJECT: &str = "session";

pub async fn start(ws: &mut Workspace) -> Result<(), Error> {
    record(ws, "session started".to_string()).await
}

pub async fn end(ws: &mut Workspace, notes: Option<String>) -> Result<(), Error> {
    let text = match notes {
        Some(notes) => format!("session ended: {notes}"),
        None => "session ended".to_string(),
    };
    record(ws, text).await
}

async fn record(ws: &mut Workspace, text: String) -> Result<(), Error> {
    let content = ClaimContent {
        author: AuthorId {
            did: ws.identity.did(),
            agent: None,
        },
        workspace: ws.anchor.clone(),
        subject: SubjectRef::Local(Rkey::from(SESSION_SUBJECT)),
        body: ClaimBody::Observation { text },
        cites: vec![],
        artifacts: vec![],
    };
    let claim_cid = ws.log.append(content, &ws.identity).await?;
    let claims = ws.log.iter_all().await?;
    ws.index.rebuild(&claims)?;
    println!("{claim_cid}");
    Ok(())
}

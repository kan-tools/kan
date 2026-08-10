//! Resolving which signing identities this workspace has declared, from the
//! log rather than from `.kan/roles` (`.design/role-declarations.md` REQ-3).
//!
//! **Deliberately not under `src/fold/`.** Role resolution is not part of the
//! fold; it *produces an input to* it — the `TrustBase` a read folds under. A
//! `RoleDeclaration` carries no status and no relational meaning, and nothing
//! in `src/fold/` matches on it. Keeping this module out of `fold/` is what
//! makes that architectural claim visible rather than a comment somebody has
//! to take on faith.
//!
//! **Not circular, and that is load-bearing.** Resolution consults
//! `fold::identity::excluded_by_retraction`, which is *trust-independent* —
//! self-retraction only — so it needs no `TrustBase` to compute the thing that
//! becomes one. It deliberately does **not** consult `excluded_by_rejection`:
//! see [`declared`].

use std::collections::HashMap;

use atproto_dasl::Cid;

use crate::{
    claim::{ClaimBody, Did},
    store::log::StoredClaim,
};

/// One identity this workspace vouched for, under a local name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredRole {
    pub name: String,
    pub did: Did,
}

/// What resolution found — total, so that "empty" always carries its reason.
///
/// The three empty cases are genuinely different questions and a single empty
/// list answers none of them (`.design/role-declarations.md` REQ-8). The file
/// registry could not tell them apart, because reading a file needs no
/// identity; that distinction is new information, not a nicety.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Declared {
    /// At least one live declaration by this workspace's own identity.
    Roles(Vec<DeclaredRole>),
    /// No `RoleDeclaration` claim exists here at all — the overwhelmingly
    /// common case, and not a problem.
    Nothing,
    /// This workspace's own identity could not be resolved, so no declaration
    /// *can* be honoured. Says nothing about whether any exist.
    NoWorkspaceIdentity,
    /// Declarations exist, but none were authored by this workspace's
    /// identity — so they grant nothing. The count is carried because "there
    /// are 3 declarations here and none are yours" is the actionable form.
    OnlyForeign { count: usize },
}

impl Declared {
    /// The declared roles, or an empty slice for any of the empty cases.
    pub fn roles(&self) -> &[DeclaredRole] {
        match self {
            Declared::Roles(roles) => roles,
            _ => &[],
        }
    }
}

/// Every DID that has authored a `RoleDeclaration` here, with each one's live
/// declared set — resolved **without needing to know who this workspace is**.
///
/// **This is what makes REQ-9's adopt work in the case it exists for.** Asking
/// [`declared`] would ask `workspace_identity`, which is precisely what is
/// missing when a key has been lost — resolution would return
/// [`Declared::NoWorkspaceIdentity`], the set would be empty, and adopt would
/// carry nothing across while reporting success. Every claim carries its own
/// author, so "who declared roles here" is answerable with no identity at all.
///
/// Returns one entry per declaring author, so a caller can refuse to guess
/// when there is more than one rather than picking the wrong registry.
pub fn declaring_authors(claims: &[(Cid, StoredClaim)]) -> Vec<(Did, Vec<DeclaredRole>)> {
    let mut authors: Vec<Did> = Vec::new();
    for (_, stored) in claims {
        if !matches!(stored.claim.content.body, ClaimBody::RoleDeclaration { .. }) {
            continue;
        }
        let did = &stored.claim.content.author.did;
        if !authors.iter().any(|a| a == did) {
            authors.push(did.clone());
        }
    }
    authors
        .into_iter()
        .filter_map(|did| match declared(claims, Some(&did)) {
            Declared::Roles(roles) => Some((did, roles)),
            // An author every one of whose declarations is retracted has no
            // live registry to carry, which is not the same as never having
            // declared -- and either way there is nothing to move.
            _ => None,
        })
        .collect()
}

/// A notice for a workspace holding a **legacy `.kan/roles`** that has not
/// been imported — or the empty string when there is nothing to say.
///
/// **The discoverability half of the migration decision.** `kan identity role
/// import` is one-shot and explicit, and the cost of any non-automatic option
/// was named when it was chosen: an upgraded workspace gets an empty answer
/// with nothing pointing at the explanation sitting right there on disk. This
/// closes that without kan ever *reading* the file for resolution — it checks
/// only that it exists, and says what to run.
///
/// Shown when the file exists and nothing has been declared. A workspace that
/// has imported has declarations, so the notice disappears on its own rather
/// than needing kan to track that the migration happened.
pub fn legacy_file_notice(kan_dir: &std::path::Path, declared: &Declared) -> String {
    if !matches!(declared, Declared::Nothing) {
        return String::new();
    }
    if !kan_dir.join(crate::sign::ROLES_FILE).exists() {
        return String::new();
    }
    format!(
        "\nnote: this workspace has a `.kan/{}` file from a kan older than v0.12, and \
         nothing in it has been imported. Roles live in the log now; run `kan identity \
         role import` to bring those declarations across.\n",
        crate::sign::ROLES_FILE
    )
}

/// Why a role set is empty, in one clause, for surfaces that have room for a
/// phrase rather than a paragraph (`--trust role:<name>`'s "declared: …").
///
/// The three states exist precisely so a caller is not left debugging the
/// wrong problem; collapsing them back to "none declared" at the display
/// boundary would throw that away at the last step.
pub fn empty_reason(declared: &Declared) -> &'static str {
    match declared {
        Declared::Roles(_) => "some declared",
        Declared::Nothing => "none declared",
        Declared::NoWorkspaceIdentity => {
            "this workspace's own identity is unreachable, so no declaration can be honoured"
        }
        Declared::OnlyForeign { .. } => {
            "declarations exist here, but none were authored by this workspace"
        }
    }
}

/// The roles `workspace_did` has declared, from the claims it has written.
///
/// Pure: every input is an argument, so this is testable without a workspace,
/// a key, or a filesystem. The seam is drawn here rather than inside
/// `Workspace` on purpose — v0.12's REQ-3 review found its one destroy-class
/// defect in the *un*-extracted executor while every extracted part was
/// correct, and recorded the lesson as "the seam was drawn one layer too
/// shallow".
///
/// **Latest declaration wins per name**, in log order. An append-only log
/// cannot refuse a duplicate the way the file's `RoleNameTaken` check did, so
/// the projection needs a rule; log order is the one
/// `fold::state::classify` already uses for intra-author supersession
/// ("`class_claims` is already chronological"). A DID declared under two names
/// resolves under both — harmless, and forbidding it would mean a claim that
/// silently does nothing.
///
/// **Retraction is honoured; rejection is not.** A retraction is the author
/// withdrawing their own claim, which is exactly how a role is revoked
/// (AC-3). A `Rejects` claim is *another* author suppressing a claim in
/// their own view — honouring it here would hand a third party a revocation
/// power over a registry the declaring workspace never delegated, which is
/// the privilege-escalation REQ-2's author rule exists to prevent, arriving
/// through a side door. Stated because the omission is invisible: a later
/// reader adding rejection handling *for symmetry* would open it without
/// noticing, and symmetry is a persuasive reason to do the wrong thing.
pub fn declared(claims: &[(Cid, StoredClaim)], workspace_did: Option<&str>) -> Declared {
    let declarations: Vec<&(Cid, StoredClaim)> = claims
        .iter()
        .filter(|(_, stored)| {
            matches!(stored.claim.content.body, ClaimBody::RoleDeclaration { .. })
        })
        .collect();

    // ORDER MATTERS, and this is the decision rather than an accident: "no
    // declarations at all" wins over "no workspace identity". With nothing
    // declared, `Nothing` is the true and more useful answer no matter who is
    // asking, and reporting `NoWorkspaceIdentity` would send an operator to
    // recover a key that would reveal nothing. So `NoWorkspaceIdentity` means
    // exactly "declarations exist here and none can be honoured" -- the
    // lost-key state, which is the one worth naming.
    if declarations.is_empty() {
        return Declared::Nothing;
    }

    let Some(workspace_did) = workspace_did else {
        return Declared::NoWorkspaceIdentity;
    };

    let retracted = crate::fold::identity::excluded_by_retraction(claims);

    // Insertion order preserved so the result is stable for display, while
    // re-inserting a name overwrites it — latest-wins without a sort.
    let mut order: Vec<String> = Vec::new();
    let mut by_name: HashMap<String, DeclaredRole> = HashMap::new();
    let mut ours = 0usize;

    for (cid, stored) in declarations {
        let ClaimBody::RoleDeclaration { did, name } = &stored.claim.content.body else {
            unreachable!("filtered to RoleDeclaration above");
        };
        if stored.claim.content.author.did != workspace_did {
            continue;
        }
        ours += 1;
        if retracted.contains(cid) {
            continue;
        }
        if !by_name.contains_key(name) {
            order.push(name.clone());
        }
        by_name.insert(
            name.clone(),
            DeclaredRole {
                name: name.clone(),
                did: did.clone(),
            },
        );
    }

    if ours == 0 {
        // Every declaration here belongs to someone else. Counting the
        // foreign ones rather than the total, because "none of these are
        // yours" is the fact worth reporting.
        return Declared::OnlyForeign {
            count: claims
                .iter()
                .filter(|(_, s)| matches!(s.claim.content.body, ClaimBody::RoleDeclaration { .. }))
                .count(),
        };
    }

    let roles: Vec<DeclaredRole> = order
        .into_iter()
        .filter_map(|name| by_name.remove(&name))
        .collect();

    // Ours existed but every one was retracted: that is "nothing declared"
    // *now*, which is what a caller asking for the live set wants to hear.
    // AC-3 turns on this: retracting a declaration removes the role.
    match roles.is_empty() {
        true => Declared::Nothing,
        false => Declared::Roles(roles),
    }
}

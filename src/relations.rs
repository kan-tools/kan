//! Computable relations (`docs/SPEC.md` §6): edges derivable from the git
//! substrate with zero attestation, unioned with attested edges (`cites`)
//! inside the state fold (`crate::fold::state`). Default-on and named, so a
//! `TrustBase` can down-weight or disable a provider later (§6.2) — v1
//! wires up the providers and their edges but not that down-weighting yet.

use std::{collections::HashMap, path::Path};

use atproto_dasl::Cid;

use crate::{
    claim::{ArtifactRef, Claim, Sha},
    git::GitSubstrate,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComputedEdgeKind {
    /// `from`'s artifact commit is a git-ancestor of `to`'s — `to` is
    /// causally later. Directional; feeds the state-fold poset (§9).
    Ancestry,
    /// `from` and `to` touch the same file path — `About`-strength,
    /// symmetric; not an ordering edge (§6.1's `GitSameFile`).
    SameFile,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComputedEdge {
    pub from: Cid,
    pub to: Cid,
    pub kind: ComputedEdgeKind,
    pub provider: &'static str,
}

/// `docs/SPEC.md` §6.1's provider interface. Infallible by design: a
/// provider that can't determine an edge (git command failed, no anchor
/// present) just omits it rather than failing the whole fold — computed
/// edges are a bonus signal, not load-bearing the way the claim log is.
pub trait RelationProvider {
    fn name(&self) -> &'static str;
    fn relations(&self, claims: &[(Cid, Claim)], substrate: &GitSubstrate) -> Vec<ComputedEdge>;
}

/// The first commit-bearing artifact on a claim, if any — good enough for
/// v1 (agents are expected to anchor to their tightest git object,
/// `docs/SPEC.md` §6.2's client norm; picking among several is a later
/// refinement, not a correctness gap in the ordering algorithm itself).
fn commit_of(claim: &Claim) -> Option<&Sha> {
    claim.content.artifacts.iter().find_map(|a| match a {
        ArtifactRef::Commit(sha) => Some(sha),
        ArtifactRef::FileAt(_, sha) => Some(sha),
        ArtifactRef::LineRangeAt(_, sha, _) => Some(sha),
        ArtifactRef::ToolOutput(_) => None,
    })
}

fn file_of(claim: &Claim) -> Option<&Path> {
    claim.content.artifacts.iter().find_map(|a| match a {
        ArtifactRef::FileAt(path, _) => Some(path.as_path()),
        ArtifactRef::LineRangeAt(path, _, _) => Some(path.as_path()),
        ArtifactRef::Commit(_) | ArtifactRef::ToolOutput(_) => None,
    })
}

/// Claims anchored to git objects inherit git's DAG ordering (§6.1).
///
/// O(n²) in the number of commit-anchored claims per merge-class, and each
/// distinct commit pair can spawn up to two real `git` subprocesses
/// (`GitSubstrate::is_ancestor`) — like `fold::identity`'s own recompute
/// cost, this is a known, accepted v1 characteristic (correctness before
/// performance, `CLAUDE.md`), not something to silently let scale badly.
/// REQ-13 (`.design/v0.3-milestone.md`): `relations` caches `is_ancestor`
/// results in a `HashMap<(Sha, Sha), bool>` local to the call, since the
/// same commit pair recurs whenever multiple claims share a commit (a claim
/// count of `n` over `k` distinct commits still only needs up to `k²`
/// real subprocess invocations, not `n²`) — the "obvious first
/// optimization" this doc comment used to name as a future revisit; now
/// live rather than theoretical (v0.2 populated real artifacts on every
/// claim).
pub struct GitAncestry;

impl RelationProvider for GitAncestry {
    fn name(&self) -> &'static str {
        "GitAncestry"
    }

    fn relations(&self, claims: &[(Cid, Claim)], substrate: &GitSubstrate) -> Vec<ComputedEdge> {
        let mut cache: HashMap<(Sha, Sha), bool> = HashMap::new();
        let mut is_ancestor = |ancestor: &Sha, descendant: &Sha| -> bool {
            let key = (ancestor.clone(), descendant.clone());
            if let Some(&cached) = cache.get(&key) {
                return cached;
            }
            let result = matches!(substrate.is_ancestor(ancestor, descendant), Ok(true));
            cache.insert(key, result);
            result
        };

        let mut edges = Vec::new();
        for (i, (cid_a, claim_a)) in claims.iter().enumerate() {
            let Some(sha_a) = commit_of(claim_a) else {
                continue;
            };
            for (cid_b, claim_b) in claims.iter().skip(i + 1) {
                let Some(sha_b) = commit_of(claim_b) else {
                    continue;
                };
                if sha_a == sha_b {
                    continue;
                }
                if is_ancestor(sha_a, sha_b) {
                    edges.push(ComputedEdge {
                        from: cid_a.clone(),
                        to: cid_b.clone(),
                        kind: ComputedEdgeKind::Ancestry,
                        provider: self.name(),
                    });
                } else if is_ancestor(sha_b, sha_a) {
                    edges.push(ComputedEdge {
                        from: cid_b.clone(),
                        to: cid_a.clone(),
                        kind: ComputedEdgeKind::Ancestry,
                        provider: self.name(),
                    });
                }
            }
        }
        edges
    }
}

/// Claims touching the same file/lines are auto-related (§6.1).
pub struct GitSameFile;

impl RelationProvider for GitSameFile {
    fn name(&self) -> &'static str {
        "GitSameFile"
    }

    fn relations(&self, claims: &[(Cid, Claim)], _substrate: &GitSubstrate) -> Vec<ComputedEdge> {
        let mut edges = Vec::new();
        for (i, (cid_a, claim_a)) in claims.iter().enumerate() {
            let Some(path_a) = file_of(claim_a) else {
                continue;
            };
            for (cid_b, claim_b) in claims.iter().skip(i + 1) {
                if file_of(claim_b) == Some(path_a) {
                    edges.push(ComputedEdge {
                        from: cid_a.clone(),
                        to: cid_b.clone(),
                        kind: ComputedEdgeKind::SameFile,
                        provider: self.name(),
                    });
                }
            }
        }
        edges
    }
}

/// Run every provider over `claims`, unioning their edges — §6's "the fold
/// consumes their union" of attested ⊔ computable relational input.
pub fn compute_all(
    claims: &[(Cid, Claim)],
    substrate: &GitSubstrate,
    providers: &[&dyn RelationProvider],
) -> Vec<ComputedEdge> {
    providers
        .iter()
        .flat_map(|p| p.relations(claims, substrate))
        .collect()
}

/// `GitAncestry` + `GitSameFile` — the v1 provider set (§6.1), both
/// default-on.
pub fn compute_default(claims: &[(Cid, Claim)], substrate: &GitSubstrate) -> Vec<ComputedEdge> {
    let providers: [&dyn RelationProvider; 2] = [&GitAncestry, &GitSameFile];
    compute_all(claims, substrate, &providers)
}

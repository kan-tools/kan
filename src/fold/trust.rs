//! Enrichment bases (`docs/SPEC.md` §4.3). M2 implements only `SoloTrust` —
//! the trivial local-only path where an author trusts only themself, so
//! nothing is ever contested ("enrich over Bool: any trusted path -> flat
//! merge"). `PeerContested` (trust-weighted, quantale-enriched) lands with
//! the real identity/contest fold in M4 — it isn't stubbed here so there's
//! no half-implemented variant sitting unused in the meantime.

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SoloTrust;

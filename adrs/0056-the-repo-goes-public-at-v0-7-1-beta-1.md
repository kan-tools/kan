# ADR 0056: The repo goes public, at v0.7.1-beta.1

- Status: Accepted
- Date: 2026-07-29
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-56

## Context

Not recorded contemporaneously.

## Decision

Not recorded contemporaneously.

## Rationale

Not recorded contemporaneously.

## Consequences

Not recorded contemporaneously.

## Evidence

Not recorded contemporaneously.

## Alternatives considered

Not recorded contemporaneously.

## Supersession

Not recorded contemporaneously.

## Historical record

**Date:** 2026-07-29
**Status:** Accepted

**Decision:** `kan-tools/kan` is a public GitHub repository. The private repo
was the anomaly, not the policy: the crate has been MIT-licensed and published
to crates.io since v0.1, so every release already shipped the full source to
anyone who ran `cargo vendor`. The repo staying private only hid the *history* —
the ADRs, the design docs, and the issue list — while the code itself was
already public.

**What was audited before flipping**, recorded so it isn't re-derived next time
the question comes up for a sibling repo:

- Credential patterns (`ghp_`, `github_pat_`, `sk-ant-`, `AKIA`, `xox[baprs]`,
  PEM private-key headers) across all 91 tracked files **and** across every blob
  in every commit of every ref — 98 distinct paths ever committed. Clean; every
  hit in the working tree was prose *about* secrets.
- `.kan/` was never committed. The `.gitignore` entry (ADR-3) held for the
  repo's entire history, so no log, index, or signing key was ever tracked.
- Personal identifiers: only `kan-test@example.com` and `t@example.com`, both in
  test fixtures. No home-directory paths.
- `.claims/hard-claims.md` contains signed records and the author `did:key:`.
  That is a *public* key and publishing it is the point of ADR-43, not a leak.
- `CARGO_REGISTRY_TOKEN` is scoped to the `crates-io` GitHub Environment
  (ADR-20), not repo-wide, and its job triggers only on `v*.*.*` tags. Public
  visibility means `pull_request` CI now runs for forks; ADR-20's scoping is
  exactly what keeps that safe, which is the payoff for a choice made when the
  repo had no forks to worry about.

**Two exposures accepted deliberately**, not overlooked:

1. **The issue list is now public, including kan's own security-shaped
   weaknesses** — #30 (per-agent identity is still the v0.2 temporary patch),
   #90 (a binary upgrade can silently mint a new identity), #96/#69 (the OS
   keychain is unusable non-interactively), #121 (the default fold silently
   hides other identities' claims). Publishing the known-weakness list next to a
   pre-1.0 crate that signs things is a real trade. It is accepted because the
   alternative — a signing tool whose limitations are discoverable only by
   reading the source — is worse, and because the candor is the same property
   the tool itself is built to provide. Revisit if kan is publicized beyond
   beta; the exposure question changes with the audience, not with the code.
2. **`forecast-bio/crosslink` is named** in ADR-34, and `docs/SPEC.md` opens
   with a direct critique of crosslink's sync model. crosslink is MIT-licensed
   open source, so the citation and the critique are both fine as they stand.

**Consequences:** none for the build. Nothing in the codebase, CI, or release
process changes. What changes is that the design record — SPEC, 56 ADRs, the
`.design/` docs — is now readable by anyone evaluating the crate, which was
always the argument for keeping it in the repo rather than in a notebook.

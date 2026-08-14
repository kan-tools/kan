# ADR 20: `crates-io` GitHub Environment scopes the publish secret and tag policy

- Status: Not recorded contemporaneously
- Date: 2026-07-21
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-20

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

**Date:** 2026-07-21
**Decision:** `.github/workflows/release.yml`'s `publish` job now declares
`environment: crates-io`. Created via the GitHub API (`PUT
/repos/kan-tools/kan/environments/crates-io`), with a deployment-tag policy
restricting it to tags matching `v*.*.*` — a second, independently-enforced
guard beyond the workflow's own `on.push.tags` filter. `CARGO_REGISTRY_TOKEN`
should be added as an environment-scoped secret (`gh secret set
CARGO_REGISTRY_TOKEN --env crates-io`, or the environment's own GitHub UI
page), not a repo-wide one — scopes the token to exactly the job that
declares this environment, not every workflow in the repo.
**Why attempted and only partly succeeded:** the original intent was also a
required-reviewer approval gate (a manual "approve" click before `cargo
publish` runs, even after the tag is pushed) — GitHub's own docs say
environment protection rules are free for public repositories. Attempting it
returned a 422: `"Please ensure the billing plan supports the required
reviewers protection rule"` — confirmed via the actual API call, not assumed
from docs. `kan-tools` is an *organization*, and required reviewers on
environments needs GitHub Team/Enterprise Cloud for org-owned repos
specifically, even when the repo itself is public; the "free for public
repos" carve-out applies to personal-account-owned repos. `can_admins_bypass`
defaults to `true` regardless, so this was never going to be an unconditional
gate even if available.
**Consequences:** the tag push remains the one deliberate manual gate before
a real publish (unchanged from ADR-19) — no additional approval step exists
yet. Revisit if `kan-tools` ever moves to a paid GitHub plan; until then, this
is a known, confirmed platform limitation, not an oversight.

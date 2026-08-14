# ADR 73: HostedRelay's L1 wire is object PUT/GET, not repo-sync

- Status: Accepted
- Date: 2026-07-30
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-73

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

**Date:** 2026-07-30
**Status:** Accepted

**Decision:** `.design/hosted-relay.md`, ADR-35's Milestone 4 design pass. The
L1 encrypted backup speaks a four-operation object interface — PUT, GET, LIST,
DELETE over opaque bytes — and **not** atproto repo-sync.

**This resolves a contradiction between two accepted ADRs, which is the main
thing this pass found.** ADR-54 stated the wire is atproto repo-sync: "two MSTs
reconcile by comparing root CIDs and descending only where subtrees differ",
lighter than git because kan's log is append-only with no history rewriting.
The reasoning was sound. It is also **incompatible with ADR-70**: descending
into differing subtrees requires the server to see the MST, which is
structure-preserving synchronisation by definition — precisely the posture
ADR-70 rejected on the ground that kan's `cites` graph *is* the provenance.

**ADR-70 wins and ADR-54's wire claim is rescoped rather than reversed.**
ADR-70 is later, more specific, and made against a stated threat model and an
explicit product judgement. ADR-54's argument holds exactly where the server is
*permitted* to read — L2+ and M5, where an AppView must index to be one. What
becomes false is "L1 is a continuation of the same wire": L1 is a different and
much simpler wire, and atproto continuity begins at the rung where reading
starts.

**The consequence is that M4 gets substantially smaller.** ADR-35 named the
wire protocol as M4's dominant net-new build surface, confirmed by reading
crate source — no PDS/XRPC client exists anywhere in kan's dependency tree.
With L1 reduced to object PUT/GET, that surface defers to M5. What remains is
an object store with auth, which kan-infra can satisfy with a bucket behind
signed URLs.

**The interface is deliberately not kan-shaped.** No operation mentions claims,
subjects, CIDs, or MSTs, so the server cannot act on them even if it wanted to.
A `slot` is an opaque client-chosen identifier; the server must not derive
meaning from it, which is what lets the unlinkability path (ADR-70) use random
identifiers.

**The backup credential is a capability, not the signing identity**, and
deliberately not derived from it. Tying backup access to the signing key would
mean a leaked backup credential could only be revoked by rotating a DID and
moving every claim's author — the exact failure #90 and #107 are about — and
would hand the server a public, correlatable `did:key` across every rung.

**Local-first failure is a requirement, not a quality.** An unreachable, slow,
or hostile server never blocks a local write; kan works offline and a backup
that can stop you recording a claim has inverted the product. Auth rejection is
the one failure surfaced loudly and immediately, because silently retrying a
rejected credential forever is how a backup quietly stops existing. A backup
that has not run in three weeks is otherwise indistinguishable from one that
ran five minutes ago — so the `kan status` durability column (ADR-64) reports
last-successful-push, reusing the "make the gap data" move rather than adding a
surface.

**Consequences:** two questions are left open on purpose. What runs the fixed
cadence — ADR-70's timing obfuscation needs a scheduler, kan has no daemon, and
"one surface: CLI + MCP" argues against growing one; the lean is a command plus
documented scheduler recipes, with `kan status` making a misconfigured cadence
visible. And where the credential lives; the lean is the existing key-storage
machinery at lower ceremony, since a lost capability is re-issued rather than
recovered and a second 24-word phrase would be ceremony for nothing.

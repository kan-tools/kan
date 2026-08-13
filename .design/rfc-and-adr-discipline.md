# Feature: RFC and ADR discipline

## Summary

Establish a reviewed Request for Comments process for forward-looking kan
specifications and an explicit Architecture Decision Record format for adopted
engineering decisions. Migrate the 91 records in `docs/DECISIONS.md` into
individually addressable ADR files without silently inventing missing history.

## Requirements

- REQ-1: `rfcs/0000-rfc-and-adr-process.md` must define the distinct purposes,
  lifecycles, statuses, numbering, review, acceptance, rejection, withdrawal,
  implementation, and supersession rules for RFCs and ADRs.
- REQ-2: RFC numbers must be allocated when the proposal pull request opens,
  must never be reused, and may leave permanent gaps. Acceptance requires a
  maintainer and at least 72 hours of public review.
- REQ-3: `rfcs/README.md`, `rfcs/0000-rfc-and-adr-process.md`, and
  `rfcs/template.md` must provide an indexed, copyable structure with explicit
  metadata, semantics, security, compatibility, alternatives, test vectors,
  unresolved questions, and implementation-status sections.
- REQ-4: `adrs/README.md` and `adrs/template.md` must define ADRs as records of
  decisions actually taken, distinguish them from proposals, and require
  status, date, context, decision, rationale, consequences, evidence,
  alternatives, and supersession metadata.
- REQ-5: Every ADR currently headed `ADR-1` through `ADR-91` in
  `docs/DECISIONS.md` must appear exactly once as a zero-padded file under
  `adrs/`, with its original title and prose preserved.
- REQ-6: Every migrated historical ADR must be marked as reconstructed. A
  required field not recoverable from the original record must say exactly
  `Not recorded contemporaneously`; migration must not infer facts merely to
  make the new template look complete.
- REQ-7: `adrs/README.md` must index all migrated ADRs, and
  `docs/DECISIONS.md` must become a compatibility pointer explaining the move
  rather than retaining a second mutable copy.
- REQ-8: An executable validation must compare the legacy source retained for
  migration verification with the migrated set, detecting missing, duplicate,
  renumbered, or prose-altered ADRs.
- REQ-9: `CONTRIBUTING.md` must explain when a proposal needs an RFC, when a
  direct ADR is sufficient, and that an accepted RFC does not require a
  duplicate ADR unless implementation materially departs from it.
- REQ-10: The next proposed RFC must be reserved conceptually for the kan URI
  scheme, but this change must not specify that URI scheme.

## Acceptance Criteria

- [ ] AC-1: A validator reports RFC 0000 and both templates contain every
      required section and only recognized statuses. (REQ-1, REQ-3, REQ-4)
- [ ] AC-2: RFC 0000 states allocation-at-PR-open, permanent gaps, maintainer
      acceptance, and a minimum 72-hour review period. (REQ-2)
- [ ] AC-3: The ADR migration validator reports exactly 91 unique records,
      numbered 0001 through 0091, with matching titles and preserved source
      prose. (REQ-5, REQ-8)
- [ ] AC-4: Every migrated ADR declares reconstruction metadata and every empty
      required field uses the exact non-invention marker. (REQ-6)
- [ ] AC-5: Every ADR file is linked exactly once from `adrs/README.md`, and
      `docs/DECISIONS.md` contains no live ADR headings. (REQ-7)
- [ ] AC-6: `CONTRIBUTING.md` states the RFC/ADR boundary and duplication rule,
      and its RFC link resolves to RFC 0000. (REQ-9)
- [ ] AC-7: RFC 0000 identifies the kan URI scheme as the expected next RFC
      while declaring its syntax and semantics out of scope. (REQ-10)
- [ ] AC-8: The ordinary documentation/check command runs the RFC/ADR
      validator so later structural drift fails CI. (REQ-1, REQ-3, REQ-4,
      REQ-5, REQ-6, REQ-7, REQ-8)

## Architecture

`docs/DECISIONS.md` currently contains 91 `## ADR-N` sections and describes
itself as a short-form implementation decision log. `CONTRIBUTING.md` sends
behavior changes through `.design/` and then directly into that file. This
change preserves `.design/` as working design input while separating two
publication outcomes:

- `rfcs/` holds proposals whose public interface, protocol, governance, or
  cross-cutting consequences benefit from an explicit comment period.
- `adrs/` records decisions already taken, including small implementation
  choices that do not warrant an RFC and material departures from accepted
  RFCs.

The migration is mechanical. A retained legacy snapshot supplies the oracle;
each original ADR section becomes the `Historical record` section of one new
file byte-for-byte apart from the removed heading, while new metadata and
required empty sections surround it. `scripts/check-rfcs-adrs.sh` verifies the
mapping and is invoked from the repository's existing check surface alongside
`scripts/check-citations.sh`.

RFC 0000 is self-applying where possible. Because it is the act that creates
the process, its number and acceptance procedure are established by this pull
request and become normative only when merged.

## Resolved Questions

- RFCs govern forward-looking reviewed proposals; ADRs record decisions
  actually taken. Existing ADRs remain historical rather than being recast as
  proposals.
- Each ADR has its own zero-padded file and `adrs/README.md` is the index.
- Historical prose is preserved; absent fields are explicit and reconstruction
  never fabricates context.
- RFC numbers are allocated when their pull requests open, gaps are permanent,
  and acceptance requires a maintainer after at least 72 hours of review.

## Open Questions

None.

## Out of Scope

- Specifying the kan URI grammar, resolution algorithm, or equivalence rules;
  that is the intended RFC 0001 after RFC 0000 merges.
- Converting ADRs into signed kan claims or closing GitHub issue #75.
- Re-evaluating, editing, or correcting the substance of historical ADRs.
- Renumbering the existing ADR sequence.

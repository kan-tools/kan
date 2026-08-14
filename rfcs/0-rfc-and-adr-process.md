# RFC 0: RFC and ADR process

- Status: Review
- Authors: kan maintainers
- Created: 2026-08-13
- Discussion: https://github.com/kan-tools/kan/pull/225
- Review-period-ends: 2026-08-17T03:47:00Z
- Supersedes: The implicit process described by the former `docs/DECISIONS.md`
- Superseded-by: None

## Summary

kan uses Requests for Comments for forward-looking proposals that require
deliberate public review and Architecture Decision Records for decisions
actually taken. This RFC defines both formats, their lifecycles, their
relationship to `.design/` documents and kan claims, and the reconstruction of
the repository's 91 historical ADRs.

## Motivation

The repository accumulated 91 numbered decisions in one
`docs/DECISIONS.md`. That record is valuable, but its entries do not share an
explicit schema and it combines proposals, implementation choices, review
findings, and releases. The planned kan URI scheme needs a proposal process in
which syntax and identity semantics can be reviewed before becoming an
implementation decision.

This process must improve future discipline without manufacturing a cleaner
past than the evidence supports. Historical prose is therefore retained, and
new required fields absent from an old record say `Not recorded
contemporaneously`.

## Terminology

- **RFC:** A Request for Comments: a forward-looking proposal for a public
  protocol, interface, governance rule, compatibility contract, or
  cross-cutting architectural commitment.
- **ADR:** An Architecture Decision Record: an immutable account of a decision
  actually taken and the evidence available when it was taken.
- **Design document:** Working requirements and acceptance criteria under
  `.design/`. It may produce an RFC, an ADR, both, or neither.
- **Reconstructed ADR:** An ADR migrated from a historical source into the
  current schema after the decision occurred.
- **Maintainer:** A person authorized to merge changes into the kan repository.

Normative words such as MUST, SHOULD, and MAY have their ordinary RFC 2119
meanings.

## Detailed design

### When an RFC is required

An RFC is required for a new or changed public protocol, durable data format,
URI or identifier scheme, compatibility promise, governance rule, security or
trust model, or architecture spanning multiple independently changeable
components. Maintainers may request an RFC when a proposal has similarly broad
or irreversible consequences.

An RFC is not required for a local implementation choice, an ordinary bug fix,
a release record, or a decision whose consequences are confined to one
implementation and are readily reversible. Such a decision MAY proceed from a
validated `.design/` document directly to an ADR.

### RFC numbering and files

RFCs live at `rfcs/N-slug.md`. Numbers use their shortest ASCII decimal form:
RFC 0 is `0`, RFC 1 is `1`, and leading zeroes are forbidden. A number is
allocated when the proposal pull request opens. It MUST NOT be reused,
including when its proposal is withdrawn or rejected; permanent gaps are valid
historical evidence. RFC 0 is the self-applying process record and is accepted
by the pull request that first merges it.

### RFC lifecycle

Recognized RFC statuses are:

```text
Draft → Review → Accepted → Implemented
              ↘ Rejected
Draft/Review → Withdrawn
Accepted/Implemented → Superseded
```

- **Draft:** Authored but not yet submitted for the formal review period.
- **Review:** Submitted in a pull request with an assigned number.
- **Accepted:** Approved by a maintainer after no fewer than 72 continuous
  hours of public review.
- **Implemented:** Its normative behavior is shipped and implementation
  evidence is linked.
- **Rejected:** Considered and declined; the record remains available.
- **Withdrawn:** Removed from consideration by its authors; the number remains
  allocated.
- **Superseded:** Replaced by a named later RFC.

Acceptance requires all blocking questions to be resolved. A question MAY
remain under `Deferred questions` only when the RFC explicitly shows that it
does not affect the proposed contract. Substantive changes restart the 72-hour
period; editorial corrections do not.

### ADR numbering and files

ADRs live at `adrs/N-slug.md` and are indexed by `adrs/README.md`. They use the
same shortest-decimal, no-leading-zeroes representation as RFCs. Numbers are
allocated monotonically when the ADR is merged. Existing numbers 1 through 91
retain their historical order.

Recognized ADR statuses are `Proposed`, `Accepted`, `Rejected`, `Deprecated`,
and `Superseded`. A reconstructed record MAY preserve an unstructured
historical status; its `Reconstruction` metadata makes that exception explicit.

ADRs MUST contain status, date, context, decision, rationale, consequences,
evidence, alternatives, and supersession sections. A contemporary ADR writes
`None` where a field genuinely does not apply. A reconstructed ADR writes
`Not recorded contemporaneously` where the source does not establish the
answer. Reconstruction MUST NOT infer missing rationale, alternatives, or
consequences merely to complete the template.

### Relationship between RFCs, ADRs, designs, and kan claims

`.design/` documents remain the working, mechanically validated requirements
surface. An RFC is the reviewed public proposal produced when the subject
crosses the threshold above. An ADR records a decision actually made.

An accepted RFC is itself sufficient as the governing decision. A duplicate
ADR is neither required nor encouraged. An ADR SHOULD be written when
implementation materially departs from an accepted RFC, and it MUST cite the
RFC and explain the departure. Smaller decisions made while implementing an
RFC may receive ADRs when their rationale will matter later.

Signed kan claims may cite RFCs and ADRs, but neither document type is replaced
by a claim under this RFC. Converting architectural records into hard claims is
tracked separately by GitHub issue #75.

### Historical migration

The former `docs/DECISIONS.md` contained ADR-1 through ADR-91. This change
splits each into an unpadded file, preserves its title and original prose in
`Historical record`, marks it reconstructed, and adds explicit empty required
sections. `adrs/migration-manifest.tsv` records the SHA-256 digest of every
original body, and `scripts/check-rfcs-adrs.sh` checks numbering, uniqueness,
indexing, required sections, reconstruction markers, and those digests.

`docs/DECISIONS.md` remains as a compatibility pointer so old links explain
where the records moved; it is no longer a decision-writing surface.

## Canonicalization and equivalence

RFC and ADR numbers are canonical identities and their canonical rendering is
the shortest ASCII decimal representation, with no leading zeroes. Filenames
add human-readable slugs, but references SHOULD use the number and MAY omit the
slug in prose. Renaming a title or slug does not create a new record. Reusing a
number does.

## Resolution or processing algorithm

To propose an RFC:

1. Open or identify the motivating issue.
2. Copy `rfcs/template.md` and prepare a draft.
3. Open the proposal pull request and allocate the next unused number.
4. Change status to `Review` and record the discussion URL and review end.
5. Resolve blocking questions and restart review after substantive changes.
6. After at least 72 hours, a maintainer accepts, rejects, or asks for further
   revision.
7. Track implementation in the RFC and change status to `Implemented` only
   when shipped evidence exists.

To record an ADR, copy `adrs/template.md`, allocate the next number, record the
decision and evidence, update the index, and submit it with the implementation
or decision it documents.

## Authority and trust model

The merged repository is authoritative for RFC and ADR text and status. Pull
request discussion is supporting evidence, not a substitute for the merged
record. A maintainer's merge establishes acceptance; authorship alone does not.
Historical reconstruction is authoritative only about what the retained
source said, not about facts absent from that source.

## Security considerations

User-controlled links and examples in RFCs are untrusted. Reviewers must check
for misleading authority/userinfo rendering, credential disclosure, ambiguous
normalization, and downgrade behavior when relevant. RFC metadata MUST NOT
contain secrets. A reconstructed ADR must not transform uncertainty into a
confident security claim.

## Compatibility

Existing ADR numbers and prose remain stable. Links to `docs/DECISIONS.md`
reach a compatibility pointer and the ADR index. No historical decision is
silently promoted into an accepted RFC. Future tooling may parse the explicit
formats but must tolerate reconstructed ADR status text.

## Alternatives considered

- Continue appending to one ADR file: rejected because it leaves proposals and
  adopted decisions conflated and makes individual review and linking harder.
- Replace ADRs with RFCs: rejected because proposals and historical decisions
  have different truth conditions.
- Rewrite historical entries into polished contemporary ADRs: rejected because
  it would manufacture missing context and rationale.
- Require a duplicate ADR for every accepted RFC: rejected as redundant and a
  likely source of contradictory governing text.
- Allocate RFC numbers only at merge: rejected because discussion needs stable
  references and gaps truthfully preserve withdrawn work.

## Reference test vectors

`scripts/check-rfcs-adrs.sh` is the executable reference. It must accept this
repository and reject a missing ADR, duplicate number, changed historical body,
missing index entry, absent required section, or invalid RFC status.

## Unresolved questions

None.

## Deferred questions

- Whether RFCs and ADRs later become signed kan claim types or projections is
  deferred to issue #75 or a future RFC.

## Implementation status

Proposed in pull request #225, which adds RFC 0, the templates and indexes,
the ADR migration, and its validator. The process takes effect when that pull
request merges.

The next expected RFC is RFC 1, the kan identity architecture. RFC 2 is
expected to define the kan URI scheme after identity semantics settle. Their
substantive rules are deliberately outside RFC 0.

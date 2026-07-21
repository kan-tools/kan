# Feature: schema evolution — compatibility as a stated contract

## Summary

kan has no compatibility contract, and the absence became visible the moment
a second sharing layer existed: adding `ClaimBody::Publication` made every
older kan unable to read this repo's log at all. This pass writes the
contract down — what may change, what may never change, how a reader treats a
record it only partly understands — adds it to `docs/SPEC.md` as
authoritative, and specifies the two mechanisms that make it enforceable.

The central finding is that **kan cannot migrate**. Its log is append-only
and a CID *is* a claim's identity, so a claim can never be rewritten in
place: rewriting produces a different claim. What kan needs is not a
migration tool but **permanent coexistence** — readers that tolerate every
historical shape, forever — and this doc names that honestly rather than
implying a migration that cannot exist.

## What the substrate actually permits

Measured against kan's real encoder, not assumed:

- **A CID is canonical DAG-CBOR, and it is correct.** `content_cid` produces
  `d8 2a 58 25 00 01 …` — tag 42, byte string, multibase-identity prefix,
  CIDv1: the IPLD/atproto standard. Nothing on disk needs fixing.
- **Additive optional fields do not change existing CIDs.** A field declared
  `Option<T>` with `skip_serializing_if = "Option::is_none"` produces
  byte-identical output when absent, so every claim written before the field
  existed keeps its exact CID. Additive evolution is therefore possible.
- **New readers read old records and verify correctly.** Backward
  compatibility is free.
- **Old readers given a new record fail two different ways**, and the
  difference is the whole problem:
  - a **new enum variant** is a hard decode error — the log becomes
    unreadable, loudly and honestly;
  - a **new struct field** deserializes *successfully*, silently dropping the
    field, and then fails CID verification — reporting a legitimate claim as
    **altered since it was signed**.

The second is far worse than the first. A tool that accuses an honest actor
of tampering because it is one version behind is not merely broken, it is
misleading in the exact dimension kan exists to be trustworthy in.

## Requirements

- REQ-1: `docs/SPEC.md` gains an authoritative **Schema evolution** section
  stating the compatibility contract: what may be added, what may never
  change, and what a reader must do with a record it only partly understands.
  Evolution rules belong with the data model, not in an ADR that has to be
  hunted for.
- REQ-2: The contract's core rule — **`ClaimContent`'s existing fields are
  frozen**. Their names, order, types, and encoding may never change, because
  each is an input to every CID kan has ever computed. New fields may only be
  added as `Option<T>` with `skip_serializing_if`, which is proven not to
  disturb existing CIDs.
- REQ-3: `ClaimContent` is annotated `#[serde(deny_unknown_fields)]`, so an
  older reader encountering a newer record fails with `unknown field` rather
  than silently dropping it and reporting a CID mismatch. This converts the
  dishonest failure mode into the honest one and changes no existing CID.
- REQ-4: A **record format version**, carried outside the hashed content so it
  can never perturb a CID, lets a reader say "this record is format N, I
  understand up to M" instead of reporting a decode failure. It is a
  diagnostic, not a security boundary — REQ-3 is what actually prevents
  misattribution, and the version explains it.
- REQ-5: `ClaimBody` gains an `Unknown { kind: String, raw: Vec<u8> }`
  catch-all so a claim of an unrecognized kind is **preserved rather than
  rejected or dropped**. It keeps its original bytes, so it stays
  CID-verifiable and signature-checkable; it can be counted, cited, and
  retracted; it simply cannot be interpreted. Nothing silently vanishes from
  an older actor's view of a shared tree.
- REQ-6: An `Unknown` claim re-encodes to exactly the bytes it was decoded
  from. Anything less makes it unverifiable, which would defeat the point of
  preserving it.
- REQ-7: The fold treats `Unknown` as carrying no status and no relational
  meaning: it can neither settle nor contest a subject
  (`docs/SPEC.md` §9). An uninterpretable claim must not silently influence a
  classification it cannot be reasoned about.
- REQ-8: `docs/SPEC.md` states that **kan does not migrate**. Old claims keep
  their original encoding and CID permanently; only new claims use new
  shapes; the disposable SQLite index is the only artifact ever rebuilt. A
  rewrite tool is not a deferred feature but a rejected one, because history
  you can alter is not the thing kan is.
- REQ-9: `kan status`/`show` report the presence of unknown-kind claims rather
  than hiding them, so a reader can tell the difference between "this subject
  has three claims" and "this subject has three claims I can read and one I
  cannot".
- REQ-10: A new ADR records the contract and, specifically, the empirical
  findings above — the measurements are the justification, and a future
  reader should not have to re-derive them to know why the rules are what
  they are.

## Acceptance Criteria

- [ ] AC-1: `docs/SPEC.md` contains a Schema evolution section stating the
      frozen-fields rule, the additive-optional rule, the unknown-kind rule,
      and the no-migration rule, in terms specific enough to apply to a
      proposed change without re-deriving them. (REQ-1, REQ-2, REQ-8)
- [ ] AC-2: A test adds a field to a copy of `ClaimContent` as
      `Option<T> + skip_serializing_if` and asserts the CID of a value with
      that field absent is byte-identical to the pre-field CID — the property
      REQ-2 depends on, pinned so it cannot regress silently. (REQ-2)
- [ ] AC-3: With `deny_unknown_fields`, decoding a record containing an
      unexpected field fails with an error naming the field, and **not** with
      a CID mismatch. (REQ-3)
- [ ] AC-4: Every existing claim in a fixture log decodes and verifies
      unchanged after REQ-3's annotation — proving the annotation is
      backward-compatible rather than assumed to be. (REQ-3)
- [ ] AC-5: A record carrying a format version newer than the reader
      understands produces a message naming both versions, distinct from a
      decode failure and from a tampering report. (REQ-4)
- [ ] AC-6: A claim whose body is an unrecognized kind decodes to
      `ClaimBody::Unknown`, and its recomputed CID matches the CID it states.
      (REQ-5, REQ-6)
- [ ] AC-7: Re-encoding an `Unknown` claim produces bytes identical to those
      it was decoded from. (REQ-6)
- [ ] AC-8: A subject whose only unresolved claim is `Unknown` is not
      classified as settled or contested by that claim. (REQ-7)
- [ ] AC-9: A log containing one unknown-kind claim among known ones folds
      successfully, and `kan status` reports the unknown one's presence rather
      than omitting it. (REQ-5, REQ-9)
- [ ] AC-10: `docs/DECISIONS.md` contains an ADR recording the contract and
      the four measurements that justify it. (REQ-10)

## Architecture

**`src/claim.rs`** carries the two mechanisms. `ClaimContent` gains
`#[serde(deny_unknown_fields)]` — one attribute, no field changes, no CID
changes. `ClaimBody` gains `Unknown { kind, raw }`, which needs a custom
`Deserialize` (serde has no built-in catch-all for externally-tagged enums):
the variant name and the raw body bytes are captured so REQ-6's exact
re-encoding is possible.

**The `Unknown` round-trip is the delicate part.** Capturing "the bytes this
variant was encoded from" through serde's data model is not free, and
`atproto_dasl`'s decoder may not surface them directly. If exact
re-encoding proves impossible without a custom decoder, that is a finding
worth recording rather than working around — an `Unknown` that cannot
re-encode cannot be verified, and an unverifiable preserved claim is worse
than an honest hard failure. AC-7 exists to force that question early.

**`src/fold/`** treats `Unknown` as inert (REQ-7): the state fold's poset
gains nothing from it and the identity fold sees no relation. This is a small
change but a load-bearing one — the alternative is a claim that influences
classification through a meaning nobody can read.

**`docs/SPEC.md`** gains the new section near §7 (kinds and bodies), since
that is what the rules constrain. `docs/DECISIONS.md` gains the ADR.

**Nothing here rewrites, deletes, or re-signs a claim.** The whole design
exists to make that permanent rather than incidental.

## Resolved Questions

- **Both `deny_unknown_fields` and a format version.** The attribute is what
  actually prevents a legitimate claim being reported as tampered; the
  version is what turns the resulting error into a message a human can act
  on. Neither substitutes for the other.
- **Unknown kinds are preserved as opaque claims**, not skipped. A skipped
  claim is invisible to the fold, which in a shared tree means a newer
  actor's claims quietly disappear from an older actor's picture — the exact
  silent-divergence failure the sharing layer was built to avoid.
- **Permanent coexistence, not migration.** Readers tolerate every historical
  shape forever; old claims keep their encoding and CID; only the disposable
  index is ever rebuilt. Republishing under new shapes was rejected because
  it creates two CIDs for one fact, fragmenting exactly the identity the fold
  exists to establish. A rewrite tool was rejected because history you can
  alter is not what kan is.
- **Deliverable is design + spec + ADR**, with implementation as its own pass
  against these REQs, so the contract is settled before it is encoded.

## Out of Scope

- Implementation. This pass produces the contract and the specification; the
  code follows against these requirements.
- Changing any existing `ClaimContent` field, which REQ-2 forbids outright.
- A timestamp field (#67) — a real candidate for the first additive field,
  and deliberately not decided here. This pass establishes *how* such a field
  could be added; whether to add it is its own question.
- Exposing artifacts through `show` (#61) — a rendering question, unaffected
  by these rules.
- Cross-version negotiation between actors. Two actors at different versions
  read what they can and say what they cannot; agreeing on a common version
  is a sync-layer concern, not a claim-format one.

# Feature: Typed IdentityOperation wire format

## Summary

Close GitHub issue #244 by making Rust types and their explicit serde attributes
the reference schema for every v1 `IdentityOperation`, then pinning the resulting
canonical DAG-CBOR bytes. Keep raw preserved evidence separate from validated
producer values so unknown extensions round-trip while an absent-target removal
cannot become a finalized locally produced update.

This design serves `telos/identity-system-redesigned`, especially its
`identity-reference-vectors` witness: independently produced identity updates
must agree on operation bytes, logical event CIDs, and transition validity. It
does not change RFC 1's accepted identity architecture, authority model, or
recovery topology.

## Requirements

- REQ-1: `src/identity/did_kan_state.rs` must define the supported v1 wire
  schema as a closed, internally tagged Rust enum using
  `#[serde(tag = "op", rename_all = "camelCase", deny_unknown_fields)]`.
  Every variant must be a struct variant with a specifically named typed
  operand; no positional arrays, externally tagged maps, or generic `value`
  field may define the v1 representation.
- REQ-2: The enum must produce exactly these IPLD maps through serde:
  `addMethod { method: VerificationMethod }`, `removeMethod { id: text }`,
  `setMethodPurposes { id: text, purposes: [VerificationPurpose, ...] }`,
  `addAdministrationController { did: text }`,
  `removeAdministrationController { did: text }`,
  `addRecoveryController { did: text }`,
  `removeRecoveryController { did: text }`, `addService { service: Service }`,
  and `removeService { id: text }`, with `op` carrying the camel-case variant
  name in every map.
- REQ-3: `DidKanUpdate` must be a typed serde payload for RFC 1's existing
  `v`, `did`, `mode`, `previous`, `sequence`, `recoveryParent`,
  `recoveryEpoch`, `operations`, and `supersedes` fields. Its canonical bytes
  must be the canonical DAG-CBOR encoding produced from that typed value by
  `atproto_dasl`; hand-written CBOR assembly must not define a second schema.
- REQ-4: Operations must remain in author-supplied order. Producers and
  decoders must neither sort nor deduplicate the operation array. Transition
  validation must apply each operation to a working state before validating
  the next one.
- REQ-5: Removing a method, administration controller, recovery controller,
  or service that is absent from the working state at that exact operation
  position must make the update invalid. Adding an already-present target and
  setting purposes on an absent method remain invalid as already implemented
  by `DidKanState`.
- REQ-6: The producer API must not expose a way to construct a finalized
  `DidKanUpdate` without validating it against its exact parent state. Private
  payload fields plus administration and recovery constructors/builders must
  return a validated update only after all sequential operations, mode rules,
  collection invariants, sequence, recovery epoch, and final nonempty
  controller invariants pass. Raw decoded evidence remains separately
  representable because a resolver must diagnose invalid hostile input.
- REQ-7: The lossless control-event boundary in
  `src/identity/control.rs` must preserve the original canonical IPLD and
  identifiers before narrowing an update into supported types. An unknown
  `op`, or an otherwise recognized operation carrying additive fields, must
  make the complete update `unsupported` for transition while retaining its
  authenticated raw bytes. A missing required field, wrong field type,
  malformed known operand, or noncanonical common envelope must be `invalid`.
- REQ-8: `rfcs/1-identity-system.md` must publish the Rust-equivalent typed
  operation schema, its serde tagging rule, absent-removal rule, ordered-array
  rule, and invalid-versus-unsupported boundary. The RFC must not rely on an
  unstated serde default; every attribute that affects signed bytes must be
  visible in the normative type definition.
- REQ-9: Reference-vector tests must pin the exact canonical DAG-CBOR hex and
  logical CID of at least one administration update containing all
  administration-legal operation shapes in an order where earlier operations
  affect later ones. Recovery vectors must separately cover both recovery
  controller variants.

## Acceptance Criteria

- [ ] AC-1: A schema test serializes every `IdentityOperation` variant to IPLD
      and asserts the exact field set, the camel-case `op` value, and the typed
      operand field named in REQ-2; deserialization returns the identical enum
      value. (REQ-1, REQ-2)
- [ ] AC-2: Compile-time/source-inventory coverage asserts that
      `IdentityOperation` uses an internal `op` tag, consists only of the nine
      named struct variants, and has no generic operand or custom CBOR encoder.
      (REQ-1, REQ-2, REQ-3)
- [ ] AC-3: A fixed administration vector pins the typed `DidKanUpdate`, exact
      DAG-CBOR hex, signing-input bytes, and logical CID. An independent IPLD
      map fixture decodes to the same typed value and re-encodes byte-for-byte.
      (REQ-3, REQ-8, REQ-9)
- [ ] AC-4: Reversing a sequentially meaningful `removeMethod` then
      `addMethod` replacement changes the outcome from valid to invalid;
      reversing two independent operations changes the logical CID even when
      both resulting states are equal. No producer canonicalizes their order.
      (REQ-4, REQ-5)
- [ ] AC-5: Focused tests reject absent method, administration-controller,
      recovery-controller, and service removals in both administration and
      recovery paths where the mode permits that target class. (REQ-5)
- [ ] AC-6: Producer tests show that public administration and recovery
      construction returns no finalized update for an absent removal,
      duplicate addition, missing method-purpose target, forbidden
      recovery-controller administration operation, sequence mismatch, epoch
      mismatch, or empty final required-controller set. (REQ-5, REQ-6)
- [ ] AC-7: Resolver tests ingest canonical raw evidence for every invalid case
      in AC-6, disclose it as invalid/orphan evidence, and leave the recognized
      parent as a leaf; this proves producer unrepresentability did not erase
      diagnostic input. (REQ-6, REQ-7)
- [ ] AC-8: An authenticated update containing an unknown `op` and one
      containing an additive field on a known operation both retain their
      original canonical bytes and logical CID and classify the identity
      resolution as `unsupported` without applying any operation. (REQ-7)
- [ ] AC-9: Missing operands, wrong operand types, invalid DID/DID-URL values,
      malformed methods or services, and a noncanonical proof envelope classify
      as invalid rather than unsupported. (REQ-7)
- [ ] AC-10: A recovery update vector exercises both recovery-controller
      operation variants and pins their canonical maps; an administration
      update containing either variant is invalid after successful structural
      decoding. (REQ-2, REQ-8, REQ-9)
- [ ] AC-11: RFC implementation-status text and issue #244's eventual closure
      evidence cite the fixed vectors and state explicitly that signed bytes
      come from the normative typed serde schema plus canonical DAG-CBOR.
      (REQ-8, REQ-9)

## Architecture

### Types are the schema

`src/identity/did_kan_state.rs` should replace the present wire-independent
enum with the following normative shape (ordinary derives omitted here except
where they affect the wire):

```rust
#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "camelCase", deny_unknown_fields)]
enum IdentityOperation {
    AddMethod { method: VerificationMethod },
    RemoveMethod { id: String },
    SetMethodPurposes {
        id: String,
        purposes: Vec<VerificationPurpose>,
    },
    AddAdministrationController { did: String },
    RemoveAdministrationController { did: String },
    AddRecoveryController { did: String },
    RemoveRecoveryController { did: String },
    AddService { service: Service },
    RemoveService { id: String },
}
```

The struct variants matter: serde internal tagging produces one map per
operation, and the named operands make the schema visible in the Rust type.
The RFC reproduces this definition and states that its serde attributes are
normative. `atproto_dasl::to_vec` remains the sole canonical encoder, just as
it is for `DidKanGenesis`, repository inception, and governance. A golden
vector is still required: “derived by serde” is an implementation recipe,
while exact bytes and a CID are the cross-language contract.

`DidKanUpdate` belongs in a new `src/identity/did_kan_update.rs` module. It uses
the same `Serialize`, `Deserialize`, camel-case, and `deny_unknown_fields`
pattern as `DidKanGenesis` and `GovernanceEvent`, and creates a
`SigningInput` under `kan.did.update.v1` / `update`. The mode is a typed
`IdentityUpdateMode::{Administration, Recovery}` enum rather than text carried
through producer logic.

### Raw evidence versus valid producer values

Two representations serve different invariants and must not be conflated:

1. The control boundary first holds `PreservedControlEvent` and raw `Ipld`.
   It can therefore retain unknown operations, additive operation fields, and
   structurally invalid hostile evidence without rewriting signed bytes.
2. A supported typed `DidKanUpdate` exists only after structural narrowing.
   A validated producer wrapper or private-field constructor then binds it to
   exact parent state and mode semantics before it can produce canonical bytes
   or a proved event.

Absence is a property of the evolving state, not of an isolated
`removeMethod { id }` value, so Rust's static type system cannot make the raw
operation itself impossible. The producer API instead makes an invalid
*finalized update* unrepresentable. An administration/recovery builder owns a
working `DidKanState`; each method such as `remove_method` checks and mutates
that state while appending the corresponding private operation. `finish`
checks the event-wide invariants and returns the only value that exposes
`canonical_bytes`, `signing_input`, and `proved_event`. The resolver uses a
separate decode-and-validate path and never treats successful serde decoding as
semantic validity.

The existing `DidKanState::apply_administration` remains the pure reference
transition initially. Recovery application should join it in the same module.
Builder and resolver paths must compare their produced state with these pure
functions in tests so producer convenience cannot become a second semantics.

### Forward-compatible narrowing

The update decoder follows the pattern established by
`governance::decode_payload`: inspect canonical raw IPLD first, retain the
complete authenticated map, and project only recognized fields for supported
decoding. The operation list is inspected item by item. An unknown `op` or an
extra field on a known operation is authenticated but unsupported; because
operations are sequential, the resolver must not partially apply the known
prefix or suffix. A malformed known shape is invalid. In either case the raw
event remains available for diagnostics and future software.

### Ordered replacement and removal

The operation array is a program, not a set. No canonical sorting rule applies
to it. Replacement uses existing operations explicitly:

```text
removeMethod(old-id)
addMethod(replacement-with-the-same-id)
```

The first operation proves that the producer built against the state it names;
the second installs the replacement. `addMethod` before `removeMethod` is
invalid when that identifier already exists. Removing an absent target is
also invalid rather than an idempotent no-op. Exact-parent references already
provide deterministic retries, while rejection catches stale or mistaken
transition construction.

## Open Questions

None remaining.

## Resolved Questions

- RQ-1: Rust types with explicit serde attributes are the primary v1 operation
  schema. Canonical DAG-CBOR is derived from those types and pinned with exact
  cross-language vectors.
- RQ-2: Operations use internally tagged, camel-case `op` maps with typed,
  specifically named operands rather than positional or generic values.
- RQ-3: Removing a target absent at that point in sequential evaluation makes
  the update invalid. The producer API prevents such an operation from
  becoming a finalized update; raw resolver evidence can still represent it.
- RQ-4: Unknown operations and additive fields on known operations are
  preserved and make the complete transition unsupported. Malformed known
  shapes are invalid.
- RQ-5: Operation order is signed and semantically significant. It is never
  sorted or deduplicated, and remove-then-add is the v1 replacement spelling.

## Out of Scope

- Changing RFC 1's identity authority, fork, recovery, retirement, standing,
  admission, or checkpoint semantics.
- Adding a `replaceMethod`, profile, role, handle, or other tenth operation.
- Implementing Ed25519, external DID resolution, delegated admission, storage,
  CLI/TUI/GUI workflows, or the default-write cutover.
- Changing `ControlEvent`, genesis, repository-inception, governance, claim,
  CAR, MST, or legacy-claim wire formats.
- Treating Rust-specific enum layout as sufficient documentation without the
  normative serde attributes and fixed DAG-CBOR vectors.

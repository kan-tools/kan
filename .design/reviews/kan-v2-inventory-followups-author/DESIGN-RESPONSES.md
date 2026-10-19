# Recovery design responses to independent scope C

These are proposed resolutions to the frozen 2f6a309 review, pending fresh review.
No DDL, vectors, codec implementation or bundle writer is accepted by this note.

- C-1: the codec appendix is the single normative flat statement/table proposal;
  the parent now uses member_records/member_plan/member_membership and places
  commitment/frontier in the signed created event.
- C-2: partial profile-3 bundles are explicitly ineligible for KNB1 publication.
  With the complete original source, an owner restart first checks the old pinned
  source recipe, then creates a new nonce/archive identity through the existing
  copy workflow and retains the old bundle/checkpoint as job provenance. This is
  not in-bundle completion. An append-only metadata-extension protocol remains
  additional roadmap work before that capability can be exposed.
- C-3: exact initial loss vector, shared-CID occurrence semantics, null entries
  only for unreferenced expected/original keys, length agreement, ordered unique
  coverage and deterministic bounded partition are specified. Missing membership
  orphans are covered; no guessed missing orphan is invented.
- C-4: non-BLOB original object cells refuse bundle creation, without casts or
  dropping evidence. Retain source and failed output for forensic/backup recovery.
- C-5: R1 is reconstructible from all restored observations before intent; the
  output key union and verified byte selection are deterministic. Intent signs
  expected output O1; observed must match it and actual fully verified output.
- C-6: output uses a distinct tools.kan.recovery.output.v1 domain (O1).
- C-7: restored explicitly includes member digest M1.
- C-8: multiple attempts can publish; activation selects one fenced writer.
  Every mutation/job returns a verified frontier for independent owner retention;
  tail truncation after that checkpoint remains undetectable. An online observer
  signature supplies attribution, not an independent rollback witness.

The availability parent explicitly records the move from a separately opened
recovery ledger to separate authority/tables inside the outer KNB1 transaction.
Cross-file output publication and external checkpoint custody remain separate.

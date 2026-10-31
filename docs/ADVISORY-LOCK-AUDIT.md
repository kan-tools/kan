# Advisory lock ownership audit

This audit follows the recovery setup review at `64616d7`. It covers every
production `fs4` acquisition found under `src/`, including blocking acquisitions
and shared-to-exclusive upgrades. It excludes ordinary in-memory mutexes and
SQLite's internal locking. The failure mechanism is demonstrated by retained OS
descriptor-duplication evidence; provenance of descriptors in earlier intermittent
CI failures remains untraced. No timing tolerance or retry was added.

A deliberate owner must explicitly unlock on drop. Closing just one descriptor
may leave a flock alive in an inherited or duplicated descriptor. Independent
readers must retain independently opened shared locks. Moving an owner transfers
its lifetime; duplicating a raw descriptor does not create a deliberate owner.

| Acquisition | Ownership and audit result |
|---|---|
| Policy history | `FileLease` immediately wraps successful acquisition; `Snapshot`, `Current`, checkpoint moves and rejected reads retain/release the same owner. Previously close-only. |
| Erasure history | Same ownership through full/indexed current views, append/checkpoint and error paths. Previously close-only. |
| Completed backup inspection | `FileLease` spans inode checks, SQLite audit, payload hashing and final identity checks. Previously close-only, including errors. |
| Backup purge | `FileLease` spans private-file checks and verification; the same descriptor is upgraded only after read-only verification closes, then retained through rename/removal and directory synchronization. Previously close-only. This is code qualification, not authorization to purge any real backup. |
| Migration controller | Acquired guards stay in a vector for the entire operation; partial acquisition and operation errors drop already acquired owners. Previously close-only. No live migration performed. |
| Legacy log writer | Existing `WriteGuard` is now constructed inside the blocking task immediately after acquisition, before fence checks. Error/cancellation disposal therefore drops a guard instead of a raw file. Successful append ownership unchanged. |
| Key history | Existing nonclonable `KeyLease` already unlocks on owner drop; unchanged. |
| Workspace analysis/maintenance | Existing explicit guards; intentional maintenance ownership shares an `Arc`, including cleanup after connection close. Unchanged. |
| Operations journal | Existing `JournalLock` wraps immediately before opening SQLite and remains owned by the journal. Unchanged. |
| Collection analysis | Existing `CollectionLock` wraps successful shared/exclusive acquisition before return. Unchanged. |
| Scope identity and identity profiles | Existing guards constructed immediately after blocking acquisition, before fallible write/check paths. Unchanged. |

The new crate-private `FileLease` is nonclonable and owns an already acquired file;
it does not change acquisition mode, permissions or surface authority. Its
internal file reference permits the existing explicit purge upgrade and ordinary
reads. Only deliberate owner moves preserve lifetime. Unlock failures remain
best-effort, as in existing guards; no claim of robustness to arbitrary OS failure.

Deterministic Unix regressions cover duplicated descriptors, independent readers,
upgrade/move/error cleanup, replacement-owner exclusion, actual policy/erasure
read rejection, partial migration-lock acquisition, the actual purge private-file upgrade, and
legacy post-acquisition fence-check errors. A dedicated macOS CI step runs all
lease regressions in addition to Linux qualification. Existing integration
checks continue to exercise policy/erasure control, backup inspection/purge and
clone migration. Tests are gated remotely; local compilation/testing is excluded
by the machine policy. Current qualification and focused independent review are
pending; prior green runs do not qualify this change.

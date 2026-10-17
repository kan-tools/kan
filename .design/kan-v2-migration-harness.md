# Feature: Initialize released migration writers explicitly

## Summary

The migration matrix's v1.0.0-beta.1 seed writer refuses to write until a system actor and workspace scope exist. Teach the harness to use that released writer's explicit initialization commands when available, while preserving older writers' initialization behavior and identity-file coverage. This removes a fixture failure that currently prevents the candidate reader from being exercised.

## Requirements

- REQ-1: Probe the released binary's command support rather than infer capabilities from its version. Initialization failures remain visible as unwritable; expectations must not be weakened.
- REQ-2: Isolate system identity configuration inside the fixture, without changing the operator's identity or keychain policy.
- REQ-3: Preserve CID reconciliation, read/write checks, and the legacy identity-file path in `scripts/run-migration-cell.sh`.

## Acceptance Criteria

- [ ] AC-1: Run the actual current writer in seed mode; the harness reaches the candidate reader and returns ok. Removing explicit initialization makes that test fail. (REQ-1, REQ-3)
- [ ] AC-2: Run the current writer in identity-file mode and verify its previous outcome is preserved; assert all system configuration stays beneath the disposable fixture directory. (REQ-2, REQ-3)

## Architecture

`scripts/run-migration-cell.sh` exports a fixture-local KAN_CONFIG_DIR. Where both `identity init --help` and `init --help` succeed, and the mode does not select a legacy key file, initialize the system actor and scope before writing claims. RFC 1 identity continuity is checked against the author of the actual upgrade-write CID, since the legacy `identity did` command does not resolve system actors. Older binaries retain their own initialization flow. This is test infrastructure, not a change to evidence or production identity semantics. Keychain modes retain their existing explicit CI-only guard.

The broader v2 continuation remains `.design/kan-v2-buildout.md`. The existing day partial-trust read limitation means this design needs later backfill into the log; no successful recording is claimed.

## Open Questions

None for this fixture repair.

## Out of Scope

- Changing migration expectations to accept a broken fixture.
- Altering live identities, sources, client routing, or v2 encryption.

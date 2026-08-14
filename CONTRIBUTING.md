# Contributing to kan

Thanks for looking. kan is pre-1.0 and currently written by one person, so this
file is short and tries to be honest about what is actually useful rather than
listing everything a contributing guide usually lists.

## The most useful thing you can send is a report from real use

This is not politeness. The defects that changed kan's direction were all found
by running it, not by reading it:

- [#47](https://github.com/kan-tools/kan/issues/47) — an agent using kan for a
  multi-pass formalization project reported which verbs paid for themselves.
- [#101](https://github.com/kan-tools/kan/issues/101) — a session debrief that
  found an ergonomics bug which silently **lost writes**.
- [#114](https://github.com/kan-tools/kan/issues/114) — a three-role research
  loop that could not consume published claims, which set the scope of v0.8.

Each of those moved a release. If you have used kan on something real and it got
in your way, that is the contribution with the highest leverage available.

A good report contains what those did: what you ran, what you expected, what
happened, the version (`kan --version`), and — if it is about speed — a
measurement rather than an impression. Issue templates are provided for both a
plain bug and a longer field report.

## Code changes start as an issue, not as a pull request

Please **open an issue before writing code**. This is not gatekeeping; it is how
the repo works, and a PR that skips it is likely to be asked to go back and
start there, which wastes your time.

Anything that changes behaviour goes through a design pass first, landing as
`.design/<slug>.md` with numbered requirements (REQ-*) and acceptance criteria
(AC-*). A public protocol, durable format, identifier scheme, governance rule,
compatibility promise, or cross-cutting architecture change then proceeds as a
Request for Comments under [RFC 0](rfcs/0-rfc-and-adr-process.md). A
smaller implementation decision may proceed directly to an Architecture
Decision Record under [`adrs/`](adrs/README.md). An accepted RFC is already the
governing decision and does not need a duplicate ADR unless implementation
materially departs from it. The archaeology is in `adrs/` if you want to see
what these decisions have cost.

Small, self-evident fixes — a typo, a broken link, a stale comment — do not need
any of that. Send them directly.

## The invariants a change must not break

These are the things kan exists to guarantee. A change that violates one of them
is wrong even if it passes CI:

- **No operation destroys a subject.** The log is append-only. There is no
  delete path, and adding one is not a feature.
- **The fold reads morphisms; it never mutates objects.** Identity and status
  are *computed* from claims, collapsed to flat values only at the display
  boundary, never in the store.
- **The fold is a pure, deterministic function of (claim set, enrichment).**
  Same inputs, same output, always.
- **Provenance is sacred.** Never fabricate a `cites` edge and never drop one.
- **Affordance, not enforcement.** kan makes the record legible and surfaces
  drift as data. It does not block anyone's workflow.
- **One surface: CLI + MCP.** No second or third UI.
- **Correctness before performance.** The reference fold recomputes. Caching and
  incremental folds are follow-ups, and are optimized only against passing
  fixtures.

`CLAUDE.md` holds the working notes; `docs/SPEC.md` is authoritative on the data
model and wins over every other document, including this one.

## Building and testing

```sh
just test     # cargo test --workspace
just lint     # clippy -D warnings, plus cargo fmt --check
just fmt      # apply formatting
just run …    # cargo run -p kan -- …
```

The toolchain is pinned to `stable` via `rust-toolchain.toml`. CI runs the
citation checker, then build, test, `clippy -D warnings` and `cargo fmt --check`
on Linux, an MSRV job, and a macOS keychain canary. All of it has to be green.

**Minimum supported Rust version is 1.95**, declared as `rust-version` in
`Cargo.toml`. The `msrv` CI job reads that value out of the manifest and builds
with exactly it, so the declaration cannot quietly become false — and there is
only one place to change it. The floor is currently set by a dependency
(`libsqlite3-sys` uses `cfg_select!`, unstable before 1.95), not by kan's own
code.

If a change raises the floor, bump `rust-version` in the same PR and say so.
Raising it is allowed; discovering it was already wrong is the thing the job
exists to prevent.

## Two house rules that are easy to miss

**A fix answering a review ships with a test that fails without it.** In the
same commit. Verify it by reverting the fix and watching the test go red — a
test written after the fact that passes both ways proves nothing. This rule
exists because a release once shipped three fixes that were claimed and never
made.

**Do not add a check that cannot fail.** If you add a guard, a lint or a test
harness, demonstrate that it detects the thing it is for, ideally by mutating
the code and watching it go red. kan has repeatedly found instruments that had
silently stopped detecting anything while still reporting green — see
[#188](https://github.com/kan-tools/kan/issues/188) and
[#194](https://github.com/kan-tools/kan/issues/194).

## Commits and pull requests

Commit messages are lowercase, imperative, and say what changed and why —
`git log` is the model to follow. One PR per milestone or per issue; keep
unrelated changes out of it.

Note that `.claims/` is a tracked directory of signed claims. If your change
touches it, say so explicitly in the PR — those files are verified by CID and
signature, not by review.

## Security

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).

## Scope: kan or day?

kan owns a feature if and only if it needs a new or existing
`ClaimBody`/`ClaimKind`/`Anchor`/`RelationKind` variant, or is a pure read/fold
over the claim graph. If it can be built as a calling convention over existing
primitives, it is process or workflow, and it belongs in the companion tool
[`day`](https://github.com/kan-tools/day) instead. ADR-18 has the reasoning and
worked examples.

## Conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

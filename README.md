# kan

**Encrypted evidence capture, a human Library, and provenance-preserving knowledge.**

`kan` runs the v2 capture, service, Library and administration workflows. The
repository-based v1 CLI remains available as the optional `kan-v1` executable.
The crate and Rust library are still named `kan`.

## Install the current source candidate

The binary naming change is not published yet. From this checkout:

```sh
# Default: installs kan with the full v2 feature set.
cargo install --path . --locked
kan --help
kan --version

# Optional: install both kan and the legacy kan-v1 executable.
cargo install --path . --locked --features kan-v1

# Or install only the legacy CLI.
cargo install --path . --locked --no-default-features --features kan-v1 --bin kan-v1
kan-v1 --help
```

After publication, use `cargo install kan --version VERSION --locked` with the
chosen release version; the same feature and binary options apply. No `kan-v2`
executable is built by this candidate. Cargo does not remove unrelated binaries
from prior installs: update existing supervisor and hook paths to `kan` explicitly.

An upgrade changes what the name `kan` invokes. Before upgrading a machine that
uses v1 commands, configure those callers to run `kan-v1`. This includes existing
day integrations and saved MCP registrations. A shell alias is not sufficient for
programs that spawn executables directly. The bundled Claude plugin retains its server name `kan` but now launches
`kan-v1`; install the optional feature before using it. The legacy CLI does not forward to v2,
and installing either executable does not migrate data or activate services.

Start with [managed deployment and restore activation](docs/V2-DEPLOYMENT.md),
then configure [capture and the harness gateway](docs/V2-GATEWAY.md),
[v1 import](docs/V2-IMPORT.md), the [Library](docs/V2-LIBRARY.md) and
[Operations](docs/V2-OPERATIONS.md). Provision credentials and independent custody
before launching services. The Library uses `kan library`; one-shot JSON requests
use `--request`, and its MCP mode uses `--mcp`. Owner maintenance remains explicitly
authorized through `kan owner`. Neither installation nor import performs cutover.

When `kan` finds v1 workspace markers in the current project, it prints a
migration reminder to stderr, including on help/version and invalid commands.
Start with `kan preview .` from the detected project root and follow the
[fenced migration runbook](docs/V2-LIBRARY.md#fenced-migration-and-reversible-client-cutover).
Detection is read-only; it does not migrate data. Retained originals and writer
fences cannot prove whether cutover completed. For a known migrated project,
`--no-migration-notice` suppresses the reminder for one invocation without recording
migration approval. JSON and MCP stdout remain unchanged.
Callers that parse **stderr** health JSON or startup announcements must also pass
`--no-migration-notice`; default stderr can contain the human/agent advisory before
those records. Suppression does not bypass migration safeguards.

The remaining sections describe the optional legacy repository CLI.

## Legacy quickstart

```sh
cargo install --path . --locked --no-default-features --features kan-v1 --bin kan-v1

cd your-project                   # kan runs inside a git repo and anchors
git init && git commit --allow-empty -m init   # ...to its history, so it needs at least one commit

kan-v1 observe login-bug "panics on empty input"  # record a finding
kan-v1 decide login-bug "guard the empty case before parsing"
kan-v1 block  login-bug "waiting on the parser refactor"
kan-v1 resolve login-bug "fixed in a1b2c3d"        # resolve closes it out

kan-v1 status                        # one line per subject: its settled state
kan-v1 show login-bug                # that subject's full claim history
kan-v1 issues                        # everything not yet resolved
kan-v1 context --budget 800          # the highest-value claims within a token budget
```

The first write mints this repo's signing identity (see
[Identity](#identity)); nothing is written to a repo until you record a
claim, and reading a repo that has none leaves it untouched. To let an agent
use kan over MCP instead of the CLI, run `kan-v1 mcp install`.

## Machine-readable orientation

Programs usually do not need every claim body merely to learn what a workspace
contains. Use a manifest-then-hydrate read:

```sh
kan-v1 status --json                              # compact subject manifest
kan-v1 show --json --subject login-bug            # hydrate exact subjects
kan-v1 show --json --subject one --subject two
kan-v1 show --json --prefix telos/                 # hydrate visible prefixes
kan-v1 show --all --json                           # complete live claim graph
```

`status --json` includes body-free claim counts, kind counts, the deterministic
fold head, and revisions for every visible merge class. The envelope revision
is scoped to the returned trust frame; a narrative-only append changes it even
when settled status does not. Revisions hash visible CIDs and naming only.
Excluded CIDs and wholly excluded subject names never enter them, while
`excluded_by_trust` still says when the view is partial.

Selected `show` accepts repeatable exact names and prefixes, opens and folds the
workspace once, and returns full `ShowJson` entries. Exact names match trusted
`SameAs` aliases; overlapping selectors return a merge class once; inbound
edges from unselected subjects remain present. `visible_subjects` and
`matched_subjects` make a successful zero-match response explicit.

Use `show --all --json` when the consumer genuinely needs the complete live
graph. It retains the complete, all-or-nothing ADR-71/ADR-81 contract. `context`
answers a different question: it is ranked and token-budgeted, so it is useful
for filling a model window but is deliberately not an inventory.

## Why

AI coding agents forget everything between sessions, and coordinating several of
them means reconciling contradictory state. Most tools solve this with a shared,
mutable store and locks — which is exactly where things break. `kan` takes the
opposite approach: **every actor appends only to its own log; nothing mutates
anyone else's.** Conflicts stop being write-time errors and become read-time
information. All the intelligence lives in the *fold* — a deterministic reduction
from many local logs into a coherent view, parameterized by whom you trust.

## Properties

- **Local-first** — works offline, solo, one machine, no server.
- **Provenance-preserving** — every claim is signed and carries what it was
  derived from. The record of reasoning is auditable end to end.
- **No forced consensus** — many agents, many local truths, glued into a shared
  picture while their differences are preserved (or surfaced, when they conflict).
- **Append-only** — the past is never destroyed; views are computed, not stored.

## Status

The last published baseline is `v1.0.0-beta.1`. This branch prepares
`2.0.0-beta.1`; it is not yet published. See the
[release candidate checklist](docs/RELEASE-2.0.0-beta.1.md) for the CLI transition,
qualification gates and known limitations. Stable 1.0 or 2.0 is not declared.
The following repository-sharing behavior describes the retained legacy CLI.

Sharing works in both directions as of v0.8. `kan-v1 publish <subject>` writes
a subject's signed claims into a tracked `.claims/` directory, so they
travel with the repo: visible in `git diff`, reviewable in a PR, and
readable by someone without kan installed. Each record carries a complete
signed claim, so it is verified rather than trusted — editing the prose
changes the CID and fails verification. A clone now **reads** that tree
too: foreign-authored claims are verified against their own author and
folded from an overlay beside the local log, which stays *claims I
authored* (ADR-43, ADR-59).

Reading is where the trust posture becomes visible. The default `local` view
shows every author represented in this workspace's authoritative log; it does
not resolve a signing identity. Any read that leaves claims out says so — on
both the human output and `--json` — so a partial view cannot pass for a
complete one (ADR-57, ADR-83).

Durability arrived in v0.9. `kan-v1 status` says, per subject, whether it would
survive losing `.kan/` — `unpublished`, `published`, or `stale` — and
`kan-v1 restore` rebuilds a log from the published tree, refusing if nothing in
it was signed by this identity, because that is what a lost key looks like
from the inside (ADR-63, ADR-64).

`docs/SPEC.md` §7.1 states the compatibility contract that came out of it:
existing claim fields are frozen, new ones are additive and optional, and an
unrecognized claim kind is preserved as a verifiable opaque claim rather
than rejected — so an older kan meeting a newer log says what it does not
understand instead of failing outright (ADR-44).

The storage boundary is explicit rather than conventional: `docs/SPEC.md`
§10.1 classifies authoritative kan data, authoritative external inputs, and
derived projections, while a committed catalog and conformance suite bind that
model to every implemented persistence surface.

The current forward plan is in [`docs/ROADMAP.md`](docs/ROADMAP.md). Public
ATProto publication and version-aware views are specified by
[RFC 3](rfcs/3-authoritative-lexicon-publication.md), currently in Review, and
tracked as a dependency graph under
[#29](https://github.com/kan-tools/kan/issues/29). The older HostedRelay/version
sequence in `.design/sync-layer-architecture-and-staging.md` and ADR-35 remains
historical context, not the current public publication checklist.

Upgrading an existing installation to the identity-first, URI-native build is
a deliberate one-time sequence. Back up the old repository identity and signed
log, initialize the installation identity once, and then migrate and verify one
repository at a time using the
[`identity/URI migration guide`](docs/IDENTITY-URI-MIGRATION.md).

## Identity

Current governed scopes sign new claims with the installation's configured
`did:kan` actor. Historical v1 claims keep their original per-repository
`did:key`, and scope-less workspaces retain the released v1 identity behavior
for compatibility. See the
[`identity/URI migration guide`](docs/IDENTITY-URI-MIGRATION.md) before moving
an existing repository onto a governed scope.

For that released v1 identity model, **as of v0.12 the signing key is rooted by
default in a `0600` file at `.kan/seed`** — not the OS keychain — and `.kan/`
is gitignored, so the secret stays on your machine and out of the repo. The
first v1 write tells you exactly where the key lives and how to back it up:

```
kan: this repo's identity is rooted in .kan/seed, a 0600 file readable by anything running as you.
`kan-v1 identity phrase` prints its 24-word recovery phrase -- that is the backup, and it is the only copy not on this disk.
`kan-v1 identity protect` moves the secret into the OS keychain if you want it there.
```

Take the recovery phrase before you need it, at a real terminal — it is the
only copy not on the disk.

**Why the file is the default, and the keychain is opt-in.** On macOS a
keychain entry is authorised to *the binary that created it*, so every
`cargo install` produces a binary the keychain does not recognise, and a
keychain-by-default kan would prompt — or hang — on every rebuild
([#96](https://github.com/kan-tools/kan/issues/96)). A `0600` seed file has
no such failure mode. The trade-off is that the seed is plaintext on disk
rather than encrypted at rest; for a repo you are *developing*, on an
encrypted disk, with `.kan/` gitignored, that is usually the right call.

If you do want the secret encrypted at rest, move it into the keychain — and
back out again — at any time:

```sh
kan-v1 identity protect      # move the seed into the OS keychain
kan-v1 identity unprotect    # move it back to a 0600 file
```

**Escape hatches, for CI and specific key files:**

- `KAN_IDENTITY_FILE=/path/to/key` names a signing key file directly. A
  read that names a *missing* path is an error, never a silent mint — CI
  should point this at a provisioned key.
- `KAN_NO_KEYCHAIN=1` makes kan behave as though no keychain exists. It is
  an opt-*out*; set it only where you never want a keychain call, and only
  for a workspace whose seed already lives in a file.

## Several roles in one repo

A workspace can sign as more than one identity — a director and a prover in
an agent loop, say, so each one's claims are attributable to the role that
made them. It has to be declared, because a second identity appearing by
accident is the failure kan guards hardest against: the claims already in the
log are signed by the first identity, and the default fold trusts one author,
so an unnoticed new key makes an entire log vanish from every read at exit 0.

Declare a role, then write as it:

```sh
kan-v1 identity role add director            # mints .kan/roles.d/director, registers it
KAN_IDENTITY_FILE=.kan/roles.d/director kan-v1 observe finding "the verdict"
```

Declaring your first role also records the identity that was already signing
here, as `primary` — so `--trust roles` covers claims written before the roles
existed, not only after. `kan-v1 identity role list` shows the whole set.

**Reading needs no identity at all.** The default view is `local` — every
author with a claim in this workspace's log — so every role reads back every
role's claims, and a read resolves, derives and persists no signing key.
Narrow it when you want a specific frame:

```sh
kan-v1 show finding --trust me               # this installation's kan author alone
kan-v1 show finding --trust roles            # only the identities declared in .kan/roles
kan-v1 show finding --trust role:prover      # one declared role, by name
kan-v1 show finding --trust did:key:zA --trust did:key:zB   # two explicit authors
```

In a current scope, `me` resolves the selected system profile and its public
`did:kan` state; it never names the repository transport DID. In a v1
workspace it retains the compatibility meaning of the active workspace
signer. This resolution is read-only and does not access a signing credential.

A `did:key:...=<weight>` form is accepted, but note that **weights are not
yet folded**: an author is either in the view or not, so `did=0.5` currently
gives the same result as naming the author plainly (kan warns when you pass
one). Weighted composition is a planned enrichment, not a shipped one.

Any read that leaves claims out says so, on both the human output and `--json`
(`excluded_by_trust`), so a partial view cannot pass for a complete one. And
`kan-v1 identity authors` lists every author in the log, marking which were
declared — `local` minus `roles`, which is how an identity you did not expect
shows up as data rather than as an absence.

Claims that arrived as committed `.claims/` files are excluded from the
default view unless their author has also written to this log; admit them by
naming the author in `--trust`.

Pointing `KAN_IDENTITY_FILE` at a *new* key file without declaring it is
still refused whenever the log is non-empty. That refusal is the #90 guard,
and declaring a role is how you tell it apart from the accident it exists to
stop.

## Name

`kan` is the Kan extension: the universal construction that builds the best global
object from local data along a map. That is, more or less, the whole job.

## License

MIT

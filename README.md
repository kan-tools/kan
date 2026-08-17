# kan

**Local reasoning, global coherence — memory for AI agents.**

Where `git` versions your code, `kan` remembers your reasoning. Each agent keeps
its own signed, append-only record of what it observed, planned, decided, and
resolved — and `kan` folds those local records into one coherent view on demand,
without a central authority deciding what's true.

Nothing is overwritten. Nothing is flattened. Nothing is lost.

## Quickstart

```sh
cargo install kan                 # or: cargo install --path . from a clone

cd your-project                   # kan runs inside a git repo and anchors
git init && git commit --allow-empty -m init   # ...to its history, so it needs at least one commit

kan observe login-bug "panics on empty input"  # record a finding
kan decide login-bug "guard the empty case before parsing"
kan block  login-bug "waiting on the parser refactor"
kan resolve login-bug "fixed in a1b2c3d"        # resolve closes it out

kan status                        # one line per subject: its settled state
kan show login-bug                # that subject's full claim history
kan issues                        # everything not yet resolved
kan context --budget 800          # the highest-value claims within a token budget
```

The first write mints this repo's signing identity (see
[Identity](#identity)); nothing is written to a repo until you record a
claim, and reading a repo that has none leaves it untouched. To let an agent
use kan over MCP instead of the CLI, run `kan mcp install`.

## Machine-readable orientation

Programs usually do not need every claim body merely to learn what a workspace
contains. Use a manifest-then-hydrate read:

```sh
kan status --json                              # compact subject manifest
kan show --json --subject login-bug            # hydrate exact subjects
kan show --json --subject one --subject two
kan show --json --prefix telos/                 # hydrate visible prefixes
kan show --all --json                           # complete live claim graph
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

Pre-1.0 (`v0.13.0-beta.1`). The local-only spine — one human,
one-or-more agents, one repo — is built and hardening.

Sharing works in both directions as of v0.8. `kan publish <subject>` writes
a subject's signed claims into a tracked `.claims/` directory, so they
travel with the repo: visible in `git diff`, reviewable in a PR, and
readable by someone without kan installed. Each record carries a complete
signed claim, so it is verified rather than trusted — editing the prose
changes the CID and fails verification. A clone now **reads** that tree
too: foreign-authored claims are verified against their own author and
folded from an overlay beside the local log, which stays *claims I
authored* (ADR-43, ADR-59).

Reading is where the trust posture becomes visible. The default view shows
only the identity you are running as, and any read that leaves claims out
now says so — on both the human output and `--json` — so a partial view
cannot pass for a complete one (ADR-57).

Durability arrived in v0.9. `kan status` says, per subject, whether it would
survive losing `.kan/` — `unpublished`, `published`, or `stale` — and
`kan restore` rebuilds a log from the published tree, refusing if nothing in
it was signed by this identity, because that is what a lost key looks like
from the inside (ADR-63, ADR-64).

`docs/SPEC.md` §7.1 states the compatibility contract that came out of it:
existing claim fields are frozen, new ones are additive and optional, and an
unrecognized claim kind is preserved as a verifiable opaque claim rather
than rejected — so an older kan meeting a newer log says what it does not
understand instead of failing outright (ADR-44).

The rest of sync — a private-team `HostedRelay` transport, then the public
atproto layer — has a concrete staged plan targeting `v1.0.0`; see
`.design/sync-layer-architecture-and-staging.md` and
[`ADR-0035`](adrs/35-sync-layer-staging-plan-and-a-version-roadmap-through-1-0.md).

## Identity

kan signs every claim with a per-repo `did:key`. **As of v0.12 the signing
key is rooted by default in a `0600` file at `.kan/seed`** — not the OS
keychain — and `.kan/` is gitignored, so the secret stays on your machine
and out of the repo. The first write tells you exactly where the key lives
and how to back it up:

```
kan: this repo's identity is rooted in .kan/seed, a 0600 file readable by anything running as you.
`kan identity phrase` prints its 24-word recovery phrase -- that is the backup, and it is the only copy not on this disk.
`kan identity protect` moves the secret into the OS keychain if you want it there.
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
kan identity protect      # move the seed into the OS keychain
kan identity unprotect    # move it back to a 0600 file
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
kan identity role add director            # mints .kan/roles.d/director, registers it
KAN_IDENTITY_FILE=.kan/roles.d/director kan observe finding "the verdict"
```

Declaring your first role also records the identity that was already signing
here, as `primary` — so `--trust roles` covers claims written before the roles
existed, not only after. `kan identity role list` shows the whole set.

**Reading needs no identity at all.** The default view is `local` — every
author with a claim in this workspace's log — so every role reads back every
role's claims, and a read resolves, derives and persists no signing key.
Narrow it when you want a specific frame:

```sh
kan show finding --trust me               # the active identity alone
kan show finding --trust roles            # only the identities declared in .kan/roles
kan show finding --trust role:prover      # one declared role, by name
kan show finding --trust did:key:zA --trust did:key:zB   # two explicit authors
```

A `did:key:...=<weight>` form is accepted, but note that **weights are not
yet folded**: an author is either in the view or not, so `did=0.5` currently
gives the same result as naming the author plainly (kan warns when you pass
one). Weighted composition is a planned enrichment, not a shipped one.

Any read that leaves claims out says so, on both the human output and `--json`
(`excluded_by_trust`), so a partial view cannot pass for a complete one. And
`kan identity authors` lists every author in the log, marking which were
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

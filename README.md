# kan

**Local reasoning, global coherence — memory for AI agents.**

Where `git` versions your code, `kan` remembers your reasoning. Each agent keeps
its own signed, append-only record of what it observed, planned, decided, and
resolved — and `kan` folds those local records into one coherent view on demand,
without a central authority deciding what's true.

Nothing is overwritten. Nothing is flattened. Nothing is lost.

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

Pre-1.0 (`v0.9.2-beta.1` on crates.io). The local-only spine — one human,
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
`.design/sync-layer-architecture-and-staging.md` and `docs/DECISIONS.md`
ADR-35.

## Identity and the keychain

kan signs every claim with a per-repo `did:key`. By default the key lives in
the OS keychain, encrypted at rest, and `kan identity phrase` gives you a
24-word recovery phrase — take it before you need it, at a real terminal.

**If you rebuild kan often, set this and forget the keychain exists:**

```sh
export KAN_IDENTITY_FILE="$PWD/.kan/identity"
```

On macOS a keychain entry is authorised to *the binary that created it*, so
every `cargo install` produces a binary the keychain does not recognise and
you get an auth prompt — forever, on every rebuild. `KAN_IDENTITY_FILE` names
a key file directly and never consults the keychain, so nothing can block. The
file is written `0600`.

The trade-off is real and worth stating: that key is then plaintext on disk
rather than encrypted at rest. For a repo you are *developing*, whose `.kan/`
is gitignored, on an encrypted disk, that is usually the right call. For a
repo you are *using*, prefer the keychain. Tracked as
[#96](https://github.com/kan-tools/kan/issues/96) and
[#105](https://github.com/kan-tools/kan/issues/105) — the long-term answer is
a single root of trust with enclave-held keys, not a nicer prompt.

`KAN_NO_KEYCHAIN=1` is the other half of this: it makes kan behave as though
no keychain exists, keeping secrets in `0600` files under `.kan/` without you
having to name a specific key file. Use it if you simply don't want your keys
in the keychain.

If a keychain read does block, kan now says so on stderr after a second or
two, naming both escape hatches — rather than looking like a slow command
(#90).

CI and any non-interactive caller should always set `KAN_IDENTITY_FILE`.

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

**Reading is the half that surprises people.** The default view is `Solo` —
only the identity you are running as — so a role reads back only its own
claims. Widen it:

```sh
kan show finding --trust roles            # every declared role, plus the active one
kan show finding --trust did:key:zA --trust did:key:zB=0.5   # explicit, weighted
```

Any read that leaves claims out now says so, on both the human output and
`--json` (`excluded_by_trust`), so a partial view can no longer pass for a
complete one. Whether `Solo` should stay the *default* once a workspace has
several roles is open — [#121](https://github.com/kan-tools/kan/issues/121).

Pointing `KAN_IDENTITY_FILE` at a *new* key file without declaring it is
still refused whenever the log is non-empty. That refusal is the #90 guard,
and declaring a role is how you tell it apart from the accident it exists to
stop.

## Name

`kan` is the Kan extension: the universal construction that builds the best global
object from local data along a map. That is, more or less, the whole job.

## License

MIT

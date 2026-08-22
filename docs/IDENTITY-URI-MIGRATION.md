# Migrating to identity-first, URI-native kan

This guide is for moving an existing local kan installation and its repositories
onto the RFC 1 identity and RFC 2 local-URI architecture. It targets builds that
contain PRs [#246](https://github.com/kan-tools/kan/pull/246),
[#258](https://github.com/kan-tools/kan/pull/258), and
[#260](https://github.com/kan-tools/kan/pull/260). Until that work has a unique
release tag, record the exact Git commit you build: `kan --version` alone may
not distinguish two development builds with the same manifest version.

The safe order is:

1. keep the old binary available;
2. stop writers and back up every repository under the old binary;
3. build the new binary alongside the old one;
4. initialize and back up one installation-level system identity;
5. initialize one governed scope per repository, verifying reads before any
   current-format write;
6. make and verify the first current write; and
7. replace the installed binary only after every repository is settled.

Do repositories one at a time. Do not run two migration attempts against the
same `.kan/` directory, and stop MCP servers, hooks, editors, agents, and other
processes that might write claims while a backup or migration is running.

## What changes—and what does not

Existing signed claims are not rewritten into new claims. A migrated repository
becomes a governed kan scope, historical v1 claims remain verifiable, and new
claims use the `kan-claim-v2` codec and the installation's `did:kan` actor.

The principals remain deliberately distinct:

- the old per-repository `did:key` continues to identify historical v1 claims;
- when the first current write opens an existing repository, that old
  repository key is retained as the repository-transport principal; and
- the new installation-level `did:kan` is the kan author and initial governance
  root for newly initialized scopes.

Do not try to import an old repo seed or 24-word repo recovery phrase as the new
P-256 system recovery key. They are different key systems with different jobs.

The authoritative repository data is primarily the signed log and identity
material under `.kan/`, plus the new `.kan/scope/` inception state. The SQLite
index is disposable. `.claims/` is a tracked publication projection, not a
replacement for the private log unless everything needed was deliberately
published. A Git bundle does not contain `.kan/`.

## Stop conditions

Stop instead of improvising if any of these applies:

- the repository root has a `.git` **file** rather than a `.git` directory;
  that is a linked worktree or submodule, and workspace ownership remains open
  under [#197](https://github.com/kan-tools/kan/issues/197);
- the repository is shallow or has no commit, because scope inception binds the
  Git genesis;
- `.kan/repository` exists; this is pre-release identity state that current kan
  deliberately refuses to reinterpret;
- the old binary cannot resolve the old repository identity or read the full
  claim set;
- backup verification fails; or
- `kan init` reports incomplete, conflicting, inaccessible, or unverifiable
  identity/scope state.

Never fix one of these by deleting identity files. Preserve the exact state and
investigate it first.

## 1. Build the new binary alongside the old one

Do not overwrite the installed binary yet. Record the old executable and build
the reviewed source as a separate path:

```sh
OLD_KAN="$(command -v kan)"
"$OLD_KAN" --version

git clone https://github.com/kan-tools/kan.git kan-upgrade
cd kan-upgrade
git checkout <reviewed-tag-or-commit>
git rev-parse HEAD
cargo build --release --locked

NEW_KAN="$PWD/target/release/kan"
"$NEW_KAN" --version
```

If the source checkout already exists, use it instead of cloning another. Keep
`OLD_KAN` and `NEW_KAN` available in the same terminal for the steps below.

On macOS, replacing or relocating a binary can change keychain authorization.
If an old repository key is protected in the keychain, use the **old binary**
to export its recovery phrase and, preferably, move it back to its owner-only
file before replacing anything:

```sh
"$OLD_KAN" identity phrase --yes
"$OLD_KAN" identity unprotect
```

`identity phrase` must be run interactively in a trusted terminal. Do not put
the phrase in a command argument, shell history, redirected plaintext file,
issue, chat, or ordinary cloud storage. If the repository was never protected,
`unprotect` is unnecessary.

## 2. Back up one repository under the old binary

Run these steps from the repository's ordinary primary checkout. Choose a
backup location outside the Git working tree, on an encrypted disk or volume
with access restricted to you.

```sh
REPO_ROOT="$(git rev-parse --show-toplevel)"
REPO_NAME="$(basename "$REPO_ROOT")"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_ROOT="$HOME/kan-migration-backups/${REPO_NAME}-${STAMP}"

mkdir -p "$BACKUP_ROOT"
chmod 700 "$HOME/kan-migration-backups" "$BACKUP_ROOT"

test -d "$REPO_ROOT/.git"
test "$(git -C "$REPO_ROOT" rev-parse --is-shallow-repository)" = "false"
git -C "$REPO_ROOT" rev-parse --verify HEAD
test ! -e "$REPO_ROOT/.kan/repository"

"$OLD_KAN" --version > "$BACKUP_ROOT/old-kan-version.txt"
git -C "$REPO_ROOT" status --short > "$BACKUP_ROOT/git-status.txt"
git -C "$REPO_ROOT" bundle create "$BACKUP_ROOT/repository.bundle" --all
tar -C "$REPO_ROOT" -cpf "$BACKUP_ROOT/dot-kan.tar" .kan

if test -e "$REPO_ROOT/.claims"; then
  tar -C "$REPO_ROOT" -cpf "$BACKUP_ROOT/dot-claims.tar" .claims
fi

"$OLD_KAN" show --all --json > "$BACKUP_ROOT/before.json"
jq -r '.subjects[].claims[].cid' "$BACKUP_ROOT/before.json" \
  | LC_ALL=C sort -u > "$BACKUP_ROOT/before-cids.txt"

(cd "$BACKUP_ROOT" && shasum -a 256 ./* > SHA256SUMS)
```

The examples use macOS's `shasum -a 256`; on Linux, use `sha256sum` and
`sha256sum -c` for the corresponding two commands.

Review `git-status.txt`; the migration does not require a clean worktree, but
you need to know which unrelated files already differ. Verify the archive can
be listed and the bundle can be read:

```sh
tar -tf "$BACKUP_ROOT/dot-kan.tar" > /dev/null
git bundle verify "$BACKUP_ROOT/repository.bundle"
(cd "$BACKUP_ROOT" && shasum -a 256 -c SHA256SUMS)
```

Keep the old repo recovery phrase separately even though the archive contains
the current on-disk identity state. If you rely on `.claims/` for Git-based
recovery, do any desired v1 `kan publish --all` and commit that projection
**before** taking the final backup.

The JSON snapshot can contain private claim text. Protect it like `.kan/`, or
omit `before.json` only if you accept losing the strongest human-auditable
before/after comparison.

Repeat this section for every repository before initializing the system
identity. Record each repository's `REPO_ROOT` and matching `BACKUP_ROOT`; set
those two variables to the recorded pair again when you migrate that repository
in sections 4 and 5.

## 3. Initialize and back up the system identity once

This step is once per kan installation, not once per repository. The default
configuration roots are:

| Platform | Default root |
|---|---|
| macOS | `~/Library/Application Support/kan` |
| Linux | `${XDG_CONFIG_HOME:-~/.config}/kan` |
| Windows | `%APPDATA%\kan` |

`KAN_CONFIG_DIR` overrides those defaults. If you use it, set the same value for
every future kan invocation. Do not casually change roots between repositories.

If a config root already exists, archive it before initialization. For example,
on macOS with the default root:

```sh
SYSTEM_CONFIG="$HOME/Library/Application Support/kan"
SYSTEM_STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SYSTEM_BACKUP="$HOME/kan-migration-backups/system-${SYSTEM_STAMP}"

mkdir -p "$SYSTEM_BACKUP"
chmod 700 "$SYSTEM_BACKUP"

if test -e "$SYSTEM_CONFIG"; then
  tar -C "$(dirname "$SYSTEM_CONFIG")" -cpf \
    "$SYSTEM_BACKUP/system-config-before-init.tar" \
    "$(basename "$SYSTEM_CONFIG")"
  chmod 600 "$SYSTEM_BACKUP/system-config-before-init.tar"
  tar -tf "$SYSTEM_BACKUP/system-config-before-init.tar" > /dev/null
else
  touch "$SYSTEM_BACKUP/config-was-absent-before-init"
fi
```

Substitute the actual root on Linux or Windows, and use the value of
`KAN_CONFIG_DIR` if set. Then initialize:

```sh
"$NEW_KAN" identity init --alias daily
```

The command prints the exact config root, public `did:kan`, default actor,
credential paths, and verification method. It does not open a repository, and
an identical retry is idempotent. A different existing default actor is a
refusal, not an overwrite.

Immediately back up the **entire printed config root**, including:

- `credentials/recovery-daily.key`;
- `credentials/device-daily.key`;
- `identity/ledger/`;
- `identity/profiles/`; and
- the enrollment nonce.

Using the same `SYSTEM_CONFIG` and `SYSTEM_BACKUP` values:

```sh
tar -C "$(dirname "$SYSTEM_CONFIG")" -cpf \
  "$SYSTEM_BACKUP/system-config-after-init.tar" \
  "$(basename "$SYSTEM_CONFIG")"
chmod 600 "$SYSTEM_BACKUP/system-config-after-init.tar"
tar -tf "$SYSTEM_BACKUP/system-config-after-init.tar" > /dev/null
```

That tar file contains private keys and is not encrypted merely because it has
mode `0600`. Move a verified copy to encrypted, independently recoverable
storage. The new system recovery credential is currently a P-256 key file, not
the old repository's 24-word phrase; retaining the complete config state is the
safest recovery boundary.

## 4. Initialize one repository scope

Choose inception names deliberately. They are immutable discovery hints, and
the default is only the repository directory basename. For a hosted project,
an `owner:repo` name is usually clearer:

```sh
cd "$REPO_ROOT"
"$NEW_KAN" init --name example-org:example-repo
```

Repeat `--name` if the scope needs more than one inception-time name. The
command prints the stable `ScopeId`, governance root, actor, inception event,
and workspace root. With no new options, retrying an already initialized scope
only reports the installed scope.

`kan init` adds verified scope state; it does not rewrite historical claims or
append a current claim. Before making any write, capture and compare the read:

```sh
"$NEW_KAN" show --all --json > "$BACKUP_ROOT/after-init.json"
jq -r '.subjects[].claims[].cid' "$BACKUP_ROOT/after-init.json" \
  | LC_ALL=C sort -u > "$BACKUP_ROOT/after-init-cids.txt"

comm -23 "$BACKUP_ROOT/before-cids.txt" \
  "$BACKUP_ROOT/after-init-cids.txt" \
  > "$BACKUP_ROOT/missing-after-init.txt"
test ! -s "$BACKUP_ROOT/missing-after-init.txt"

"$NEW_KAN" status
"$NEW_KAN" identity authors
```

The JSON is not expected to be byte-identical: current reads add scope,
identity-standing, admission, and trust information. The invariant is that no
previously visible claim CID disappears. Investigate any missing CID before
continuing.

## 5. Make the first current write

The first successful write after scope initialization is the real writer
cutover. It selects the system actor, retains the old repository identity as
transport identity, migrates the live claim collection to its canonical name,
and appends a `kan-claim-v2` claim. Older kan binaries should not be used on the
live repository after this point.

Use the next real claim you intended to record, or make the migration itself a
truthful canary:

```sh
"$NEW_KAN" observe \
  "identity and URI migration verified from the pre-migration CID inventory" \
  --subject migration/identity-uri-cutover

"$NEW_KAN" show migration/identity-uri-cutover --json
"$NEW_KAN" show --all --json > "$BACKUP_ROOT/after-first-write.json"
jq -r '.subjects[].claims[].cid' "$BACKUP_ROOT/after-first-write.json" \
  | LC_ALL=C sort -u > "$BACKUP_ROOT/after-first-write-cids.txt"

comm -23 "$BACKUP_ROOT/before-cids.txt" \
  "$BACKUP_ROOT/after-first-write-cids.txt" \
  > "$BACKUP_ROOT/missing-after-first-write.txt"
test ! -s "$BACKUP_ROOT/missing-after-first-write.txt"
```

Confirm that the new claim reports codec `kan-claim-v2`, the expected scope,
the system `did:kan` author, and separate validity, identity-standing, scope-
admission, and view-trust judgments. Then take a second, post-migration `.kan`
archive without overwriting the pre-migration one.

Repeat sections 4 and 5 for each repository already backed up in section 2. Do
**not** run `identity init` again for each repo; all should use the same
deliberately selected installation actor unless you have designed a different
multi-profile arrangement.

## 6. Replace the installed binary last

After every repository has passed the before/after CID check:

```sh
cd /path/to/kan-upgrade
cargo install --path . --locked --force
kan --version
command -v kan
```

Restart MCP servers and other long-lived processes only after the replacement.
Keep the old binary and all pre-migration archives until the new installation
has survived normal use and an independent backup verification.

## Important compatibility limits

- **Linked worktrees:** explicit local URI resolution fails closed there while
  #197 is unsettled. Migrate and use kan from the primary checkout.
- **Legacy role-key selection:** in a governed current scope, writes use the
  selected system actor. `KAN_IDENTITY_FILE` remains a v1 compatibility
  selection for a scope-less workspace; do not assume it selects a current
  role author after migration. Audit agent scripts that export it.
- **Publication:** current-scope publication is intentionally waiting on the
  URI/transport publication boundary. Preserve existing `.claims/`, but expect
  `kan publish` of new current claims to refuse until that work lands.
- **Older binaries:** reads before the first current write may still understand
  the historical log, but after the v2 append and collection migration an older
  binary is not a rollback tool. Restore the pre-migration archive instead.
- **Derived files:** SQLite and other projections may change during ordinary
  reads and may be rebuilt. Never use an index hash as the claim-preservation
  check; compare signed claim CIDs.

## Rollback without destroying evidence

There is no in-place down-migration. Stop all kan processes and preserve the
failed/new state before restoring anything.

For one repository, move the current `.kan` outside the working tree and
extract the pre-migration archive:

```sh
ROLLBACK_STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mv "$REPO_ROOT/.kan" "$BACKUP_ROOT/dot-kan-failed-$ROLLBACK_STAMP"
tar -C "$REPO_ROOT" -xpf "$BACKUP_ROOT/dot-kan.tar"
```

Restore `.claims/` only if it changed, using its separate archive, and keep the
newer state quarantined until any post-backup claims have been accounted for.
Test the restoration with the old binary and compare against `before-cids.txt`.

Do not roll back or delete the installation-level system config while any
successfully migrated repository depends on it. If system initialization itself
failed before any repo was initialized, quarantine the new config root and
restore its pre-init archive (or restore its prior absence). When in doubt,
perform the restoration in a separate checkout or on a copied disk image first.

## Per-repository checklist

- [ ] Writers and MCP servers stopped.
- [ ] Primary, non-shallow checkout with a real `.git/` directory.
- [ ] Old binary reads all expected subjects and claims.
- [ ] Old repo recovery phrase secured; protected key unprotected if needed.
- [ ] Git bundle, `.kan`, optional `.claims`, and CID inventory backed up and
      verified.
- [ ] System identity initialized once and its entire config root backed up.
- [ ] Immutable scope names reviewed before `kan init`.
- [ ] No pre-migration CID missing after scope initialization.
- [ ] First current write has the expected scope, author, codec, and judgments.
- [ ] No pre-migration CID missing after the first current write.
- [ ] Post-migration archive stored separately.
- [ ] Old binary not used on the migrated live repository.

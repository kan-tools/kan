#!/usr/bin/env bash
# One migration cell: a workspace written by a *released* kan, read by the
# build in this working tree.
#
# Direction matters and is the opposite of day's matrix. day asks what a
# released binary does with shapes this commit writes, because day reads
# someone else's data. kan owns its own on-disk format, so the question with
# teeth is the reverse: does this build still read a workspace an older kan
# created? That is a guarantee, not a characterization -- a user upgrades kan
# and expects their log to still be there.
#
# Prints exactly one outcome word on stdout. Everything else goes to stderr so
# the caller can capture the outcome cleanly.
#
# Outcomes:
#   ok                the old workspace reads correctly under this build
#   unbuildable       the tag does not compile with the current toolchain
#   unwritable        the tag builds but could not create a workspace here
#   claims-lost       this build sees fewer claims than the old binary wrote
#   identity-changed  claims are present but excluded by trust (the #90 shape)
set -uo pipefail

OLD_BIN="${1:?usage: run-migration-cell.sh <old-kan-binary> <new-kan-binary> [mode]}"
NEW_BIN="${2:?usage: run-migration-cell.sh <old-kan-binary> <new-kan-binary> [mode]}"
# How the identity is resolved on BOTH sides of the cell. See the block below.
MODE="${3:-identity-file}"

say() { echo "$@" >&2; }

# Absolute, because this script cds into a scratch workspace and a relative
# binary path would silently stop resolving there -- which presents as
# "the old binary wrote nothing", i.e. as a migration finding rather than as
# a broken harness.
[ -e "$OLD_BIN" ] && OLD_BIN="$(cd "$(dirname "$OLD_BIN")" && pwd)/$(basename "$OLD_BIN")"
[ -e "$NEW_BIN" ] && NEW_BIN="$(cd "$(dirname "$NEW_BIN")" && pwd)/$(basename "$NEW_BIN")"

if [ ! -x "$OLD_BIN" ]; then
  echo "unbuildable"
  exit 0
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work" || { echo "unwritable"; exit 0; }

git init -q .
git -c user.email=matrix@example.com -c user.name=matrix commit -q --allow-empty -m init

# The identity axis (#146 part 3).
#
# Every cell used to drive `KAN_IDENTITY_FILE`, which meant the matrix
# exercised exactly one of the three ways kan resolves an identity -- and the
# one that short-circuits the other two. `load_or_create_for_workspace`
# returns early when that variable is set, so v0.9's seed-rooting has never
# been run against an older workspace by this matrix, and #146's defect lived
# in a branch no cell could reach. A harness that drives one shape cannot see
# a defect that lives in the other; that is the same finding as the bug.
#
#   identity-file  KAN_IDENTITY_FILE on both sides. The original cell.
#   seed           Neither side names a key file. The writer falls back to a
#                  plaintext `.kan/identity` (no Secret Service on CI), and
#                  the reader takes the seed-rooting path -- freshness judged
#                  from identity files, with the log as the tiebreaker the
#                  files cannot see.
case "$MODE" in
  identity-file)
    # A dedicated key file rather than the keychain: CI has no Secret Service,
    # and every kan since KAN_IDENTITY_FILE existed honours this. Older
    # versions that do not simply fall back to a plaintext `.kan/identity`,
    # which is equally fine here -- the point is a workspace, not which path
    # produced it.
    export KAN_IDENTITY_FILE="$work/key"
    ;;
  seed)
    unset KAN_IDENTITY_FILE
    # Honoured only by v0.9+; older writers ignore it and fall back to
    # plaintext anyway on a machine with no keychain, which is the same
    # on-disk result.
    export KAN_NO_KEYCHAIN=1
    ;;
  *)
    say "unknown mode: $MODE"
    echo "unwritable"
    exit 0
    ;;
esac

# `--subject` rather than a positional: the positional form only arrived in
# v0.7.1 (Wave 1, ADR-53), and this script has to drive every released
# version, including the ones that predate it.
wrote=0
for i in 1 2 3; do
  if "$OLD_BIN" observe "claim number $i written by the old binary" \
       --subject "migration-subject" >/dev/null 2>&1; then
    wrote=$((wrote + 1))
  fi
done

if [ "$wrote" -eq 0 ]; then
  say "the old binary wrote nothing -- CLI shape too different to drive"
  echo "unwritable"
  exit 0
fi
say "old binary wrote $wrote claim(s)"

# Point the reader at whatever key the *writer* actually used.
#
# `KAN_IDENTITY_FILE` did not exist before v0.2, so an early tag ignores it
# and writes `.kan/identity` instead. Leaving the env var pointing at a file
# that was never created makes this build meet a non-empty log with a
# would-be-new identity, trip the `WouldMintSecondIdentity` guard, and exit --
# which the first version of this script scored as `claims-lost`. That is the
# guard working exactly as designed being reported as data loss, and the
# whole value of the matrix rests on not confusing the two.
#
# Reproducing "same machine, same workspace, upgraded binary" means using the
# key that is actually there.
if [ "$MODE" = identity-file ] && [ ! -f "$KAN_IDENTITY_FILE" ]; then
  if [ -f "$work/.kan/identity" ]; then
    say "writer predates KAN_IDENTITY_FILE -- reading with .kan/identity, as an upgrade would"
    export KAN_IDENTITY_FILE="$work/.kan/identity"
  else
    # No key file anywhere: the writer put its key in the OS keychain. The
    # faithful upgrade is for the reader to consult the keychain too, which
    # means not naming a file at all.
    #
    # On CI (Linux, no Secret Service) this branch is unreachable -- every
    # version falls back to a plaintext `.kan/identity`. It exists so the
    # script is honest when run by hand on macOS, where taking this branch
    # can hang on a keychain prompt for a rebuilt binary. That hang is #96,
    # not a migration outcome, which is exactly why CI rather than a
    # developer laptop is the ground truth for this table.
    say "writer left no key file -- it used the OS keychain; reading the same way"
    unset KAN_IDENTITY_FILE
  fi
fi

# Now the upgrade: this build, same workspace, no migration command run. The
# whole point is that opening it is enough.
out="$("$NEW_BIN" show migration-subject --json 2>/dev/null)"
if [ -z "$out" ]; then
  say "this build produced no output for the migrated workspace"
  echo "claims-lost"
  exit 0
fi

visible="$(echo "$out" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["claims"]))' 2>/dev/null)"
excluded="$(echo "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("excluded_by_trust",0))' 2>/dev/null)"
visible="${visible:-0}"
excluded="${excluded:-0}"
say "this build sees $visible claim(s), $excluded excluded by trust"

# The #90 shape, which v0.8's disclosure is what makes detectable at all: the
# claims are on disk and verifiable, and invisible because the identity moved.
# Before `excluded_by_trust` existed this was indistinguishable from an empty
# log, which is precisely why it shipped twice.
if [ "$excluded" -gt 0 ] && [ "$visible" -lt "$wrote" ]; then
  echo "identity-changed"
  exit 0
fi

if [ "$visible" -lt "$wrote" ]; then
  echo "claims-lost"
  exit 0
fi

echo "ok"

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
#   claims-altered    the right NUMBER of claims, but not the same claims --
#                     the CID set moved, so a body, author or subject changed
#                     under a migration that reported success
#   keychain-unused   the cell asked for the keychain and did not get it: the
#                     writer predates keychain support, or the runner's
#                     keychain was unreachable. The workspace is plaintext, so
#                     this cell did NOT exercise the keychain plane. Recorded
#                     rather than scored `ok`, so the table shows exactly which
#                     versions that plane actually covers.
#   keychain-blocked  the read never returned: a keychain entry created by the
#                     writer is ACL'd to that binary, so the reader waits on an
#                     authorization prompt nobody answers (#96). A hang is not
#                     a pass and is not a crash, so it gets its own word.
set -uo pipefail

# How long the reader may take before a hang is called a hang. Generous: a
# cold index rebuild over a small log is well under a second, and #96's wait
# is unbounded, so anything in between is not ambiguous.
READ_TIMEOUT="${READ_TIMEOUT:-120}"

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
    #
    # NAMING A PATH THAT DOES NOT EXIST STOPPED BEING A WAY TO CREATE ONE.
    # This mode used to point the variable at `$work/key` and rely on the
    # WRITER minting it. Every released writer does. v0.12's REQ-2 made a
    # selection naming an absent target an error on principle -- never a mint,
    # never a fallback -- so from v0.12 on, a writer driven this way writes
    # NOTHING and the cell scores `unwritable`.
    #
    # `unwritable` is a legitimate recorded outcome, so that would not have
    # gone red. The axis would simply have stopped testing anything, quietly,
    # for every writer from v0.12 onward -- which is #146's finding exactly:
    # a harness that drives one shape cannot see a defect that lives in the
    # other. Caught before v0.12 shipped, by running the current build as a
    # writer by hand.
    #
    # So the key is made to EXIST first, by whatever means the writer of the
    # day supports, and only then named on both sides. See `seed_the_key_file`.
    export KAN_IDENTITY_FILE="$work/key"
    ;;
  seed)
    unset KAN_IDENTITY_FILE
    # Honoured only by v0.9+; older writers ignore it and fall back to
    # plaintext anyway on a machine with no keychain, which is the same
    # on-disk result.
    export KAN_NO_KEYCHAIN=1
    ;;
  keychain)
    # The plane no cell has ever run, and the one every identity defect has
    # lived on: #90, #96, #107, #170 and #180.
    #
    # Neither side names a key file and the keychain is NOT disabled, so the
    # writer files its secret in the OS keychain and the reader must find it
    # there. On Linux there is no Secret Service and this degrades to the
    # plaintext path, which is why this mode is only scheduled on macOS.
    #
    # EXPECT THIS TO BLOCK, and that is the measurement rather than a broken
    # cell. Writer and reader are different binaries, so the entry's
    # trusted-application ACL does not match on the second one and macOS
    # raises an authorization prompt no CI runner can answer. That is #96, and
    # recording it as `keychain-blocked` turns it from an anecdote into a
    # migration outcome with a row in the table.
    unset KAN_IDENTITY_FILE
    unset KAN_NO_KEYCHAIN
    ;;
  *)
    say "unknown mode: $MODE"
    echo "unwritable"
    exit 0
    ;;
esac

# Make the selected key EXIST before the writer is asked to use it.
#
# Two routes, because which one works depends on the writer's vintage, and
# the harness must not silently lose the axis when the first stops working
# (see the identity-file note above).
seed_the_key_file() {
  target="$1"
  scratch="$(mktemp -d)"
  (
    cd "$scratch" || exit 1
    git init -q .
    git -c user.email=matrix@example.com -c user.name=matrix commit -q --allow-empty -m init
    # This scratch workspace exists ONLY to mint a key file, so it must not
    # touch the OS keychain: an entry here would be junk that outlives the
    # run, and on macOS reaching for one is #96 -- the hang this harness is
    # trying to measure, fired somewhere it would just look like a broken
    # cell. Not setting this is what made the first version of route 2 fail.
    export KAN_NO_KEYCHAIN=1
    # And it must NOT inherit the selection the caller just exported. The mode
    # block sets KAN_IDENTITY_FILE to the very path being created, so leaving
    # it set makes route 2's own `commit_identity` resolve a selection whose
    # target does not exist yet and fail with SelectionMissing -- the command
    # that exists to create the key refusing because the key is not there.
    unset KAN_IDENTITY_FILE
    # Route 1: pre-v0.12 writers mint at a named-but-absent path.
    KAN_IDENTITY_FILE="$target" "$OLD_BIN" observe seed --subject seed \
      >/dev/null 2>>"$scratch/seed.log"
    if [ ! -f "$target" ]; then
      # Route 2: v0.12+ refuses to mint from a selection (REQ-2), so ask for a
      # key deliberately. `role add` is the supported way to create one.
      "$OLD_BIN" identity role add matrix --key "$target" \
        >/dev/null 2>>"$scratch/seed.log"
    fi
  )
  if [ ! -f "$target" ] && [ -s "$scratch/seed.log" ]; then
    say "--- key seeding failed; writer said: ---"
    tail -5 "$scratch/seed.log" >&2
  fi
  rm -rf "$scratch"
  [ -f "$target" ]
}

# BEST-EFFORT, NEVER FATAL -- and the first version of this got that wrong.
#
# Making a failed seed fatal broke the six OLDEST tags (v0.1.1 through
# v0.6.0), which CI caught as `unwritable` against an expected `ok`. Neither
# route exists that far back: `KAN_IDENTITY_FILE` is not honoured yet, and
# `identity role add` does not exist yet. Those writers were always handled
# correctly further down -- they ignore the variable, write `.kan/identity`,
# and the reader is repointed at it, exactly as a real upgrade would be. The
# early exit ran before that could happen.
#
# So a fix aimed at FUTURE writers broke PAST ones, which is the hazard of
# repairing a harness whose whole job is spanning versions. Seeding helps
# where it can and stays out of the way where it cannot.
if [ "$MODE" = identity-file ]; then
  if seed_the_key_file "$KAN_IDENTITY_FILE"; then
    say "seeded the selected key file at $KAN_IDENTITY_FILE"
  else
    say "could not seed a key file with this writer -- continuing; if it predates"
    say "KAN_IDENTITY_FILE it will write .kan/identity and the reader follows it"
  fi
fi

# `--subject` rather than a positional: the positional form only arrived in
# v0.7.1 (Wave 1, ADR-53), and this script has to drive every released
# version, including the ones that predate it.
#
# STDOUT IS CAPTURED RATHER THAN DISCARDED, because a write verb prints the
# CID it just appended. Those CIDs are what make an integrity check possible
# at all: kan is content-addressed, so equal CIDs before and after mean
# byte-identical claim content -- no need for a richer corpus to detect a
# corrupted body.
wrote=0
written_cids=""
for i in 1 2 3; do
  if out="$("$OLD_BIN" observe "claim number $i written by the old binary" \
              --subject "migration-subject" 2>>"$work/writer.log")"; then
    wrote=$((wrote + 1))
    cid="$(printf '%s\n' "$out" | grep -oE '^baf[a-z0-9]+$' | head -1)"
    [ -n "$cid" ] && written_cids="$written_cids$cid
"
  fi
done

if [ "$wrote" -eq 0 ]; then
  # SAY WHY, not just that. `unwritable` was reported for five tags on the
  # keychain axis with no captured reason, which is not a result anyone can
  # act on -- and this harness had already produced one `unwritable` that was
  # its own bug rather than a property of the writer, so an unexplained one
  # is not safe to record as an expectation.
  say "the old binary wrote nothing. Its stderr:"
  if [ -s "$work/writer.log" ]; then
    tail -20 "$work/writer.log" >&2
  else
    say "  (nothing on stderr either -- CLI shape too different to drive)"
  fi
  echo "unwritable"
  exit 0
fi
say "old binary wrote $wrote claim(s)"

# DID THE KEYCHAIN MODE ACTUALLY USE THE KEYCHAIN?
#
# Asked positively, because the first run of this mode returned `ok` for all
# fourteen tags and the only evidence that the keychain was involved was the
# ABSENCE of a fallback warning. An instrument must prove it measured what it
# claims, and two different things produce a silent plaintext workspace here:
# a runner whose keychain cannot be reached, and a writer old enough to
# predate keychain support altogether. Either way the cell would score `ok`
# for a plane it never touched -- a plausible green, which is the failure
# shape this whole harness keeps finding.
#
# So the secret's location is checked directly. A keychain-held secret leaves
# a POINTER and no plaintext; a degraded one leaves the plaintext.
if [ "$MODE" = keychain ]; then
  if [ -f .kan/seed ] || [ -f .kan/identity ]; then
    say "keychain mode degraded to a plaintext secret -- this writer either predates"
    say "keychain support or the runner's keychain was unreachable. NOT a keychain test."
    echo "keychain-unused"
    exit 0
  fi
  if [ ! -f .kan/seed-id ] && [ ! -f .kan/identity-id ]; then
    say "keychain mode left neither a plaintext secret nor a keychain pointer"
    echo "unwritable"
    exit 0
  fi
  say "keychain confirmed in use: $(ls .kan/seed-id .kan/identity-id 2>/dev/null | tr '\n' ' ')"
fi

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
#
# Under a DEADLINE, because on the keychain axis the failure mode is a hang
# rather than an error: an entry the writer created is ACL'd to the writer's
# binary, so the reader waits on an authorization prompt that never comes
# (#96). `timeout(1)` is GNU and absent from a stock macOS runner, so this is
# done with a background job and a watchdog instead of assuming coreutils.
read_out="$work/read.json"
"$NEW_BIN" show migration-subject --json >"$read_out" 2>/dev/null &
reader_pid=$!
( sleep "$READ_TIMEOUT"; kill -9 "$reader_pid" 2>/dev/null ) >/dev/null 2>&1 &
watchdog_pid=$!
if wait "$reader_pid" 2>/dev/null; then reader_rc=0; else reader_rc=$?; fi
kill "$watchdog_pid" 2>/dev/null
wait "$watchdog_pid" 2>/dev/null

# 137 = SIGKILL: the watchdog fired, so the read never returned on its own.
if [ "$reader_rc" -eq 137 ]; then
  say "the read did not return within ${READ_TIMEOUT}s -- blocked, not failed"
  echo "keychain-blocked"
  exit 0
fi

out="$(cat "$read_out" 2>/dev/null)"
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

# INTEGRITY, not just arithmetic. Until now this script compared two integers
# and nothing else -- so a migration that preserved three claims while
# corrupting every one of their bodies scored `ok`. kan is content-addressed,
# which makes the strong check cheap: if the CID set the reader sees equals
# the CID set the writer produced, every claim is byte-identical, including
# its author, subject, kind and text.
#
# Conditional on having captured the writer's CIDs: the oldest tags may print
# something this cannot parse. Where that happens the count check still
# applies and the weaker coverage is SAID rather than assumed -- a silent
# downgrade would be the table claiming a guarantee it did not check.
if [ -n "$written_cids" ]; then
  expected="$(printf '%s' "$written_cids" | grep -c . || true)"
  if [ "$expected" -eq "$wrote" ]; then
    read_cids="$(printf '%s' "$out" \
      | python3 -c 'import json,sys; print("\n".join(sorted(c["cid"] for c in json.load(sys.stdin)["claims"])))' \
      2>/dev/null)"
    want="$(printf '%s' "$written_cids" | grep . | sort)"
    if [ "$read_cids" != "$want" ]; then
      say "CID set moved: the claim count survived but the claims did not"
      echo "claims-altered"
      exit 0
    fi
    say "integrity: all $wrote claim CIDs match what the writer produced"
  else
    say "integrity: only $expected of $wrote CIDs were parseable -- count check only"
  fi
else
  say "integrity: writer printed no parseable CIDs -- count check only"
fi

echo "ok"

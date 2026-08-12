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
#   fix-route-missing the documented remedy for this cell's failure does not
#                     exist in this build yet. Recorded rather than omitted, so
#                     the table says a remedy is OWED rather than staying silent.
#   fix-route-blocked the remedy is itself blocked by the condition it exists to
#                     remedy -- `unprotect` must READ the keychain to move the
#                     secret out of it, and reading is what #96 prevents. If a
#                     cell ever produces this, the exit from the trap is inside
#                     the trap and that is a design finding, not a flaky run.
#   fix-route-failed  the remedy ran and returned non-zero.
#   identity-unresolvable
#                     the claims fold, but this build cannot resolve an
#                     identity for the workspace at all -- so it cannot sign
#                     here and cannot name its own DID. Readable, not writable.
#                     Previously invisible: the cell's only reader action was a
#                     read, and a read resolves no identity (ADR-83).
#   read-hung         the read did not return, on an axis where the keychain is
#                     not in play. Distinguished from keychain-modal so an
#                     unexplained hang is not given a known cause's name.
#   keychain-unused   the cell asked for the keychain and did not get it: the
#                     writer predates keychain support, the runner's keychain
#                     was unreachable, or the cell's own `identity protect`
#                     opt-in failed. The workspace is plaintext, so
#                     this cell did NOT exercise the keychain plane. Recorded
#                     rather than scored `ok`, so the table shows exactly which
#                     versions that plane actually covers.
#   write-refused     the workspace reads correctly but this build cannot WRITE
#                     to it. Separate from the read outcomes because reading an
#                     old log and appending to it are different guarantees, and
#                     only the second exercises the MST rebuild that carries a
#                     flat pre-kan#204 tree forward.
#   write-hung        the upgrade write did not return. As `read-hung`, but on
#                     the write path, so a hang is not filed under a read.
#   write-lost-claims the write succeeded and cost a claim: something readable
#                     before it is not readable after. This is the shape
#                     kan#204's read-invisibility path produced -- a rebuild
#                     that drops one claim and adds the new one leaves the
#                     COUNT plausible, so this compares CID sets, not integers.
#   keychain-modal    the read never returned: a keychain entry created by the
#                     writer is ACL'd to that binary, so the reader waits on an
#                     authorization prompt nobody answers (#96). A hang is not
#                     a pass and is not a crash, so it gets its own word.
#
#                     MODAL, not "blocked", and the word is doing work. Nothing
#                     is preventing the read: the OS is waiting on a human
#                     decision that a headless runner cannot make. "Blocked"
#                     reads as a wall and sends people looking for what broke;
#                     "modal" names the actual state and implies the actual
#                     remedy -- answer the prompt, or take a route that asks no
#                     question (KAN_IDENTITY_FILE, KAN_NO_KEYCHAIN=1). This is
#                     macOS's trusted-application ACL working as designed, not
#                     a defect in kan; #30's per-agent identity work is the fix.
#
#                     `fix-route-blocked` below deliberately keeps "blocked",
#                     because its blockage is a different thing: not the wait,
#                     but the circularity of a remedy that depends on the
#                     condition it exists to remove.
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

# THE KEYCHAIN MODES REFUSE TO RUN ON A DEVELOPER MACHINE.
#
# They deliberately unset KAN_NO_KEYCHAIN, so they write to the REAL login
# keychain and can block on an authorization prompt. Every operational note in
# this project says not to do that outside CI, and the author of this guard ran
# `keychain-recovery` locally minutes after telling two reviewers not to. The
# run was harmless only because the keychain write happened to fail.
#
# A rule that its own author breaks within the hour is a rule that wanted to be
# a guard. CI sets CI=true; a human who genuinely means it can set
# KAN_ALLOW_KEYCHAIN_CELL=1.
case "${MODE:-}" in
  keychain|keychain-recovery)
    if [ -z "${CI:-}" ] && [ -z "${KAN_ALLOW_KEYCHAIN_CELL:-}" ]; then
      say "refusing: mode '$MODE' uses the REAL OS keychain and can block on an"
      say "authorization prompt. It is meant for CI. Set KAN_ALLOW_KEYCHAIN_CELL=1"
      say "if you genuinely intend to write to your login keychain."
      echo "refused-locally"
      exit 0
    fi ;;
esac

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
  keychain-recovery)
    # DOES THE DOCUMENTED FIX ROUTE ACTUALLY WORK?
    #
    # The `keychain` mode records that upgrading a keychain-rooted workspace
    # BLOCKS (#96). A table that records a failure and never tests its remedy
    # tells half the story -- and the remedy is the part a user actually needs,
    # so it is the part most worth knowing is broken.
    #
    # Same setup as `keychain`; the difference is what happens after the block.
    # The reader attempts `kan identity unprotect`, which is REQ-3.3's exit for
    # a grandfathered workspace, and the cell records whether that command
    # exists and whether it succeeds.
    unset KAN_IDENTITY_FILE
    unset KAN_NO_KEYCHAIN
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
    # recording it as `keychain-modal` turns it from an anecdote into a
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

# THE KEYCHAIN IS AN OPT-IN AS OF v0.12 (REQ-3), so the cell has to ASK for
# it -- the same thing REQ-3 asks of an operator. A v0.12+ writer roots in a
# plaintext 0600 secret and never reaches the keychain on its own, which is
# what turned this axis green-while-measuring-nothing for every future
# version (`keychain-unused`, a legitimate committed outcome).
#
# Gated on the SUBCOMMAND'S EXISTENCE rather than a version string, so the
# harness never has to know which tag introduced what -- the mistake that
# once made a probe use today's binary to simulate an old one with opposite
# behaviour. Writers without `identity protect` are left alone and reach the
# plane natively (or don't, and the guard below says so).
#
# A protect failure is NOT fatal: the cell is scored on what is on disk by
# the guard below, not on protect's exit code.
if [ "$MODE" = keychain ] || [ "$MODE" = keychain-recovery ]; then
  if { [ -f .kan/seed ] || [ -f .kan/identity ]; } \
     && "$OLD_BIN" identity protect --help >/dev/null 2>&1; then
    if "$OLD_BIN" identity protect --yes >/dev/null 2>>"$work/writer.log"; then
      say "writer has 'identity protect' -- ran it, opting this workspace into the keychain"
    else
      say "'identity protect' failed (see writer.log) -- continuing; the guard below"
      say "scores what is actually on disk"
    fi
  fi
fi

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
if [ "$MODE" = keychain ] || [ "$MODE" = keychain-recovery ]; then
  if [ -f .kan/seed ] || [ -f .kan/identity ]; then
    say "keychain mode degraded to a plaintext secret -- this writer predates keychain"
    say "support, the runner's keychain was unreachable, or the protect opt-in above"
    say "failed (writer.log has its stderr). NOT a keychain test."
    echo "keychain-unused"
    exit 0
  fi
  # NO PLAINTEXT IS THE SIGNAL. A POINTER FILE IS NOT.
  #
  # The first version of this treated "no plaintext AND no pointer" as
  # `unwritable`, which turned five tags (v0.2.0..v0.6.0) red for a layout
  # that is working correctly. Those versions predate `.kan/identity-id`
  # entirely: the keychain account was derived from the canonicalized
  # `.kan/identity` PATH, so the secret went into the keychain leaving no
  # pointer at all. That is exactly the scheme v0.7's REQ-5 replaced, because
  # a path-derived account meant a moved checkout silently minted a new DID.
  #
  # So a guard added to stop a false green produced a false red, on the
  # oldest and least-exercised layout in the corpus. The sound inference is
  # the simple one: if no plaintext secret exists, the secret is in the
  # keychain, because there is nowhere else for it to be.
  pointer="$(ls .kan/seed-id .kan/identity-id 2>/dev/null | tr '\n' ' ')"
  if [ -n "$pointer" ]; then
    say "keychain confirmed in use, pointer: $pointer"
  else
    say "keychain confirmed in use with NO pointer file -- the pre-v0.7.0"
    say "path-derived account scheme. This is the legacy layout, exercised here"
    say "for the first time by any cell."
  fi
fi

# Point the reader at whatever key the *writer* actually used.
#
# `KAN_IDENTITY_FILE` did not exist before v0.7.0 (checked against every tag,
# not inferred), so an early tag ignores it
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
  # Only the keychain axis can be blocked BY the keychain. Calling a Linux
  # seed-mode hang, an OOM kill or a slow runner "keychain-modal" would name
  # a known cause for an unexplained failure.
  if [ "$MODE" = keychain ]; then echo "keychain-modal"; else echo "read-hung"; fi
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

# DOES THIS BUILD STILL RESOLVE THE WORKSPACE'S IDENTITY? Until now the cell
# never asked, and that was its largest hole.
#
# The only reader action was `show --json`, and a read resolves NO identity at
# all -- `Workspace::open_read_only` says so in its own comment, and ADR-83
# makes it deliberate. So every outcome this script produced was independent of
# whether the upgraded binary could reach the writer's key. The keychain axis
# in particular claimed, in the expectations table, that "a secret filed by one
# binary is found and used by a DIFFERENT, later binary" -- and measured
# nothing of the kind. A workspace this build can read but can neither write to
# nor name its own DID in was scored `ok`.
#
# `kan identity did` is the cheapest reader action that DOES resolve one: it
# routes through `commit_identity` (src/cli/mod.rs::IdentityAction), which is
# the same path a post-upgrade write takes. Under the same deadline, because
# on the keychain axis this is where a #96 block would actually surface.
# THE REMEDY, ATTEMPTED BEFORE THE IDENTITY PROBE, so what the probe measures
# is the state a user would be in AFTER following the documented advice rather
# than before it.
if [ "$MODE" = keychain-recovery ]; then
  if ! "$NEW_BIN" identity unprotect --help >/dev/null 2>&1; then
    say "the documented fix route does not exist in this build"
    echo "fix-route-missing"
    exit 0
  fi
  say "attempting the fix route: kan identity unprotect"
  "$NEW_BIN" identity unprotect --yes >/dev/null 2>"$work/unprotect.err" &
  fix_pid=$!
  ( sleep "$READ_TIMEOUT"; kill -9 "$fix_pid" 2>/dev/null ) >/dev/null 2>&1 &
  fix_watchdog=$!
  if wait "$fix_pid" 2>/dev/null; then fix_rc=0; else fix_rc=$?; fi
  kill "$fix_watchdog" 2>/dev/null; wait "$fix_watchdog" 2>/dev/null

  if [ "$fix_rc" -eq 137 ]; then
    # The sharpest outcome this harness can produce: the remedy for the block
    # is itself blocked. `unprotect` must READ the keychain to move the secret
    # out of it, and reading is what #96 prevents -- so the exit from the trap
    # may be inside the trap.
    say "the fix route itself did not return within ${READ_TIMEOUT}s:"
    [ -s "$work/unprotect.err" ] && tail -10 "$work/unprotect.err" >&2
    echo "fix-route-blocked"
    exit 0
  fi
  if [ "$fix_rc" -ne 0 ]; then
    say "the fix route failed:"
    [ -s "$work/unprotect.err" ] && tail -10 "$work/unprotect.err" >&2
    echo "fix-route-failed"
    exit 0
  fi
  say "fix route completed; measuring the workspace it left behind"
fi

author="$(printf '%s' "$out" \
  | python3 -c 'import json,sys; c=json.load(sys.stdin)["claims"]; print(c[0]["author"] if c else "")' \
  2>/dev/null)"

did_out="$work/did.txt"
"$NEW_BIN" identity did >"$did_out" 2>"$work/did.err" &
did_pid=$!
( sleep "$READ_TIMEOUT"; kill -9 "$did_pid" 2>/dev/null ) >/dev/null 2>&1 &
did_watchdog=$!
if wait "$did_pid" 2>/dev/null; then did_rc=0; else did_rc=$?; fi
kill "$did_watchdog" 2>/dev/null; wait "$did_watchdog" 2>/dev/null

if [ "$did_rc" -eq 137 ]; then
  say "resolving an identity did not return within ${READ_TIMEOUT}s. Its stderr:"
  # kan prints its own slow-keychain warning after 1.5s
  # (src/sign.rs::SlowKeychainWarning), and that warning names the cause. The
  # first version of this branch discarded it -- so the log recorded THAT the
  # read blocked and threw away the tool's own account of WHY, on the one axis
  # added to observe keychain behaviour.
  if [ -s "$work/did.err" ]; then tail -20 "$work/did.err" >&2; else say "  (nothing on stderr)"; fi
  if [ "$MODE" = keychain ]; then echo "keychain-modal"; else echo "read-hung"; fi
  exit 0
fi

resolved="$(tr -d '[:space:]' <"$did_out" 2>/dev/null)"
if [ "$did_rc" -ne 0 ] || [ -z "$resolved" ]; then
  # Readable but not writable. A real and previously invisible migration
  # outcome: the claims fold, and the upgraded binary cannot sign here or even
  # name the workspace's own identity.
  say "this build cannot resolve an identity for the migrated workspace:"
  tail -5 "$work/did.err" >&2 2>/dev/null
  echo "identity-unresolvable"
  exit 0
fi

if [ -n "$author" ] && [ "$resolved" != "$author" ]; then
  # #90, detected directly rather than inferred from a trust exclusion.
  say "identity moved: claims authored by $author, this build resolves $resolved"
  echo "identity-changed"
  exit 0
fi
say "identity resolves to $resolved, matching the claims' author"

# The trust-exclusion form of the same question, kept as a secondary signal.
# NOTE it cannot fire on a single-writer workspace under the current default:
# `local_trust` trusts EVERY author in the log (src/workspace.rs::local_trust),
# so `excluded_by_trust` is structurally 0 here. It was the only #90 detector
# this harness had, and it had been dead since Local became the default base --
# which is why the DID comparison above exists rather than a tightened
# threshold.
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
    want="$(printf '%s' "$written_cids" | grep . | LC_ALL=C sort)"
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

# THE UPGRADE WRITE. Until now every cell's only reader action was a read, so
# the matrix proved this build can READ a workspace an older kan wrote and
# never that it can WRITE to one. That gap mattered the moment kan took over
# its own MST (kan#204, ADR-90): an old kan wrote a FLAT tree, and the first
# write under this build rebuilds it canonically. That rebuild is the closest
# thing to a migration kan has, it happens automatically, and nothing here
# exercised it.
#
# Gated on the cell having otherwise passed. A cell that is already blocked,
# hung or lossy has said what it needs to; making it also attempt a write
# would give one failure two names. So no row that is healthy today can flip
# for an environmental reason -- only for a real one.
say "upgrade write: appending one claim to the migrated workspace"
write_err="$work/write.err"
"$NEW_BIN" observe "written by this build after reading an older kan's workspace" \
  --subject migration-subject >/dev/null 2>"$write_err" &
writer_pid=$!
( sleep "$READ_TIMEOUT"; kill -9 "$writer_pid" 2>/dev/null ) >/dev/null 2>&1 &
write_watchdog=$!
if wait "$writer_pid" 2>/dev/null; then writer_rc=0; else writer_rc=$?; fi
kill "$write_watchdog" 2>/dev/null
wait "$write_watchdog" 2>/dev/null

if [ "$writer_rc" -eq 137 ]; then
  say "the upgrade write did not return within ${READ_TIMEOUT}s"
  echo "write-hung"
  exit 0
fi
if [ "$writer_rc" -ne 0 ]; then
  say "the upgrade write failed: $(head -c 400 "$write_err" 2>/dev/null)"
  echo "write-refused"
  exit 0
fi

# The write must not have cost anything. Re-read and require that every CID
# the old binary wrote is STILL there -- the count alone would be satisfied by
# a rebuild that dropped one claim and added the new one, which is precisely
# the shape kan#204's read-invisibility path produced.
after="$("$NEW_BIN" show migration-subject --json 2>/dev/null)"
after_cids="$(printf '%s' "$after" \
  | python3 -c 'import json,sys; print("\n".join(sorted(c["cid"] for c in json.load(sys.stdin)["claims"])))' \
  2>/dev/null)"
after_n="$(printf '%s' "$after_cids" | grep -c . || true)"

if [ "$after_n" -lt $((wrote + 1)) ]; then
  say "after the upgrade write this build sees $after_n claims, expected $((wrote + 1))"
  echo "write-lost-claims"
  exit 0
fi
if [ -n "${read_cids:-}" ]; then
  missing="$(comm -23 <(printf '%s\n' "$read_cids" | LC_ALL=C sort) \
                      <(printf '%s\n' "$after_cids" | LC_ALL=C sort) | grep -c . || true)"
  if [ "$missing" -gt 0 ]; then
    say "the upgrade write dropped $missing claim(s) that were readable before it"
    echo "write-lost-claims"
    exit 0
  fi
  say "upgrade write: all $wrote pre-existing claims survived, plus the new one"
fi

echo "ok"

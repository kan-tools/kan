#!/usr/bin/env bash
# Which released tags are HISTORICAL WRITERS for this build's migration matrix.
#
# The matrix asks one question per cell: does THIS build still read a workspace
# an OLDER released kan wrote. A tag only answers that question if it actually
# produces a different binary from the reader. When it does not, the cell puts
# one binary in both roles -- writer and reader -- and measures nothing.
#
# The workflow already excluded the tag being released, with the right reason:
# "a version is not a historical writer for its own release". That exclusion was
# by REF NAME, which is a name-shaped approximation of a content-shaped
# property, and it left the general case open. kan#205 is what came through the
# gap: a `workflow_dispatch` from a HEAD sitting at (or docs-only ahead of) a
# released tag put that tag in the matrix, the writer and reader compiled from
# the same source, and the keychain cell scored `ok` -- a binary reading a
# keychain entry it created itself, which the table then read as migration
# working. Four such cells over five runs looked exactly like nondeterminism,
# and the "alternation" people kept trying to explain was dispatch-vs-tag-push.
#
# So the exclusion is stated in terms of content:
#
#     a tag is a historical writer iff it builds something other than this build
#
# approximated by the (src tree, Cargo.lock, Cargo.toml) triple -- the same
# triple the workflow hashes into its reader cache key, for the same reason.
# A version bump alone is enough to make a tag a real writer: it changes
# Cargo.toml, so it changes the binary.
#
# This is the `keychain-unused` lesson applied one level up. That outcome exists
# because a cell that did not exercise the keychain plane must not be scored
# `ok`; the same holds for a cell that did not exercise an UPGRADE. The
# difference is that `keychain-unused` is an outcome and this is a selection:
# an excluded tag has no cell, so `tests/fixtures/migration-expectations.tsv`
# stays a function of (tag, mode) rather than acquiring a dependency on
# whichever commit happened to be HEAD.
#
# Exclusions are ANNOUNCED on stderr, never silent. A matrix that quietly
# dropped rows would read as "covered everything" while covering less, which is
# the failure this whole harness keeps finding in other clothes.
#
# The decision and the full evidence are ADR-91.
#
# Usage: select-migration-writers.sh [<current-ref-name>]
# Prints a compact JSON array of tag names on stdout.

set -euo pipefail

current="${1:-}"

# The triple that decides whether two revisions build the same thing. Cargo.toml
# is in here for the same reason the reader cache key has it: feature selection
# and [profile.release] change the binary while leaving src and Cargo.lock
# alone -- and so does the version bump, which is the only difference between
# some adjacent betas.
triple() {
  local rev="$1"
  local src lock toml
  src=$(git rev-parse "${rev}:src" 2>/dev/null || echo "no-src")
  lock=$(git rev-parse "${rev}:Cargo.lock" 2>/dev/null || echo "no-lock")
  toml=$(git rev-parse "${rev}:Cargo.toml" 2>/dev/null || echo "no-toml")
  printf '%s-%s-%s' "$src" "$lock" "$toml"
}

head_triple=$(triple HEAD)

writers=()
for tag in $(git tag --list 'v*.*.*' --sort=creatordate); do
  if [ -n "$current" ] && [ "$tag" = "$current" ]; then
    # Kept even though the content check below subsumes it on a tag push: it
    # states the intent directly, and it still holds if a release is ever cut
    # so that the tag and HEAD disagree on content.
    echo "excluding ${tag}: it is the version being released -- not a historical writer for its own release" >&2
    continue
  fi
  if [ "$(triple "$tag")" = "$head_triple" ]; then
    echo "excluding ${tag}: identical (src, Cargo.lock, Cargo.toml) to HEAD, so writer and reader are the same build and the cell would measure no upgrade (kan#205)" >&2
    continue
  fi
  writers+=("$tag")
done

# Emitted without jq. Tag names are matched against 'v*.*.*' and so contain
# nothing JSON needs escaped, and dropping the dependency is what lets
# tests/migration_writer_selection.rs drive this script directly rather than
# reimplementing its logic in Rust -- two implementations of one rule being
# the drift this repo keeps paying for.
if [ ${#writers[@]} -eq 0 ]; then
  echo '[]'
  exit 0
fi

out=""
for tag in "${writers[@]}"; do
  [ -n "$out" ] && out="${out},"
  out="${out}\"${tag}\""
done
printf '[%s]\n' "$out"

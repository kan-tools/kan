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
# `representatives` prunes to one writer per distinct layout era. Anything else
# (the default) returns every released tag.
scope="${2:-all}"

# THE ERA REPRESENTATIVES, curated on purpose where the rest of this file
# derives.
#
# Deriving them from the expectations table was the obvious move and is wrong:
# that table holds what we EXPECT, so grouping by it would let a regression
# hide in whichever member of a group we dropped. These are named instead,
# which means a human decides what an era is and the list is auditable.
#
# The eras, from tests/fixtures/migration-expectations.tsv:
#   v0.1.1              predates OS-keychain support entirely (keychain-unused)
#   v0.2.0 .. v0.6.0    the path-derived keychain account with NO pointer file,
#                       the scheme v0.7's REQ-5 replaced (identity-unresolvable,
#                       fix-route-failed). Two are kept, the era's first and
#                       last, so the span is covered rather than a point in it.
#   v0.7.0 ..           the modern pointer scheme. Thirteen tags assert an
#                       identical signature here, so two are enough: the era's
#                       first, and the last minor before the current one.
#
# WHY PRs ONLY. A tag push and a manual dispatch still run every writer, which
# is what keeps each release's rows honest: a row is PREDICTED until the cell
# executes, and if the newest tags never ran as writers their predictions would
# never convert — "a prediction that is never converted is indistinguishable
# from a measurement", which is the defect the conversion gate exists to stop.
# Releases are rare; ordinary PRs are not, and they are where the minutes go.
REPRESENTATIVES="v0.1.1-beta.1 v0.2.0-beta.1 v0.6.0-beta.1 v0.7.0-beta.1 v0.11.0-beta.1"

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

if [ "$scope" = representatives ]; then
  # A named representative that does not exist is an ERROR, not a quietly
  # smaller matrix. The same rule the workflow applies to a tag with no
  # committed row: silently covering less than you claim is the failure this
  # harness keeps finding.
  for tag in $REPRESENTATIVES; do
    if ! git rev-parse -q --verify "refs/tags/${tag}" >/dev/null; then
      echo "representative tag ${tag} does not exist -- refusing to run a smaller matrix than declared" >&2
      exit 1
    fi
  done
fi

writers=()
for tag in $(git tag --list 'v*.*.*' --sort=creatordate); do
  if [ "$scope" = representatives ]; then
    case " $REPRESENTATIVES " in
      *" $tag "*) ;;
      *) continue ;;
    esac
  fi
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

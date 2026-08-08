#!/usr/bin/env bash
# Resolve every source citation in the docs, and fail on one that does not.
#
# WHY THIS EXISTS. A `file.rs:385` citation is a curated enumeration of
# something derivable, and it rots the moment anything above it moves. v0.12
# shipped six of them wrong in one PR -- verified when written, then
# invalidated by a LATER COMMIT IN THE SAME PR that deleted ~476 lines above
# them. No amount of care fixes that class, because the citation was correct
# when checked and wrong when merged. So it is checked mechanically, at the
# tip, every time.
#
# TWO FORMS, and the second is the one to prefer:
#
#   path/to/file.rs:385            positional -- checked for existence only
#   path/to/file.rs::symbol_name   symbolic   -- resolved by definition
#
# Symbolic citations cannot rot: `src/sign.rs::workspace_identity` names the
# thing rather than where the thing currently sits. Positional ones are still
# accepted, because a line is sometimes genuinely what you mean (a specific
# comment, a fixture row), but they are only checked for plausibility -- the
# file exists and is long enough -- which is all that is knowable without
# guessing at intent.
#
# Usage:  scripts/check-citations.sh [paths...]     (default: .design docs CLAUDE.md)
# Exit:   0 all citations resolve; 1 otherwise, with each failure named.
set -uo pipefail

targets=("$@")
if [ ${#targets[@]} -eq 0 ]; then
  targets=(.design docs CLAUDE.md README.md)
fi

files=()
for t in "${targets[@]}"; do
  [ -e "$t" ] || continue
  if [ -d "$t" ]; then
    while IFS= read -r f; do files+=("$f"); done < <(find "$t" -name '*.md' -type f)
  else
    files+=("$t")
  fi
done

fail=0
checked=0

# --------------------------------------------------------- symbolic: file::symbol
#
# Resolved by looking for a DEFINITION, not any mention -- `fn name`, `struct
# name`, `const NAME`, and so on. A citation that resolves only because the
# symbol appears in a comment is exactly the false green this script exists to
# prevent.
while IFS= read -r hit; do
  doc="${hit%%:*}"
  ref="${hit#*:}"
  path="${ref%%::*}"
  sym="${ref##*::}"
  checked=$((checked + 1))
  if [ ! -f "$path" ]; then
    echo "MISSING FILE  $doc -> $ref"
    fail=1
    continue
  fi
  if ! grep -qE "(^|[^A-Za-z0-9_])(fn|struct|enum|trait|type|const|static|mod|impl|macro_rules!)[[:space:]]+${sym}\b" "$path"; then
    echo "UNRESOLVED    $doc -> $ref  (no definition of \`$sym\` in $path)"
    fail=1
  fi
done < <(grep -rhoE '[A-Za-z0-9_./-]+\.(rs|toml|sh|yml|yaml)::[A-Za-z0-9_]+' "${files[@]}" 2>/dev/null \
         | sort -u \
         | while read -r r; do grep -rlF "$r" "${files[@]}" 2>/dev/null | head -1 | sed "s|\$|:$r|"; done)

# ------------------------------------------------------- positional: file:line
#
# Only plausibility: the file exists, the line exists, and it is not blank.
# A blank line is never what anyone meant to cite and is the usual symptom of
# a citation that has drifted.
while IFS= read -r doc; do
  while IFS= read -r ref; do
    path="${ref%:*}"
    line="${ref##*:}"
    case "$path" in
      *.rs|*.toml|*.sh|*.yml|*.yaml) ;;
      *) continue ;;
    esac
    [ -f "$path" ] || continue          # not a repo path; skip rather than guess
    checked=$((checked + 1))
    total=$(wc -l < "$path" | tr -d "[:space:]")
    if [ "$line" -gt "$total" ]; then
      echo "OUT OF RANGE  $doc -> $ref  (file has $total lines)"
      fail=1
      continue
    fi
    if [ -z "$(sed -n "${line}p" "$path" | tr -d '[:space:]')" ]; then
      echo "BLANK LINE    $doc -> $ref  (drifted: cites an empty line)"
      fail=1
    fi
  done < <(grep -oE '[A-Za-z0-9_./-]+\.(rs|toml|sh|yml|yaml):[0-9]+' "$doc" 2>/dev/null | sort -u)
done < <(printf '%s\n' "${files[@]}")

echo "---"
if [ "$fail" -eq 0 ]; then
  echo "citations: $checked checked, all resolve"
else
  echo "citations: $checked checked, FAILURES ABOVE"
fi
exit "$fail"

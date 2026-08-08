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
# THE FIRST VERSION OF THIS SCRIPT MADE A FALSE CLAIM IN THIS HEADER, which is
# the defect class it exists to close, committed inside the fix for it. It said
# it resolved symbols "by DEFINITION, not any mention" while being a plain
# grep: a symbol appearing only inside `// mentions fn ghost` resolved, and so
# did one inside a string literal. It also SILENTLY SKIPPED citations whose
# file did not exist -- the single most common cause of citation rot -- so a
# dropped citation was indistinguishable from a passing one, and it reported
# "all resolve" over a citation pointing at a struct field.
#
# The repair is not a more careful sentence. It is `--self-test`, below: a
# committed fixture of citations that MUST be reported and citations that MUST
# resolve, asserted on every CI run. A claim about an instrument now has a
# witness, which is the practice this script is part of (`kan show
# instruments`).
#
# TWO FORMS, and the second is the one to prefer:
#
#   path/to/file.rs:385            positional -- existence and plausibility
#   path/to/file.rs::symbol_name   symbolic   -- resolved to a real definition
#
# Symbolic citations cannot rot: `src/sign.rs::workspace_identity` names the
# thing rather than where the thing currently sits. Positional ones are still
# accepted, because a line is sometimes genuinely what you mean, and are
# checked only for plausibility -- which is all that is knowable without
# guessing at intent, and is stated that way in the summary rather than
# reported as "resolves".
#
# Usage:
#   scripts/check-citations.sh [paths...]   default: .design docs CLAUDE.md README.md
#   scripts/check-citations.sh --self-test  prove it still detects each defect class
set -uo pipefail

# Definition-anchored. The symbol must be preceded, from the START OF THE LINE,
# by nothing but optional visibility/qualifiers and then a defining keyword.
# That is what excludes `// mentions fn x`, `/// see \`fn x\``, and
# `let s = "fn x"` -- all of which the previous plain grep accepted.
definition_re() {
  printf '^[[:space:]]*(pub([[:space:]]*\\([^)]*\\))?[[:space:]]+)?(async[[:space:]]+)?(unsafe[[:space:]]+)?(extern[[:space:]]+"[^"]*"[[:space:]]+)?(fn|struct|enum|trait|type|const|static|mod|union|macro_rules!)[[:space:]]+%s\\b' "$1"
}

scan() {
  local -a files=("$@")
  fail=0; checked_sym=0; checked_pos=0

  # ------------------------------------------------- symbolic: file::symbol
  local doc ref path sym
  while IFS= read -r doc; do
    while IFS= read -r ref; do
      path="${ref%%::*}"; sym="${ref##*::}"
      checked_sym=$((checked_sym + 1))
      if [ ! -f "$path" ]; then
        echo "MISSING FILE  $doc -> $ref"
        fail=1; continue
      fi
      case "$path" in
        *.rs) ;;
        *)
          # Symbolic form is Rust-only: there is no definition syntax to anchor
          # to elsewhere. Say so rather than failing it as unresolved, which
          # would read as "the symbol is missing".
          echo "UNSUPPORTED   $doc -> $ref  (symbolic form is Rust-only; cite a line instead)"
          fail=1; continue ;;
      esac
      if ! grep -qE "$(definition_re "$sym")" "$path"; then
        echo "UNRESOLVED    $doc -> $ref  (no DEFINITION of \`$sym\` in $path; a mention in a comment or string does not count)"
        fail=1
      fi
    done < <(grep -oE '[A-Za-z0-9_./-]+\.[A-Za-z0-9]+::[A-Za-z0-9_!]+' "$doc" 2>/dev/null | sort -u)
  done < <(printf '%s\n' "${files[@]}")

  # ----------------------------------------------- positional: file:line
  local line total
  while IFS= read -r doc; do
    while IFS= read -r ref; do
      path="${ref%:*}"; line="${ref##*:}"
      case "$path" in
        *.rs|*.toml|*.sh|*.yml|*.yaml) ;;
        *) continue ;;
      esac
      checked_pos=$((checked_pos + 1))
      if [ ! -f "$path" ]; then
        # NOT skipped. A renamed or deleted file is the commonest cause of
        # citation rot, and the previous version dropped it silently -- which
        # made a dropped citation look exactly like a passing one.
        echo "MISSING FILE  $doc -> $ref"
        fail=1; continue
      fi
      total=$(grep -c '' "$path")   # counts the last line even without a trailing newline
      if [ "$line" -gt "$total" ] || [ "$line" -lt 1 ]; then
        echo "OUT OF RANGE  $doc -> $ref  (file has $total lines)"
        fail=1; continue
      fi
      if [ -z "$(sed -n "${line}p" "$path" | tr -d '[:space:]')" ]; then
        echo "BLANK LINE    $doc -> $ref  (drifted: cites an empty line)"
        fail=1
      fi
    done < <(grep -oE '[A-Za-z0-9_./-]+\.[A-Za-z0-9]+:[0-9]+' "$doc" 2>/dev/null | sort -u)
  done < <(printf '%s\n' "${files[@]}")
}

# ------------------------------------------------------------------ self-test
#
# The positive control, committed. Its whole point is that a claim about this
# instrument has a witness rather than a sentence: if the checker stops
# detecting a defect class, THIS fails, rather than a repository silently going
# green. `bad.md` must produce a finding for every citation in it; `good.md`
# must produce none.
if [ "${1:-}" = --self-test ]; then
  fx="$(cd "$(dirname "$0")/.." && pwd)/tests/fixtures/citations"
  [ -d "$fx" ] || { echo "self-test: fixture directory missing at $fx"; exit 1; }
  cd "$fx" || exit 1

  bad_out=$(scan bad.md; :)
  expected=(
    "src/real.rs::ghost_in_comment"        # mention inside a line comment
    "src/real.rs::doc_comment_symbol"      # mention inside a doc comment
    "src/real.rs::string_literal_symbol"   # mention inside a string literal
    "src/real.rs::no_such_symbol"          # absent entirely
    "src/nonexistent.rs::anything"         # symbolic, missing file
    "src/nonexistent.rs:12"                # positional, missing file
    "src/short.rs:9999"                    # positional, past end
    "src/short.rs:2"                       # positional, blank line
  )
  missed=0
  for e in "${expected[@]}"; do
    printf '%s\n' "$bad_out" | grep -qF -- "$e" || { echo "self-test: NOT DETECTED -> $e"; missed=1; }
  done

  good_out=$(scan good.md; :)
  spurious=0
  if [ -n "$(printf '%s\n' "$good_out" | tr -d '[:space:]')" ]; then
    echo "self-test: FALSE POSITIVES on citations that should resolve:"
    printf '%s\n' "$good_out"
    spurious=1
  fi

  if [ "$missed" -eq 0 ] && [ "$spurious" -eq 0 ]; then
    echo "self-test: all ${#expected[@]} defect classes detected, no false positives"
    exit 0
  fi
  echo "self-test: FAILED -- this checker no longer detects what its header claims"
  exit 1
fi

# ---------------------------------------------------------------------- main
targets=("$@")
[ ${#targets[@]} -eq 0 ] && targets=(.design docs CLAUDE.md README.md)

files=()
for t in "${targets[@]}"; do
  [ -e "$t" ] || continue
  if [ -d "$t" ]; then
    while IFS= read -r f; do files+=("$f"); done < <(find "$t" -name '*.md' -type f)
  else
    files+=("$t")
  fi
done

# A ZERO DENOMINATOR IS NOT A PASS. Run from the wrong directory, or after a
# rename, the previous version printed "0 checked, all resolve" and exited 0 --
# a green check over nothing at all.
if [ ${#files[@]} -eq 0 ]; then
  echo "no documents found under: ${targets[*]}"
  echo "citations: refusing to report a pass over zero documents"
  exit 1
fi

scan "${files[@]}"

echo "---"
if [ "$fail" -eq 0 ] && [ $((checked_sym + checked_pos)) -eq 0 ]; then
  echo "citations: no citations found in ${#files[@]} document(s) -- refusing to report a pass"
  exit 1
fi
if [ "$fail" -eq 0 ]; then
  # Says what was actually established. "All resolve" was what made a citation
  # pointing at a struct field invisible: positional citations are checked for
  # PLAUSIBILITY, never for meaning anything.
  echo "citations: $checked_sym symbolic resolved to definitions, $checked_pos positional in range and non-blank"
  echo "           (positional citations are checked for plausibility, not for pointing at what the prose claims)"
else
  echo "citations: FAILURES ABOVE ($checked_sym symbolic, $checked_pos positional checked)"
fi
exit "$fail"

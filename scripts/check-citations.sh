#!/usr/bin/env bash
# Resolve every source citation in the docs, and fail on one that does not.
#
# WHY THIS EXISTS. A `file.rs:385` citation is a curated enumeration of
# something derivable, and it rots the moment anything above it moves. v0.12
# shipped six of them wrong in one PR -- verified when written, then
# invalidated by a LATER COMMIT IN THE SAME PR that deleted 517 lines from
# that file (the ~476 figure a first draft used was the NET of 517 deletions
# against 41 insertions -- a citation moves by the net, but the sentence was
# describing the deletion, so it was the wrong number for what it claimed). No amount of care fixes that class, because the citation was correct
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
# Symbolic citations do not rot the way line numbers do -- they resolve or
# fail, rather than silently coming to mean something else. They are NOT
# infallible: resolution is unscoped, so a symbol defined twice in one file
# resolves to whichever definition exists without saying which was meant. Positional ones are still
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
  # Qualifiers may stack in any of the orders rustc accepts, so they are each
  # optional and independent rather than a fixed sequence. The first version
  # put `const` only in the KEYWORD alternation, so `pub const fn x` consumed
  # `const` and then demanded the symbol where `fn` sits -- `const fn`,
  # `static mut` and `macro_rules!` were all UNRESOLVED. Caught by widening the
  # self-test fixture to one citation per keyword branch, which is what that
  # fixture is for.
  local sym="${1%!}"
  printf '^[[:space:]]*((pub([[:space:]]*\\([^)]*\\))?|default)[[:space:]]+)*((const|async|unsafe)[[:space:]]+)*(extern[[:space:]]+"[^"]*"[[:space:]]+)?(fn|struct|enum|trait|type|const|static([[:space:]]+mut)?|mod|union)[[:space:]]+%s\\b|^[[:space:]]*macro_rules![[:space:]]+%s\\b' "$sym" "$sym"
}

scan() {
  local -a files=("$@")
  fail=0; checked_sym=0; checked_pos=0; skipped_pos=0

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
      # `.md` is in this list because the most rot-prone line citation in the
      # repo pointed into one: `docs/DECISIONS.md` is 4000+ lines and grows by
      # ADR, and a citation into it was neither checked, counted, nor reported
      # -- the `case` skipped before the counter, so it was invisible in both
      # directions. That is B2's class surviving inside the branch that fixed
      # B2, for anything outside the whitelist.
      case "$path" in
        *.rs|*.toml|*.sh|*.yml|*.yaml|*.md) ;;
        *) skipped_pos=$((skipped_pos + 1)); continue ;;
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

  # THE VERDICT IS ASSERTED, NOT JUST THE FINDINGS. The first version grepped
  # the OUTPUT and never consulted the exit status -- so a checker that
  # detected all eight defects and then exited 0 passed it, and a cold review
  # built exactly that by deleting the `fail=1` assignments: two rotten
  # citations listed, a green summary printed under them, CI green.
  #
  # `status-line.sh --verify` asserts its verdict. This asserted only that the
  # detector still prints. That asymmetry was the tell.
  bad_out=$(scan bad.md; printf 'RC=%s' "$fail")
  bad_rc="${bad_out##*RC=}"; bad_out="${bad_out%RC=*}"
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

  if [ "$bad_rc" != "1" ]; then
    echo "self-test: DETECTED the defects but did not FAIL on them (fail=$bad_rc)."
    echo "           A checker that reports rot and exits 0 is a checker CI passes."
    missed=1
  fi

  good_out=$(scan good.md; printf 'RC=%s' "$fail")
  good_rc="${good_out##*RC=}"; good_out="${good_out%RC=*}"
  spurious=0
  if [ "$good_rc" != "0" ]; then
    echo "self-test: FAILED on citations that should resolve (fail=$good_rc)"
    spurious=1
  fi
  if [ -n "$(printf '%s\n' "$good_out" | tr -d '[:space:]')" ]; then
    echo "self-test: FALSE POSITIVES on citations that should resolve:"
    printf '%s\n' "$good_out"
    spurious=1
  fi

  if [ "$missed" -eq 0 ] && [ "$spurious" -eq 0 ]; then
    echo "self-test: ${#expected[@]} bad citations reported AND exit 1; good citations resolved AND exit 0"
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
  [ "$skipped_pos" -gt 0 ] && echo "           $skipped_pos positional citation(s) SKIPPED by extension -- not checked, not a pass"
  echo "           (positional citations are checked for plausibility, not for pointing at what the prose claims)"
else
  echo "citations: FAILURES ABOVE ($checked_sym symbolic, $checked_pos positional checked)"
fi
exit "$fail"

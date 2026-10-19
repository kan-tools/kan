#!/bin/sh
# Compare each supplied diff against candidate git ranges (excluding .design/reviews).
R=/Users/m/code/kan-tools/kan/.worktrees/kan-v2-copy-upgrade/.local-state/reviews
cd /Users/m/code/kan-tools/kan
try() { name=$1; a=$2; b=$3
  git diff "$a" "$b" -- . ':(exclude).design/reviews' > /tmp/rv_$$.diff
  if cmp -s /tmp/rv_$$.diff "$R/$name-change.diff"; then echo "$name == git diff $a $b (excl .design/reviews)"; fi
  git diff --stat=200 "$a" "$b" > /tmp/rv_$$.stat
  if cmp -s /tmp/rv_$$.stat "$R/$name-change.stat"; then echo "$name.stat == git diff --stat $a $b (all files)"; fi
}
for a in e0e2e64 7ab1afa 405fb9d 3aec393^ 262cad3 3f4b403 7126848 1c72b50^ 2e462a2; do for b in 8244375 e0e2e64 9aca45d 1c72b50 2e462a2; do
  for n in copy-planner lifecycle-followup ui-test-followup; do try $n $a $b; done; done; done
rm -f /tmp/rv_$$.diff /tmp/rv_$$.stat

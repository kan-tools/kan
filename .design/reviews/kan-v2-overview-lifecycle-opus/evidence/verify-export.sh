#!/bin/sh
# Compare every tracked file in git archive 7ab1afa with the export (byte-identical), and list extra non-evidence files.
set -eu
W=/Users/m/code/kan-tools/kan/.worktrees/kan-v2-proof-lifecycle
E=$W/.local-state/reviews/lifecycle
T=$(mktemp -d /tmp/kanarch.XXXXXX)
git -C $W archive 7ab1afa183880a06f409a454a49e87df5b7c33fc | tar -x -C $T
(cd $T && find . -type f | LC_ALL=C sort | xargs shasum -a 256) > $T.arch
(cd $E && find . -type f -not -path './review-evidence/*' -not -path './target/*' | LC_ALL=C sort | xargs shasum -a 256) > $T.exp
if diff $T.arch $T.exp; then echo "EXPORT == git archive 7ab1afa ($(wc -l < $T.arch) files)"; else echo "EXPORT DIFFERS"; fi
rm -rf $T $T.arch $T.exp

#!/bin/sh
set -u
umask 077
root=/Users/m/code/kan-tools/kan/.worktrees/kan-v2-copy-destination
cd "$root/.local-state/reviews/copy-followups" || exit 1
export CARGO_TARGET_DIR=/Users/m/code/kan-tools/kan/.worktrees/kan-v2-library-resilience/.local-state/target
export CARGO_BUILD_JOBS=4 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0
export KAN_CRYPTO_ORACLE_PYTHON=/Users/m/code/kan-tools/kan/.worktrees/kan-v2-encryption/.local-state/crypto-oracle-env/bin/python
export KAN_TLS_ORACLE_PYTHON=/opt/homebrew/bin/python3
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=commit.gpgsign GIT_CONFIG_VALUE_0=false
/opt/homebrew/bin/claude -p --safe-mode --model claude-opus-5-5 --effort medium --no-session-persistence --strict-mcp-config --mcp-config '{"mcpServers":{}}' --permission-mode dontAsk --tools 'Bash,Read,Glob,Grep,Write' --allowedTools Bash Read Glob Grep Write --output-format stream-json --verbose < "$root/.local-state/reviews/copy-followups-prompt.txt" > "$root/.local-state/reviews/copy-followups.jsonl" 2> "$root/.local-state/reviews/copy-followups.stderr"
review_exit=$?
printf '%s\n' "$review_exit" > "$root/.local-state/reviews/copy-followups.exit"
exit "$review_exit"

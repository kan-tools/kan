#!/usr/bin/env python3
"""Demonstrate fixture and inventory defects; restore tracked source in finally."""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ENV = dict(os.environ, CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0",
           CARGO_INCREMENTAL="0", GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="commit.gpgsign",
           GIT_CONFIG_VALUE_0="false", KAN_NO_KEYCHAIN="1")
script = (ROOT / "scripts/run-migration-cell.sh").read_text()
with tempfile.TemporaryDirectory(prefix="kan-migration-controls-") as directory:
    mutant = Path(directory) / "cell.sh"
    old = 'if [ "$MODE" != identity-file ] \\\n'
    if script.count(old) != 1:
        raise SystemExit("fixture mutation no longer matches exactly once")
    mutant.write_text(script.replace(old, 'if false \\\n', 1))
    binary = str(ROOT / "target/debug/kan-v1")
    output = subprocess.run(["bash", str(mutant), binary, binary, "seed"],
                            env=ENV, capture_output=True, text=True, check=True)
    if output.stdout.strip() != "unwritable":
        raise SystemExit("missing-init control did not reproduce unwritable")
    print("missing explicit initialization: detected unwritable")

source = ROOT / "src/migration_preflight.rs"
original = source.read_bytes()
old = 'kind: if selection == "public-identity-history" && !name.to_str().is_some_and(|n| n.starts_with(".tmp-")) { NoticeKind::Unsupported } else { NoticeKind::Excluded }'
text = original.decode()
if text.count(old) != 1:
    raise SystemExit("inventory mutation no longer matches exactly once")
try:
    source.write_text(text.replace(old, 'kind: NoticeKind::Excluded', 1))
    output = subprocess.run(["cargo", "test", "--features", "v2-storage", "--test",
                             "migration_preflight", "unknown_identity_entries_and_empty_selections_are_incomplete"],
                            cwd=ROOT, env=ENV, capture_output=True, text=True)
    combined = output.stdout + output.stderr
    if output.returncode == 0 or "test result: FAILED" not in combined or "selected_inventory_complete" not in combined:
        raise SystemExit("unknown-entry control did not reach the expected runtime assertion")
    print("unknown identity entries mislabeled excluded: detected runtime assertion")
finally:
    source.write_bytes(original)
subprocess.run(["cargo", "test", "--features", "v2-storage", "--test", "migration_preflight",
                "unknown_identity_entries_and_empty_selections_are_incomplete"],
               cwd=ROOT, env=ENV, check=True, stdout=subprocess.DEVNULL)
print("restored source: fixture passes")

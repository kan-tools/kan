#!/usr/bin/env python3
"""Opt-in, fail-open Claude hook capture. Never install itself or block a hook."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def run(args, raw):
    event = json.loads(raw)
    session = event.get("session_id")
    if not isinstance(session, str) or not session:
        raise ValueError("hook has no session identifier")
    # Avoid unsafe/oversized external identifiers in CLI arguments. The raw hook
    # preserves the original identifier and transcript relationship as evidence.
    session = hashlib.sha256(session.encode()).hexdigest()
    command = [args.kan, "harness-capture", "--spool", args.spool,
               "--key", args.key, "--recipient", args.recipient, "--session", session]

    def capture(extra, data=None):
        result = subprocess.run(command + extra, input=data, capture_output=True,
                                timeout=args.timeout, check=False)
        if result.returncode:
            # Do not echo captured content, credentials, or subprocess errors.
            raise RuntimeError("capture command failed")
        report = json.loads(result.stdout)
        if report.get("health", {}).get("recording_gap"):
            raise RuntimeError("capture spool could not retain all frames")

    # Preserve the exact hook bytes, including whitespace; a hook with a trailing
    # newline is already JSONL. No reserialization of original evidence.
    capture([], raw)
    if event.get("hook_event_name") in {
        "Stop", "SessionEnd", "PreCompact", "PostCompact", "SubagentStop"
    }:
        key = "agent_transcript_path" if event.get("hook_event_name") == "SubagentStop" else "transcript_path"
        named = event.get(key)
        if not isinstance(named, str):
            raise ValueError("hook has no transcript path")
        path = Path(named)
        root = Path(args.transcript_root).resolve(strict=True)
        # Resolve against an owner-configured allowlist root; never interpret an
        # arbitrary hook path as permission to capture other files on this host.
        resolved = path.resolve(strict=True)
        if path.is_symlink() or not resolved.is_relative_to(root) or not resolved.is_file():
            raise ValueError("transcript outside configured root")
        capture(["--input", str(resolved)])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("spool", "key", "recipient", "transcript-root"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--kan", default="kan-v2")
    parser.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args()
    try:
        raw = sys.stdin.buffer.read(16 * 1024 * 1024 + 1)
        if len(raw) > 16 * 1024 * 1024:
            raise ValueError("hook exceeds capture input budget")
        run(args, raw)
    except Exception as error:
        # Nonzero hook exits can alter harness behavior. Report the gap but
        # deliberately return success so recording cannot stop inference.
        print("kan harness recording gap: " + type(error).__name__ +
              "; inspect configured capture service", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

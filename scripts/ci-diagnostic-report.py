#!/usr/bin/env python3
"""Retain original step/job outcomes and fail after diagnostic collection."""
import argparse
import json
import os
from pathlib import Path


def report(results, title):
    rows = [(name, value.get("outcome", value.get("result", "unknown")))
            for name, value in results.items()]
    lines = [f"## {title}", "", "| Check | Original outcome |", "|---|---|"]
    lines.extend(f"| {name} | {outcome} |" for name, outcome in rows)
    failed = not rows or any(outcome != "success" for _, outcome in rows)
    lines += ["", "Diagnostic run incomplete or failed." if failed else "All collected checks passed."]
    return "\n".join(lines) + "\n", failed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--title", required=True)
    args = parser.parse_args()
    results = json.loads(os.environ["CI_RESULTS"])
    args.output.write_text(json.dumps(results, indent=2) + "\n")
    summary, failed = report(results, args.title)
    print(summary)
    if path := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(path, "a") as stream:
            stream.write(summary)
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())

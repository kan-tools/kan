#!/usr/bin/env python3
"""Build the repository CLI of a historical checkout, never its v2 service CLI."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

# Only this exit code denotes a historical compiler failure. All other errors
# must fail the workflow, never become a persisted migration outcome.
BUILD_FAILED = 10
HELPER_FAILED = 3


def select_writer(package):
    binaries = {target["name"]: target for target in package["targets"]
                if "bin" in target["kind"]}
    if "kan-v1" in binaries:
        if "kan-v1" not in package.get("features", {}):
            raise ValueError("kan-v1 target has no supported opt-in feature")
        return "kan-v1", ["--no-default-features", "--features", "kan-v1", "--bin", "kan-v1"]
    if "kan" in binaries:
        # Pre-rename tags used kan as the repository CLI. Refuse a split layout
        # missing its legacy binary rather than accidentally using the v2 CLI.
        if binaries["kan"].get("required-features", []):
            raise ValueError("feature-gated kan target cannot serve as a legacy writer")
        return "kan", ["--bin", "kan"]
    raise ValueError("historical checkout has no supported repository CLI")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkout", type=Path)
    parser.add_argument("--binary-path-file", type=Path)
    parser.add_argument("--inspect", action="store_true", help="select from real metadata without building")
    args = parser.parse_args(argv)
    if not args.inspect and args.binary_path_file is None:
        parser.error("--binary-path-file is required unless --inspect is used")
    root = args.checkout.resolve()
    try:
        metadata = json.loads(subprocess.check_output(
            ["cargo", "metadata", "--no-deps", "--format-version=1"], cwd=root, text=True))
        package = next(p for p in metadata["packages"]
                       if Path(p["manifest_path"]).resolve() == root / "Cargo.toml")
        binary, features = select_writer(package)
    except (OSError, subprocess.CalledProcessError, ValueError, KeyError, TypeError, StopIteration) as error:
        print(f"migration writer selection failed: {error}", file=sys.stderr)
        return HELPER_FAILED
    print(json.dumps({"checkout": str(root), "binary": binary, "features": features}), flush=True)
    if args.inspect:
        return 0
    try:
        result = subprocess.run(["cargo", "build", "--release", "--quiet",
                                 "--target-dir", str(root / "target"), *features], cwd=root)
        if result.returncode:
            print(f"historical cargo build failed with exit {result.returncode}", file=sys.stderr)
            return BUILD_FAILED
        args.binary_path_file.write_text(str(root / "target/release" / binary) + "\n")
    except OSError as error:
        print(f"migration writer helper failed: {error}", file=sys.stderr)
        return HELPER_FAILED
    return 0


if __name__ == "__main__":
    sys.exit(main())

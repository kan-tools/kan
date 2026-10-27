#!/usr/bin/env python3
"""Build the repository CLI of a historical checkout, never its v2 service CLI."""
import argparse
import json
from pathlib import Path
import subprocess


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
        if "v2-crypto" in binaries["kan"].get("required-features", []):
            raise ValueError("v2 kan target cannot serve as a legacy writer")
        return "kan", ["--bin", "kan"]
    raise ValueError("historical checkout has no supported repository CLI")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkout", type=Path)
    parser.add_argument("--binary-path-file", required=True, type=Path)
    args = parser.parse_args()
    root = args.checkout.resolve()
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--no-deps", "--format-version=1"], cwd=root, text=True))
    package = next(p for p in metadata["packages"]
                   if Path(p["manifest_path"]).resolve() == root / "Cargo.toml")
    binary, features = select_writer(package)
    subprocess.run(["cargo", "build", "--release", "--quiet",
                    "--target-dir", str(root / "target"), *features], cwd=root, check=True)
    args.binary_path_file.write_text(str(root / "target/release" / binary) + "\n")


if __name__ == "__main__":
    main()

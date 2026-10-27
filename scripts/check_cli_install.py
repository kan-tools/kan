#!/usr/bin/env python3
"""CI-only install contract: use private roots, never the operator's Cargo bin."""
import json
import os
from pathlib import Path
import subprocess
import tempfile


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def main():
    root = Path(__file__).resolve().parent.parent
    os.chdir(root)
    package = json.loads(run("cargo", "metadata", "--offline", "--no-deps",
                             "--format-version=1"))["packages"][0]
    targets = {t["name"] for t in package["targets"] if "bin" in t["kind"]}
    assert targets == {"kan", "kan-v1"}, targets
    version = package["version"]
    suffix = ".exe" if os.name == "nt" else ""
    modes = [
        ("default", [], {"kan"}),
        ("with-legacy", ["--features", "kan-v1"], {"kan", "kan-v1"}),
        ("legacy-only", ["--no-default-features", "--features", "kan-v1",
                         "--bin", "kan-v1"], {"kan-v1"}),
    ]
    with tempfile.TemporaryDirectory(prefix="kan-cli-install-") as temp:
        for mode, features, expected in modes:
            destination = Path(temp) / mode
            # Reuse this CI checkout's build cache. No release or registry write.
            subprocess.run(["cargo", "install", "--path", ".", "--locked",
                            "--offline", "--debug", "--target-dir", str(root / "target"),
                            "--root", str(destination), *features], check=True)
            actual = {p.name.removesuffix(suffix) if suffix else p.name
                      for p in (destination / "bin").iterdir()}
            assert actual == expected, (mode, actual, expected)
            for name in sorted(expected):
                binary = str(destination / "bin" / (name + suffix))
                assert run(binary, "--version").strip() == f"{name} {version}"
                help_text = run(binary, "--help")
                assert f"Usage: {name} " in help_text, help_text
                supported, refused = (("library", "observe") if name == "kan"
                                      else ("observe", "library"))
                run(binary, supported, "--help")
                result = subprocess.run([binary, refused, "--help"], capture_output=True)
                assert result.returncode != 0, (name, refused)
                if name == "kan-v1":
                    # Registration must point to this binary, never the new kan.
                    assert binary in run(binary, "mcp", "install")
            print(json.dumps({"mode": mode, "installed": sorted(actual),
                              "version": version, "status": "passed"}), flush=True)


if __name__ == "__main__":
    main()

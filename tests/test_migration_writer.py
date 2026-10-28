"""Historical and future writer layouts must select the repository command."""
import importlib.util
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "migration_writer", Path(__file__).resolve().parents[1] / "scripts/migration_writer.py")
writer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(writer)


class WriterSelection(unittest.TestCase):
    def test_legacy_tag_with_optional_old_v2_binary(self):
        package = {"targets": [{"name": "kan", "kind": ["lib"]},
                               {"name": "kan", "kind": ["bin"]},
                               {"name": "kan-v2", "kind": ["bin"]}]}
        self.assertEqual(writer.select_writer(package), ("kan", ["--bin", "kan"]))

    def test_future_tag_uses_opt_in_legacy_not_default_service(self):
        package = {"targets": [
            {"name": "kan", "kind": ["bin"], "required-features": ["v2-crypto"]},
            {"name": "kan-v1", "kind": ["bin"], "required-features": ["kan-v1"]}],
            "features": {"default": ["v2-crypto"], "kan-v1": []}}
        self.assertEqual(writer.select_writer(package),
                         ("kan-v1", ["--no-default-features", "--features", "kan-v1", "--bin", "kan-v1"]))

    def test_incomplete_new_layout_never_falls_back_to_service(self):
        for package in [
            {"targets": [{"name": "kan", "kind": ["bin"], "required-features": ["v2-crypto"]}]},
            {"targets": [{"name": "kan", "kind": ["bin"], "required-features": ["unknown"]}]},
            {"targets": [{"name": "kan-v1", "kind": ["bin"]}]},
            {"targets": [{"name": "kan", "kind": ["lib"]}]},
        ]:
            with self.subTest(package=package), self.assertRaises(ValueError):
                writer.select_writer(package)


class WriterExecution(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.output = self.root / "writer-path"
        self.metadata = {"packages": [{
            "manifest_path": str(self.root / "Cargo.toml"),
            "targets": [{"name": "kan-v1", "kind": ["bin"]}],
            "features": {"kan-v1": []}}]}

    def invoke(self, inspect=False):
        output, errors = io.StringIO(), io.StringIO()
        argv = [str(self.root), "--inspect"] if inspect else [
            str(self.root), "--binary-path-file", str(self.output)]
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            status = writer.main(argv)
        return status, output.getvalue(), errors.getvalue()

    def test_metadata_and_layout_errors_are_not_historical_build_failures(self):
        cases = [subprocess.CalledProcessError(1, "cargo metadata"),
                 FileNotFoundError("cargo"), "not JSON", '{"packages": []}',
                 json.dumps({"packages": [{"manifest_path": str(self.root / "Cargo.toml"),
                                           "targets": []}]})]
        for case in cases:
            with self.subTest(case=case), patch.object(writer.subprocess, "check_output") as metadata, \
                    patch.object(writer.subprocess, "run") as build:
                if isinstance(case, Exception):
                    metadata.side_effect = case
                else:
                    metadata.return_value = case
                status, _, error = self.invoke()
                self.assertEqual(status, writer.HELPER_FAILED)
                self.assertIn("selection failed", error)
                build.assert_not_called()
                self.assertFalse(self.output.exists())

    def test_only_compiler_failure_has_build_failed_status(self):
        with patch.object(writer.subprocess, "check_output", return_value=json.dumps(self.metadata)), \
                patch.object(writer.subprocess, "run", return_value=subprocess.CompletedProcess([], 101)):
            status, selection, error = self.invoke()
        self.assertEqual(status, writer.BUILD_FAILED)
        self.assertEqual(json.loads(selection)["binary"], "kan-v1")
        self.assertIn("101", error)
        self.assertFalse(self.output.exists())

    def test_spawn_and_path_publication_failures_are_helper_errors(self):
        with patch.object(writer.subprocess, "check_output", return_value=json.dumps(self.metadata)), \
                patch.object(writer.subprocess, "run", side_effect=OSError("spawn failed")):
            self.assertEqual(self.invoke()[0], writer.HELPER_FAILED)
        self.assertFalse(self.output.exists())
        self.output.mkdir()
        with patch.object(writer.subprocess, "check_output", return_value=json.dumps(self.metadata)), \
                patch.object(writer.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)):
            self.assertEqual(self.invoke()[0], writer.HELPER_FAILED)

    def test_success_publishes_selected_binary_only_after_build(self):
        def build(command, cwd):
            self.assertFalse(self.output.exists())
            self.assertEqual(cwd, self.root)
            self.assertEqual(command[-5:], ["--no-default-features", "--features", "kan-v1", "--bin", "kan-v1"])
            return subprocess.CompletedProcess(command, 0)
        with patch.object(writer.subprocess, "check_output", return_value=json.dumps(self.metadata)), \
                patch.object(writer.subprocess, "run", side_effect=build):
            status, selection, error = self.invoke()
        self.assertEqual(status, 0)
        self.assertEqual(error, "")
        self.assertEqual(json.loads(selection)["binary"], "kan-v1")
        self.assertEqual(self.output.read_text().strip(), str(self.root / "target/release/kan-v1"))

    def test_inspect_selects_without_building_or_publishing(self):
        with patch.object(writer.subprocess, "check_output", return_value=json.dumps(self.metadata)), \
                patch.object(writer.subprocess, "run") as build:
            status, selection, _ = self.invoke(inspect=True)
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(selection)["binary"], "kan-v1")
        build.assert_not_called()
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()

"""Historical and future writer layouts must select the repository command."""
import importlib.util
from pathlib import Path
import unittest

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
            {"targets": [{"name": "kan-v1", "kind": ["bin"]}]},
            {"targets": [{"name": "kan", "kind": ["lib"]}]},
        ]:
            with self.subTest(package=package), self.assertRaises(ValueError):
                writer.select_writer(package)


if __name__ == "__main__":
    unittest.main()

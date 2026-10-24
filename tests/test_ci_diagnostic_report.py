import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "diagnostic", Path(__file__).resolve().parents[1] / "scripts/ci-diagnostic-report.py")
diagnostic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnostic)


class DiagnosticReportTests(unittest.TestCase):
    def test_continued_failure_cannot_become_green(self):
        summary, failed = diagnostic.report({
            "early": {"outcome": "failure", "conclusion": "success"},
            "later": {"outcome": "success", "conclusion": "success"},
        }, "Checks")
        self.assertTrue(failed)
        self.assertIn("| early | failure |", summary)
        self.assertIn("| later | success |", summary)

    def test_incomplete_collection_is_not_acceptance(self):
        for results in [{}, {"job": {"result": "skipped"}},
                        {"job": {"result": "cancelled"}}, {"unknown": {}}]:
            with self.subTest(results=results):
                self.assertTrue(diagnostic.report(results, "Jobs")[1])

    def test_all_success_is_green(self):
        self.assertFalse(diagnostic.report({"a": {"outcome": "success"},
                                            "b": {"result": "success"}}, "Checks")[1])


if __name__ == "__main__":
    unittest.main()

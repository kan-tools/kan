import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import subprocess

spec = importlib.util.spec_from_file_location('ci_scope', Path(__file__).resolve().parents[1] / 'scripts/ci-scope.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ScopeTests(unittest.TestCase):
    def test_library_patch_does_not_rebuild_packaging_or_run_capture(self):
        result = m.classify(['src/evidence_library/mcp_pages.rs', 'docs/V2-RECORD-RECALL.md'])
        self.assertEqual(result['scope'], 'library')
        self.assertFalse(result['capture'])
        self.assertFalse(result['macos'])

    def test_process_or_platform_changes_escalate(self):
        self.assertTrue(m.classify(['scripts/kan-project.py'])['capture'])
        for path in ['src/keychain.rs', 'tests/keychain_identity.rs', 'src/evidence_store/lease.rs']:
            self.assertTrue(m.classify([path])['macos'], path)

    def test_no_production_rust_path_can_be_classified_as_static(self):
        root = Path(__file__).resolve().parents[1]
        for path in (root / 'src').rglob('*.rs'):
            self.assertTrue(m.classify([path.relative_to(root).as_posix()])['rust'])

    def test_unknown_and_changed_ci_inputs_are_conservative(self):
        for path in ['unrecognized.build-input', '.github/workflows/iteration.yml', 'Cargo.lock']:
            self.assertTrue(m.classify([path])['core'])
        result = m.classify([], uncertain=True)
        self.assertTrue(result['core'] and result['capture'] and result['macos'])

    def test_missing_diff_is_not_an_empty_success(self):
        with patch.object(m.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, b'', b'bad base')):
            self.assertEqual(m.changed_paths({'before': 'missing'}, 'head'), ([], True))
        self.assertEqual(m.changed_paths({'before': '0' * 40}, 'head'), ([], True))

    def test_catalog_and_finalization_owner_cannot_skip_surface_checks(self):
        for path in ['tests/fixtures/read-write-surface.tsv', 'scripts/kan-finalized.py',
                     'tests/test_kan_finalized.py', 'scripts/ci-component-result.py',
                     'tests/test_ci_component_result.py']:
            result = m.classify([path])
            self.assertTrue(result['rust'] and result['core'], path)
            self.assertEqual(result['capture'], path in {'scripts/kan-finalized.py', 'tests/test_kan_finalized.py'}, path)
            self.assertFalse(result['macos'], path)

    def test_other_fixture_changes_select_real_component_checks(self):
        for path in ['tests/fixtures/uri-v1.json', 'tests/fixtures/new-shape.tsv']:
            self.assertTrue(m.classify([path])['core'], path)

    def test_rename_keeps_both_source_and_destination_paths(self):
        with patch.object(m.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'src/old.rs\0docs/new.md\0', b'')) as run:
            paths, uncertain = m.changed_paths({'before': 'base'}, 'head')
        self.assertIn('--no-renames', run.call_args.args[0])
        self.assertFalse(uncertain)
        self.assertEqual(paths, ['src/old.rs', 'docs/new.md'])
        self.assertTrue(m.classify(paths)['core'])

    def test_docs_only_stays_static_and_deleted_source_keeps_coverage(self):
        self.assertFalse(m.classify(['docs/SPEC.md', '.design/plan.md'])['rust'])
        self.assertTrue(m.classify(['src/deleted_module.rs'])['core'])


if __name__ == '__main__':
    unittest.main()

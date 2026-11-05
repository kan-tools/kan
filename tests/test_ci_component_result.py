import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('result', Path(__file__).parents[1] / 'scripts/ci-component-result.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ComponentResult(unittest.TestCase):
    def test_unit_failure_cannot_be_masked_by_http_or_lint_success(self):
        scope = dict(core=False, library=True, capture=False)
        steps = {name: {'outcome': 'success'} for name in ['library_units', 'library_http', 'lint']}
        steps['library_units'] = {'outcome': 'failure', 'conclusion': 'success'}
        self.assertEqual(m.evaluate(scope, steps)['failures'], {'library_units': 'failure'})

    def test_all_actual_failures_retained_in_one_result(self):
        report = m.evaluate(dict(core=True, library=True, capture=True), {
            'compile': {'outcome': 'success'}, 'core_units': {'outcome': 'failure'},
            'library_http': {'outcome': 'failure'}, 'lint': {'outcome': 'failure'},
            'capture': {'outcome': 'success'}})
        self.assertEqual(set(report['failures']), {'core_units', 'library_http', 'lint'})
        self.assertNotIn('library_units', report['required'])  # already in core units

    def test_selected_skipped_or_missing_steps_are_never_passes(self):
        report = m.evaluate(dict(core=True, library=True, capture=True), {'compile': {'outcome': 'failure'},
            'core_units': {'outcome': 'skipped'}, 'library_http': {'outcome': 'skipped'}, 'lint': {'outcome': 'skipped'}})
        self.assertEqual(report['failures']['core_units'], 'skipped')
        self.assertEqual(report['failures']['capture'], 'missing')
        self.assertEqual(len(report['failures']), 5)

    def test_scope_omissions_and_empty_selection_refuse(self):
        for scope in [{}, dict(core=False, library=False, capture=False), dict(core='true', library=False, capture=False)]:
            with self.assertRaises(ValueError):
                m.evaluate(scope, {})

    def test_unselected_platform_and_capture_are_not_added_to_passes(self):
        steps = {name: {'outcome': 'success'} for name in ['library_units', 'library_http', 'lint']}
        report = m.evaluate(dict(core=False, library=True, capture=False), steps)
        self.assertFalse(report['failures'])
        self.assertNotIn('capture', report['outcomes'])
        self.assertNotIn('compile', report['outcomes'])


if __name__ == '__main__':
    unittest.main()

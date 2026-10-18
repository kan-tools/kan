import importlib.util
from pathlib import Path
import unittest
spec = importlib.util.spec_from_file_location('revert_v2', Path(__file__).resolve().parents[1] / 'scripts/revert_v2.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

class Results(unittest.TestCase):
    def test_exact_assertions(self):
        self.assertEqual(runner.parse_result('node', 'a', 'ok 1 - a\nnot ok 2 - ab', 0), ({'a'}, set()))
        self.assertEqual(runner.parse_result('node', 'a', 'not ok 1 - a', 1), ({'a'}, {'a'}))
        self.assertEqual(runner.parse_result('lib', 'a::b', 'test a::b ... FAILED', 101), ({'a::b'}, {'a::b'}))
    def test_ignored_duplicate_missing_or_crashed_are_not_passes(self):
        for output in ('ok 1 - a # SKIP', 'ok 1 - a # TODO', 'ok 1 - ab', 'ok 1 - a\nok 2 - a', 'test a ... ignored', ''):
            self.assertEqual(runner.parse_result('node', 'a', output, 0), (set(), set()))
        for output, code in [('ok 1 - a', 1), ('not ok 1 - a', 0)]:
            with self.assertRaises(ValueError):
                runner.parse_result('node', 'a', output, code)

if __name__ == '__main__':
    unittest.main()

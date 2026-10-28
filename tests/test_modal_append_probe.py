"""Pure run-identity regression; never imports Modal or starts cloud work."""
import ast
from pathlib import Path
import re
import unittest

source = Path(__file__).resolve().parents[1] / 'scripts/modal_append_probe.py'
function = next(node for node in ast.parse(source.read_text()).body
                if isinstance(node, ast.FunctionDef) and node.name == 'identity')
namespace = {'re': re}
exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), 'exec'), namespace)
identity = namespace['identity']


class IdentityTests(unittest.TestCase):
    def test_volume_name_preserves_unique_run_within_modal_limit(self):
        revision = '79ceac06eba0c95589d056a92b6c6aad6ddfee8b'
        run_id = 'b7efdc38bb6c4d44855d34f2c5ad224a'
        name = identity(revision, run_id)
        self.assertLess(len(name), 64)
        self.assertRegex(name, r'^[a-zA-Z0-9_.-]+$')
        self.assertIn(revision[:12], name)
        self.assertTrue(name.endswith(run_id))
        self.assertNotEqual(name, identity(revision, '0' * 32))

    def test_rejects_unpinned_or_malformed_identity(self):
        for revision, run_id in [('main', '0' * 32), ('f' * 40, '../fixture'),
                                 ('F' * 40, '0' * 32)]:
            with self.assertRaises(ValueError):
                identity(revision, run_id)


if __name__ == '__main__':
    unittest.main()

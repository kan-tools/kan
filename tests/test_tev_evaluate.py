#!/usr/bin/env python3
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('tev', Path(__file__).resolve().parents[1] / 'scripts/tev-evaluate.py')
tev = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tev)


class EvaluationTests(unittest.TestCase):
    def corpus(self):
        cases, labels, responses = [], [], []
        for n in range(16):
            id = str(n)
            y = n % 2
            cases.append({'id': id, 'text': 'distinct excerpt ' + id, 'group': 'group' + id,
                          'split': 'calibration' if n < 12 else 'heldout'})
            labels.append({'id': id, 'stance': 'adopted' if y else 'none', 'decision': y, 'support': 2 if y else 0})
            responses.append({'id': id, 'status': 'ok', 'elapsed_seconds': 1 + n / 10,
                              'answers': {'decision': {'type': 'noul', 'noul': .7 if y else .3}}})
        return cases, labels, responses

    def test_hand_computed_probability_scores_and_failure_denominator(self):
        rows = [('a', 0, [.1, .9]), ('b', 1, [.9, .1]), ('c', 1, None)]
        score = tev.score(rows, [0, 1])
        self.assertEqual(score['accuracy_all_reference'], 0)
        self.assertEqual(score['valid_n'], 2)
        self.assertEqual(score['missing_or_invalid_n'], 1)
        self.assertAlmostEqual(score['brier_unscaled_valid_only'], 1.62)
        self.assertAlmostEqual(score['nll_valid_only'], -tev.math.log(.1))
        self.assertAlmostEqual(score['selective_risk'][0]['coverage_all_reference'], 2 / 3)

    def test_heldout_labels_cannot_change_temperature(self):
        c, labels, responses = self.corpus()
        first = tev.evaluate(c, labels, responses)
        changed = copy.deepcopy(labels)
        for label in changed[12:]:
            label['decision'] = 1 - label['decision']
        second = tev.evaluate(c, changed, responses)
        self.assertEqual(first['heads']['decision']['calibration_fit'], second['heads']['decision']['calibration_fit'])
        self.assertNotEqual(first['heads']['decision']['heldout_raw']['accuracy_all_reference'],
                            second['heads']['decision']['heldout_raw']['accuracy_all_reference'])

    def test_group_duplicate_and_unexpected_identity_leakage_refused(self):
        cases, labels, responses = self.corpus()
        for mode in ['group', 'text', 'near', 'duplicate', 'foreign']:
            c, r = copy.deepcopy(cases), copy.deepcopy(responses)
            if mode in ('group', 'text'):
                c[12][mode] = c[0][mode]
            elif mode == 'near':
                c[0]['text'] = 'alpha beta gamma delta epsilon zeta eta theta iota kappa lambda'
                c[12]['text'] = c[0]['text'] + ' extra'
            elif mode == 'duplicate':
                r.append(r[0])
            else:
                r.append({'id': 'foreign'})
            with self.assertRaises(ValueError):
                tev.evaluate(c, labels, r)

    def test_native_confidence_does_not_replace_probabilities(self):
        c, labels, responses = self.corpus()
        before = tev.evaluate(c, labels, responses)
        for r in responses:
            r['answers']['decision']['confidence'] = 1
        self.assertEqual(before, tev.evaluate(c, labels, responses))

    def test_missing_prediction_is_retained_and_ambiguous_label_disclosed(self):
        c, labels, responses = self.corpus()
        labels[-1]['decision'] = None
        result = tev.evaluate(c, labels, responses[:-2])
        score = result['heads']['decision']['heldout_raw']
        self.assertEqual(score['reference_n'], 3)
        self.assertEqual(score['ambiguous_reference_n'], 1)
        self.assertEqual(score['missing_or_invalid_n'], 1)
        self.assertEqual(result['request_statuses']['missing'], 2)
        self.assertAlmostEqual(score['accuracy_all_reference'], 2 / 3)

    def test_invalid_probabilities_and_insufficient_calibration_are_explicit(self):
        self.assertIsNone(tev.distribution({'status': 'ok', 'answers': {'decision': {'type': 'noul', 'noul': float('nan')}}}, 'decision'))
        fit = tev.fit_temperature([([.9, .1], 0)] * 24)
        self.assertFalse(fit['fitted'])
        self.assertEqual(fit['temperature'], 1)

    def test_preflight_needs_no_predictions_and_refuses_leak_before_output(self):
        cases, labels, _ = self.corpus()
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            for name, rows in [('cases', cases), ('labels', labels)]:
                (folder / name).write_text(''.join(json.dumps(row) + '\n' for row in rows))
            args = [sys.executable, str(Path(tev.__file__)), '--validate-only',
                    '--cases', str(folder / 'cases'), '--labels', str(folder / 'labels'),
                    '--output', str(folder / 'preflight.json')]
            result = subprocess.run(args, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads((folder / 'preflight.json').read_text())['model_calls'], 0)
            cases[12]['group'] = cases[0]['group']
            (folder / 'cases').write_text(''.join(json.dumps(row) + '\n' for row in cases))
            args[-1] = str(folder / 'invalid.json')
            self.assertNotEqual(subprocess.run(args, capture_output=True).returncode, 0)
            self.assertFalse((folder / 'invalid.json').exists())


if __name__ == '__main__':
    unittest.main()

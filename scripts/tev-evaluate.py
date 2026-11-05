#!/usr/bin/env python3
"""Offline, grouped pilot scoring. Never starts a model or changes Kan state."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
import math
from pathlib import Path
import random
import re
import statistics

CLASSES = {'stance': ['adopted', 'proposal', 'none', 'unknown'],
           'decision': [0, 1], 'support': [0, 1, 2]}
TEMPERATURES = [.25, .35, .5, .7, 1., 1.4, 2., 3., 4.]


def keyed(rows):
    result = {}
    for row in rows:
        if row['id'] in result:
            raise ValueError('duplicate case identity')
        result[row['id']] = row
    return result


def validate(cases, labels, predictions):
    c, labels, predictions = keyed(cases), keyed(labels), keyed(predictions)
    if set(labels) != set(c) or not set(predictions) <= set(c):
        raise ValueError('case/label/prediction identities disagree')
    groups, texts = {}, {}
    for row in c.values():
        if row['split'] not in ('calibration', 'heldout') or not row['text'].strip():
            raise ValueError('invalid split or empty text')
        for table, key in [(groups, row['group']),
                           (texts, ' '.join(row['text'].casefold().split()))]:
            if key in table and table[key] != row['split']:
                raise ValueError('subject or duplicate text crosses split')
            table[key] = row['split']
        for head, classes in CLASSES.items():
            value = labels[row['id']][head]
            if (value not in classes + [None]
                    or (head == 'stance' and type(value) is not str)
                    or (head != 'stance' and value is not None and type(value) is not int)):
                raise ValueError('invalid reference label')
    # Conservative lexical duplicate guard in addition to caller-supplied
    # semantic subject groups. Do not let cosmetic edits leak between splits.
    values = list(c.values())
    words = {r['id']: set(re.findall(r'\w+', r['text'].casefold())) for r in values}
    for n, a in enumerate(values):
        for b in values[:n]:
            x, y = words[a['id']], words[b['id']]
            if a['split'] != b['split'] and len(x & y) / max(1, len(x | y)) >= .85:
                raise ValueError('near-duplicate text crosses split')
    return list(c.values()), labels, predictions


def distribution(record, head):
    if not record or record.get('status') != 'ok':
        return None
    a = record.get('answers', {}).get(head, {})
    classes = CLASSES[head]
    if head == 'decision':
        if a.get('type') != 'noul':
            return None
        p = a.get('noul')
        values = [1 - p, p] if type(p) in (int, float) else []
    else:
        if a.get('type') != ('choice' if head == 'stance' else 'score'):
            return None
        ps = a.get('probabilities', {})
        if set(ps) != {str(x) for x in classes}:
            return None
        values = [ps[str(x)] for x in classes]
    if (len(values) != len(classes) or any(type(x) not in (int, float)
            or not math.isfinite(x) or x < 0 or x > 1 for x in values)
            or abs(sum(values) - 1) > .0001):
        return None
    return values


def scaled(p, temperature):
    logs = [math.log(max(x, 1e-12)) / temperature for x in p]
    high = max(logs)
    weights = [math.exp(x - high) for x in logs]
    return [x / sum(weights) for x in weights]


def nll(p, target):
    return -math.log(max(1e-12, p[target]))


def fit_temperature(rows):
    counts = Counter(y for _, y in rows)
    if len(rows) < 12 or sum(n >= 3 for n in counts.values()) < 2:
        return {'temperature': 1., 'fitted': False, 'reason': 'insufficient calibration support'}
    losses = {t: statistics.mean(nll(scaled(p, t), y) for p, y in rows)
              for t in TEMPERATURES}
    best = min(losses, key=lambda t: (losses[t], abs(math.log(t))))
    # Avoid reporting a fitted improvement from numerical ties.
    if losses[1.] - losses[best] < .005:
        best = 1.
    return {'temperature': best, 'fitted': True, 'calibration_n': len(rows),
            'calibration_nll_before': losses[1.], 'calibration_nll_after': losses[best]}


def quantile(values, fraction):
    if not values:
        return None
    values = sorted(values)
    pos = (len(values) - 1) * fraction
    left = int(pos)
    right = min(left + 1, len(values) - 1)
    return values[left] + (values[right] - values[left]) * (pos - left)


def grouped_interval(rows):
    groups = defaultdict(list)
    for group, correct in rows:
        groups[group].append(correct)
    keys = sorted(groups)
    if len(keys) < 2:
        return None
    rng = random.Random(20261105)
    draws = []
    for _ in range(1000):
        sample = [x for key in rng.choices(keys, k=len(keys)) for x in groups[key]]
        draws.append(statistics.mean(sample))
    return [quantile(draws, .025), quantile(draws, .975)]


def score(rows, classes):
    eligible = [(g, y, p) for g, y, p in rows if y is not None]
    valid = [(g, y, p) for g, y, p in eligible if p is not None]
    if not eligible:
        return {'reference_n': 0, 'valid_n': 0, 'reason': 'no unambiguous reference labels'}
    confusion = [[0] * len(classes) for _ in classes]
    observations = []
    for _, y, p in valid:
        predicted = max(range(len(p)), key=p.__getitem__)
        confusion[y][predicted] += 1
        observations.append((max(p), int(predicted == y)))
    bins = []
    for low, high in [(0., .5), (.5, .75), (.75, 1.000001)]:
        sample = [(p, y) for p, y in observations if low <= p < high]
        bins.append({'from': low, 'through': min(high, 1.), 'n': len(sample),
                     'mean_confidence': statistics.mean(p for p, _ in sample) if sample else None,
                     'accuracy': statistics.mean(y for _, y in sample) if sample else None})
    present = Counter(y for _, y, _ in eligible)
    f1 = []
    recalls = []
    for y in present:
        tp = confusion[y][y]
        predicted_n = sum(row[y] for row in confusion)
        f1.append(2 * tp / (present[y] + predicted_n))
        recalls.append(tp / present[y])
    hits = [(g, int(p is not None and max(range(len(p)), key=p.__getitem__) == y))
            for g, y, p in eligible]
    risk = []
    for threshold in [.5, .7, .9]:
        accepted = [(p, correct) for p, correct in observations if p >= threshold]
        risk.append({'threshold': threshold, 'selected_n': len(accepted),
                     'coverage_all_reference': len(accepted) / len(eligible),
                     'risk': 1 - statistics.mean(y for _, y in accepted) if accepted else None})
    return {'reference_n': len(eligible), 'valid_n': len(valid),
            'ambiguous_reference_n': len(rows) - len(eligible),
            'missing_or_invalid_n': len(eligible) - len(valid),
            'class_counts': {str(classes[y]): n for y, n in present.items()},
            'confusion_true_rows_predicted_columns': confusion,
            'accuracy_all_reference': statistics.mean(y for _, y in hits),
            'accuracy_group_bootstrap95': grouped_interval(hits),
            'macro_f1_present_classes': statistics.mean(f1),
            'balanced_accuracy_present_classes': statistics.mean(recalls),
            'brier_unscaled_valid_only': statistics.mean(sum((v - int(k == y)) ** 2
                for k, v in enumerate(p)) for _, y, p in valid) if valid else None,
            'nll_valid_only': statistics.mean(nll(p, y) for _, y, p in valid) if valid else None,
            'reliability_bins_valid_only': bins,
            'ece_toplabel_valid_only': sum(b['n'] * abs(b['mean_confidence'] - b['accuracy'])
                for b in bins if b['n']) / len(valid) if valid else None,
            'selective_risk': risk,
            'ordinal_expected_mae_valid_only': statistics.mean(abs(sum(k * v for k, v in enumerate(p)) - y)
                for _, y, p in valid) if valid and classes == [0, 1, 2] else None}


def evaluate(cases, labels, predictions):
    cases, labels, predictions = validate(cases, labels, predictions)
    result = {'version': 'kan-tev-pilot-evaluation/1', 'case_n': len(cases),
              'prediction_n': len(predictions), 'heads': {},
              'limitations': ['Model-assisted provisional references, not human gold.',
                  'Enriched own-project sample, not prevalence or broad calibration.',
                  'Brier/log loss combine discrimination and reliability.',
                  'Temperature fitted on calibration only; no heldout tuning.',
                  'Native confidence ignored; probabilities used directly.',
                  'Failures count against accuracy and coverage; proper scores show valid-only counts.',
                  'No source exclusion, authorship, admission or product policy change.']}
    for head, classes in CLASSES.items():
        rows = {split: [] for split in ['calibration', 'heldout']}
        for case in cases:
            label = labels[case['id']][head]
            y = classes.index(label) if label is not None else None
            rows[case['split']].append((case['group'], y, distribution(predictions.get(case['id']), head)))
        fit = fit_temperature([(p, y) for _, y, p in rows['calibration'] if y is not None and p is not None])
        prior_counts = Counter(y for _, y, _ in rows['calibration'] if y is not None)
        prior = [(prior_counts[k] + 1) / (sum(prior_counts.values()) + len(classes))
                 for k in range(len(classes))]
        heldout = rows['heldout']
        result['heads'][head] = {'classes': classes, 'calibration_fit': fit,
            'calibration_raw': score(rows['calibration'], classes),
            'heldout_raw': score(heldout, classes),
            'heldout_adjusted': score([(g, y, scaled(p, fit['temperature']) if p is not None else None)
                                      for g, y, p in heldout], classes),
            'heldout_uniform_baseline': score([(g, y, [1 / len(classes)] * len(classes)) for g, y, _ in heldout], classes),
            'heldout_calibration_prior_baseline': score([(g, y, prior) for g, y, _ in heldout], classes)}
    times = [r['elapsed_seconds'] for r in predictions.values() if isinstance(r.get('elapsed_seconds'), (float, int))]
    result['latency_seconds'] = {'n': len(times), 'first_call': times[0] if times else None,
        'p50': quantile(times, .5), 'p95': quantile(times, .95), 'max': max(times) if times else None}
    result['request_statuses'] = dict(Counter(predictions.get(c['id'], {}).get('status', 'missing') for c in cases))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['cases', 'labels', 'output']:
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--responses', type=Path)
    parser.add_argument('--validate-only', action='store_true',
                        help='Validate labels and split isolation BEFORE worker execution; no predictions needed')
    args = parser.parse_args()
    if not args.validate_only and args.responses is None:
        parser.error('scoring requires --responses')
    paths = {'cases': args.cases, 'labels': args.labels}
    if args.responses is not None:
        paths['responses'] = args.responses
    values = {k: [json.loads(line) for line in p.read_text().splitlines() if line.strip()] for k, p in paths.items()}
    if args.validate_only:
        cases, _, _ = validate(values['cases'], values['labels'], [])
        result = {'version': 'kan-tev-preflight/1', 'case_n': len(cases),
                  'splits': dict(Counter(c['split'] for c in cases)), 'model_calls': 0}
    else:
        result = evaluate(values['cases'], values['labels'], values['responses'])
    result['input_sha256'] = {k: hashlib.sha256(p.read_bytes()).hexdigest() for k, p in paths.items()}
    with args.output.open('x') as out:
        json.dump(result, out, ensure_ascii=False, indent=2, allow_nan=False)
        out.write('\n')


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Keep independent iteration diagnostics without turning failures into passes."""
import json
import os
from pathlib import Path


def evaluate(scope, steps):
    if set(scope) != {'core', 'library', 'capture'} or any(type(v) is not bool for v in scope.values()):
        raise ValueError('explicit component scope required')
    required = ['lint']
    if scope['core']:
        required += ['compile', 'core_units']
    elif scope['library']:
        required += ['library_units']
    if scope['library']:
        required += ['library_http']
    if scope['capture']:
        required += ['capture']
    if len(required) == 1:
        raise ValueError('component scope selected no tests')
    outcomes = {name: steps.get(name, {}).get('outcome', 'missing') for name in required}
    return {'required': required, 'outcomes': outcomes,
            'failures': {name: value for name, value in outcomes.items() if value != 'success'},
            'qualification': 'Selected iteration checks only; skipped checks are not passes.'}


def main():
    scope = {}
    for name in ['core', 'library', 'capture']:
        raw = os.environ['SCOPE_' + name.upper()]
        if raw not in {'true', 'false'}:
            raise ValueError('invalid scope flag')
        scope[name] = raw == 'true'
    report = evaluate(scope, json.loads(os.environ['CHECK_OUTCOMES']))
    Path('ci-component-results.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))
    return bool(report['failures'])


if __name__ == '__main__':
    raise SystemExit(main())

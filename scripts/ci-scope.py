#!/usr/bin/env python3
"""Select conservative iteration checks; this never certifies a merge candidate."""
import argparse
import json
import os
from pathlib import Path
import subprocess


def classify(paths, uncertain=False):
    paths = list(paths)
    result = dict(scope='static', rust=False, library=False, capture=False, core=False, macos=False)
    if uncertain:
        result.update(scope='core', rust=True, core=True, library=True, capture=True, macos=True)
    for path in paths:
        if path.startswith(('.github/', 'tests/fixtures/')) or path in {'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'build.rs', 'scripts/ci-scope.py', 'tests/test_ci_scope.py',
                                                  'scripts/ci-component-result.py', 'tests/test_ci_component_result.py',
                                                  'tests/fixtures/read-write-surface.tsv', 'scripts/kan-finalized.py', 'tests/test_kan_finalized.py'}:
            result.update(rust=True, core=True, library=True)
        elif path.startswith(('src/evidence_library', 'src/evidence_content', 'src/evidence_interpretation', 'src/evidence_record_cli')) or path == 'tests/support/proof_library_tests.rs':
            result.update(rust=True, library=True)
        elif path in {'scripts/kan-project.py', 'scripts/capture-claude-hook.py', 'scripts/check_project_capture.py'} or path.startswith(('src/evidence_capture', 'src/evidence_harness', 'src/evidence_spool')):
            result.update(rust=True, capture=True, library=True)
        elif path.endswith('.rs') or path.startswith('src/'):
            result.update(rust=True, core=True, library=True)
        elif not (path.startswith(('docs/', 'adrs/', 'rfcs/', '.design/', 'scripts/', 'tests/')) or path.endswith(('.md', '.txt', '.svg', '.png'))):
            # Unknown build inputs cannot quietly turn into documentation-only checks.
            result.update(rust=True, core=True, library=True)
        if any(part in path for part in ['keychain', 'keyring', 'identity', 'lease', 'at_rest', 'at-rest', 'scope_keys']):
            result.update(rust=True, core=True, macos=True)
        if path in {'scripts/kan-finalized.py', 'tests/test_kan_finalized.py'}:
            result.update(rust=True, library=True, capture=True)
    if result['core']:
        result['scope'] = 'core'
    elif result['capture']:
        result['scope'] = 'capture'
    elif result['library']:
        result['scope'] = 'library'
    result.update(paths=paths, uncertain=uncertain, qualification='iteration only; full candidate qualification remains required')
    return result


def changed_paths(event, head):
    base = event.get('pull_request', {}).get('base', {}).get('sha') or event.get('before')
    if not base or set(base) == {'0'}:
        return [], True
    # Treat a rename as delete+add so the old Rust/fixture path cannot vanish
    # from scope when its destination looks like documentation.
    result = subprocess.run(['git', 'diff', '--no-renames', '--name-only', '-z', base, head], capture_output=True)
    if result.returncode:
        return [], True
    return result.stdout.decode().rstrip('\0').split('\0') if result.stdout else [], False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--event', required=True, type=Path)
    parser.add_argument('--head', required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    paths, uncertain = changed_paths(json.loads(args.event.read_text()), args.head)
    result = classify(paths, uncertain)
    Path('ci-scope.json').write_text(json.dumps(result, indent=2) + '\n')
    if args.output:
        with args.output.open('a') as out:
            for key in ['scope', 'rust', 'library', 'capture', 'core', 'macos']:
                value = str(result[key]).lower()
                out.write(f'{key}={value}\n')
    print(json.dumps(result))
    if summary := os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(summary, 'a') as out:
            out.write(f"## Iteration scope: {result['scope']}\n\n{result['qualification']}\n")
            if uncertain:
                out.write('\nDiff unavailable: conservative core and platform checks selected.\n')


if __name__ == '__main__':
    main()

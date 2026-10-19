#!/usr/bin/env python3
"""Compile targeted decoder guard removals using the caller's shared Cargo target."""
from pathlib import Path
import subprocess
import argparse

ROOT = Path(__file__).resolve().parents[1]
FILE = ROOT / 'src/evidence_reconstruction.rs'
OUT = ROOT / '.local-state/reconstruction-author/controls'
CASES = [
    ('total-family-bound', 'if bytes.len() > MAX_FRAME', 'if false && bytes.len() > MAX_FRAME', 'capture_family_size_limit_precedes_unknown_envelope_classification'),
    ('unit-extra-fields', 'if kind == "forwarding-intent" && event.len() != 1', 'if false && kind == "forwarding-intent" && event.len() != 1', 'every_recognized_event_rejects_extra_fields_including_unit_variants'),
    ('required-clock-field', 'if !object.contains_key("observed_at_unix_micros")', 'if false && !object.contains_key("observed_at_unix_micros")', 'recognized_header_requires_explicit_timestamp_even_when_unknown'),
    ('duplicate-json-keys', 'if values.contains_key(&key)', 'if false && values.contains_key(&key)', 'duplicate_and_escaped_alias_keys_never_choose_a_winner'),
    ('non-chunk-body', 'if !body.is_empty()', 'if false && !body.is_empty()', 'non_chunk_events_cannot_smuggle_body_bytes'),
    ('body-bound', 'if body.len() > CHUNK', 'if false && body.len() > CHUNK', 'bounded_header_body_and_total_before_materialization'),
    ('unknown-version', 'if version != 2 {', 'if false && version != 2 {', 'opaque_and_unsupported_are_distinct_from_malformed_capture'),
    ('source-span', 'body_span: end..bytes.len()', 'body_span: end + 1..bytes.len()', 'exact_spans_binary_body_and_u64_coordinates_are_not_rounded'),
    ('rounded-coordinate', '        header,\n        body,', '        header: Header { ordinal: header.ordinal as f64 as u64, ..header },\n        body,', 'exact_spans_binary_body_and_u64_coordinates_are_not_rounded'),
]


def main():
    if not __debug__:
        raise RuntimeError('assertions required')
    parser = argparse.ArgumentParser()
    parser.add_argument("names", nargs="*")
    args = parser.parse_args()
    unknown = set(args.names) - {case[0] for case in CASES}
    if unknown:
        parser.error("unknown controls: " + ", ".join(sorted(unknown)))
    selected = [case for case in CASES if not args.names or case[0] in args.names]
    OUT.mkdir(parents=True, exist_ok=True)
    original = FILE.read_text()
    try:
        for name, old, new, test in selected:
            assert original.count(old) == 1, (name, original.count(old))
            FILE.write_text(original.replace(old, new))
            command = ['cargo', 'test', '--features', 'v2-crypto', '--test', 'evidence_reconstruction', test, '--', '--exact']
            run = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=180)
            log = run.stdout + run.stderr
            (OUT / (name + '.txt')).write_text(log + '\nexit=' + str(run.returncode) + '\n')
            assert run.returncode != 0, name + ' SURVIVED'
            assert 'could not compile' not in log, name + ' compile error'
            assert 'test ' + test + ' ... FAILED' in log, name + ' lacks named assertion failure'
            print('DEMONSTRATED:', name, flush=True)
            FILE.write_text(original)
    finally:
        FILE.write_text(original)
    run = subprocess.run(['cargo', 'test', '--features', 'v2-crypto', '--test', 'evidence_reconstruction'], cwd=ROOT, capture_output=True, text=True, timeout=180)
    (OUT / 'restored.txt').write_text(run.stdout + run.stderr + '\nexit=' + str(run.returncode) + '\n')
    assert run.returncode == 0, 'restored baseline failed'
    print(f'{len(selected)} controls; restored decoder suite passed.', flush=True)


if __name__ == '__main__':
    main()

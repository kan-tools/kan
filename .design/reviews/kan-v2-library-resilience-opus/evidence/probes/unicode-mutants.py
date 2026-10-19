#!/usr/bin/env python3
"""Directional-control regex mutants; strings built with explicit backslashes."""
import pathlib, subprocess, sys
here = pathlib.Path(__file__).resolve().parent
B = chr(92) + 'u'
DIR = 'all directional control families default to exact hex with explicit text access'
OLD = 'directional format controls default to exact hex and permit explicit UTF-8'
cases = [
    ('U19-no-alm', B+'061c'+B+'200e', B+'200e'),
    ('U20-no-lrm-rlm', B+'061c'+B+'200e'+B+'200f', B+'061c'),
    ('U21-no-isolates', B+'202a-'+B+'202e'+B+'2066-'+B+'2069', B+'202a-'+B+'202e'),
    ('U22-no-embeddings', B+'202a-'+B+'202e'+B+'2066-'+B+'2069', B+'202e'+B+'2066-'+B+'2069'),
    ('U22b-only-rlo-missing', B+'202a-'+B+'202e', B+'202a-'+B+'202d'),
]
for label, old, new in cases:
    subprocess.run([sys.executable, str(here / 'mutate.py'), label, 'web/library/app.js', old, new, 'node', DIR, OLD], check=False)

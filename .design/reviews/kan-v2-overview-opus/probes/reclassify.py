#!/usr/bin/env python3
"""Re-derive mutant verdicts from saved logs. The first mutate.py run mislabelled any log
containing cargo's 'error: test failed' as a compile failure. Usage: reclassify.py <mutants-dir>"""
import pathlib, re, sys

AUTHOR_PREFIX = ('po', 'UP', 'pm')  # reviewer probe test names
out = []
for log in sorted(pathlib.Path(sys.argv[1]).glob('*.txt')):
    if log.name.startswith('SUMMARY'):
        continue
    text = log.read_text()
    if 'could not compile' in text or re.search(r'^error\[E\d+\]', text, re.M):
        out.append(f'{log.stem}: COMPILE-FAILURE (not counted)')
        continue
    if log.stem.startswith('UM'):
        failed = sorted(set(re.findall(r'^✖ (.+?) \(\d', text, re.M)))
        ran = re.search(r'^ℹ tests (\d+)', text, re.M)
        ran = ran.group(1) if ran else '?'
    else:
        failed = sorted(set(re.findall(r'^test (\S+) \.\.\. FAILED', text, re.M)))
        ran = sum(int(n) for n in re.findall(r'^test result: \w+\. (\d+) passed', text, re.M)) + len(failed)
    author = [t for t in failed if not t.startswith(AUTHOR_PREFIX)]
    reviewer = [t for t in failed if t.startswith(AUTHOR_PREFIX)]
    verdict = 'KILLED' if failed else 'SURVIVED'
    by = 'author+reviewer' if author and reviewer else 'author' if author else 'reviewer-only' if reviewer else '-'
    out.append(f'{log.stem}: {verdict} by={by} ran={ran} author_failed={author} reviewer_failed={reviewer}')
print('\n'.join(out))

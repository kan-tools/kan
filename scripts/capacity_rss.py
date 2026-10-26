#!/usr/bin/env python3
"""One fresh Linux supervisor per worker: retain the child's lifetime peak RSS."""
import argparse
import json
from pathlib import Path
import platform
import resource
import subprocess
import sys

from capacity_evidence import atomic_json, validate_peak_calibration

SOURCE = 'getrusage(RUSAGE_CHILDREN).ru_maxrss:linux-kib:fresh-supervisor'
LIMIT_KIB = 512 * 1024


def require_peak(peak):
    if not isinstance(peak, int) or not 0 < peak <= LIMIT_KIB:
        raise ValueError('missing or excessive child peak RSS (512 MiB limit)')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--calibrate', action='store_true')
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if platform.system() != 'Linux':
        parser.error('Linux ru_maxrss units and semantics required')
    if args.output.exists():
        parser.error('refusing to overwrite prior RSS evidence')
    command = args.command
    if command[:1] == ['--']:
        command = command[1:]
    if args.calibrate:
        if command:
            parser.error('calibration cannot specify another command')
        command = [sys.executable, '-c', '''import json,mmap,resource
from pathlib import Path
def current():
 return int(next(s for s in Path('/proc/self/status').read_text().splitlines() if s.startswith('VmRSS:')).split()[1])
before=current()
b=mmap.mmap(-1,64*1024*1024)
for i in range(0,len(b),4096): b[i]=1
during=current()
peak=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
b.close()
print(json.dumps({'before_rss_kib':before,'during_rss_kib':during,'after_rss_kib':current(),
                  'during_peak_kib':peak,'after_peak_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}))
''']
    if not command:
        parser.error('missing worker command')
    # This process has exactly one child. RUSAGE_CHILDREN cannot inherit the
    # seed worker's peak or a previous sample's high-water mark.
    report = {'status': 'failed', 'source': SOURCE, 'calibration': args.calibrate}
    try:
        result = subprocess.run(command, timeout=40 * 60,
                                capture_output=args.calibrate, text=args.calibrate)
        peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        report.update(process_peak_rss_kib=peak, returncode=result.returncode)
        if result.returncode:
            raise RuntimeError(f'worker exited {result.returncode}')
        require_peak(peak)
        if args.calibrate:
            calibration = json.loads(result.stdout)
            report['allocation_probe'] = calibration
            validate_peak_calibration(report)
        report['status'] = 'complete'
    except BaseException as error:
        report['error'] = f'{type(error).__name__}: {error}'
        raise
    finally:
        atomic_json(args.output, report)


if __name__ == '__main__':
    main()

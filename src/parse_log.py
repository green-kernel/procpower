#!/usr/bin/env python3
"""
Parse the custom monitor log-file format into a list of dictionaries.

Usage
-----
python parse_log.py tmp/energy-XXXX.log
"""

import re
import argparse
from pathlib import Path
from pprint import pprint


def parse_monitor_file(path: str | Path):
    """Return a list of 'samples', one per timestamp block."""
    samples = []
    current = None

    # We do this with a regex to avoid splitting on whitespace which will break if we change the kernel module output format
    key_val_re = re.compile(r'^([a-zA-Z_]+)=(.+)$')

    pid_re = re.compile(
        r'^pid=(\d+)\s+'
        r'energy=(\d+)\s+'
        r'alive=(\d+)\s+'
        r'kernel=(\d+)\s+'
        r'cpu_ns=(\d+)\s+'
        r'mem=(\d+)\s+'
        r'instructions=(\d+)\s+'
        r'wakeups=(\d+)\s+'
        r'diski=(\d+)\s+'
        r'disko=(\d+)\s+'
        r'rx=(\d+)\s+'
        r'tx=(\d+)\s+'
        r'comm=(.+)$'
    )

    with open(path, encoding='utf-8') as f:
        for raw in f:
            line = raw.strip()
            if not line:                                  # blank
                continue

            if line.startswith('----'):                # block delimiter
                if current is not None:
                    samples.append(current)
                    current = None
                continue

            if line.startswith('timestamp='):             # new block
                if current is not None:
                    raise ValueError('Unexpected timestamp without block end')
                current = {'values': {}}

            kv_match = key_val_re.match(line)
            if kv_match and not line.startswith('pid='):  # top‑level field
                key, value = kv_match.groups()
                current[key] = int(value) if value.isdigit() else value
                continue

            pid_match = pid_re.match(line)                # per‑PID metrics
            if pid_match:
                (pid, energy, alive, kernel, cpu_ns, mem, instructions, wakeups,
                 diski, disko, rx, tx, comm) = pid_match.groups()
                current['values'][int(pid)] = {
                    'alive':        bool(int(alive)),
                    'energy':       int(energy),
                    'kernel':       bool(int(kernel)),
                    'cpu_ns':       int(cpu_ns),
                    'mem':          int(mem),
                    'instructions': int(instructions),
                    'wakeups':      int(wakeups),
                    'diski':        int(diski),
                    'disko':        int(disko),
                    'rx':           int(rx),
                    'tx':           int(tx),
                    'comm':         comm,
                }

    if current is not None:                               # final block
        samples.append(current)
    return samples

def remove_samples(samples, what, tf):
    for sample in samples:
        sample['values'] = {
            pid: values for pid, values in sample['values'].items()
            if values[what] == tf
        }

def compute_deltas(samples):
    if len(samples) < 2:
        return

    baseline = {
        pid: metrics.copy() for pid, metrics in samples[0]["values"].items()
    }

    for sample in samples[1:]:
        cur_vals = sample["values"]

        for pid, cur_metrics in list(cur_vals.items()):
            orig_metrics = cur_metrics.copy()
            prev_metrics = baseline.get(pid)
            if prev_metrics:
                for key, cur_v in cur_metrics.items():
                    if isinstance(cur_v, (int, float)):
                        cur_metrics[key] = cur_v - prev_metrics.get(key, 0)
            baseline[pid] = orig_metrics

def main():
    parser = argparse.ArgumentParser(description="This parses the readings from energy‑logger.sh")
    parser.add_argument("logfile", help="Path to log file")
    parser.add_argument("--deltas", action="store_true", help="Output per PID deltas (numeric fields only) relative to the previous sample",)

    args = parser.parse_args()

    samples = parse_monitor_file(args.logfile)

    # We do this with a pointer as the data might become large
    remove_samples(samples, 'alive', True)
    remove_samples(samples, 'kernel', False)

    if args.deltas:
        compute_deltas(samples)

    print(samples)
    #print(remove_dead_samples(samples)
    #pprint(samples, width=120)
    # for i in samples:
    #     print (i['values'][1]['cpu_ns'])


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Parse the custom monitor log-file format into a list of dictionaries.

Usage
-----
python parse_log.py tmp/energy-XXXX.log
"""

import re
import argparse
import pandas as pd
from pathlib import Path
import statsmodels.formula.api as smf

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
        data = f.read()

    blocks = [block.strip() for block in data.split("-------") if block.strip()]

    rows = []
    for block in blocks:
        rapl_match = re.search(r"rapl_psys_sum_uj=(\d+)", block)
        pid0_match = re.search(r"pid=0.*?cpu_ns=(\d+)\s+mem=(\d+)\s+instructions=(\d+)\s+wakeups=(\d+)\s+diski=(\d+)\s+disko=(\d+)\s+rx=(\d+)\s+tx=(\d+)", block)

        if rapl_match and pid0_match:
            rows.append({
                "rapl_psys_sum_uj": int(rapl_match.group(1)),
                "cpu_ns": int(pid0_match.group(1)),
                "mem": int(pid0_match.group(2)),
                "instructions": int(pid0_match.group(3)),
                "wakeups": int(pid0_match.group(4)),
                "diski": int(pid0_match.group(5)),
                "disko": int(pid0_match.group(6)),
                "rx": int(pid0_match.group(7)),
                "tx": int(pid0_match.group(8)),
            })

    return pd.DataFrame(rows, columns=["rapl_psys_sum_uj", "cpu_ns", "mem", "instructions", "wakeups", "diski", "disko", "rx", "tx"])

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
    parser.add_argument("--fit", action="store_true", help="Fit the data with an OLS model and validate normality assumptions",)

    args = parser.parse_args()

    df = parse_monitor_file(args.logfile)

    if args.deltas:
        df = df.diff()
        df = df.drop(index=0)
        print(df)
    else:
        print(df)

    if args.fit:
        # basic addition of variables
        model = smf.ols(formula="rapl_psys_sum_uj ~ cpu_ns + mem + instructions + wakeups + diski + disko + rx + tx", data=df, missing='raise').fit()
        ## polynomial example
        # model = smf.ols(formula="rapl_psys_sum_uj ~ cpu_ns + I(cpu_ns**2) + mem + instructions + wakeups + diski + disko + rx + tx", data=df, missing='raise').fit()

        # Transformation if instructions and time to ISP
        df['ips'] = (df['instructions'] / df['cpu_ns']).astype('int64')
        model = smf.ols(formula="rapl_psys_sum_uj ~ mem + ips + wakeups + diski + disko + rx + tx", data=df, missing='raise').fit()

        print(model.summary())


    #print(remove_dead_samples(samples)
    #pprint(samples, width=120)
    # for i in samples:
    #     print (i['values'][1]['cpu_ns'])


if __name__ == "__main__":
    main()

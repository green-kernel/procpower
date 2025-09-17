#!/usr/bin/env python3
import re
import os
import sys
import argparse
import subprocess
import psutil
import numpy as np
import pandas as pd
from time import sleep
from pathlib import Path
from sklearn.linear_model import LinearRegression, Ridge
from sklearn.metrics import (
    r2_score,
    mean_squared_error,
    mean_absolute_error,
    mean_absolute_percentage_error,
)
from sklearn.model_selection import train_test_split, KFold, cross_validate
from sklearn.metrics import mean_squared_error
import numpy as np

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

def numerical_stabilization(df, logarithm=False):
    # computing deltas is mandatory. Otherwise we carry huge bias with us that contains always different amounts of energy
    df = df.diff()
    df = df.drop(index=0)

    df['ips'] = (df['instructions'] / df['cpu_ns']).astype('int64') # maybe of use?


    if logarithm: # This transformations alters the interpretation as coeffcients are now multiplicative
        df = df.applymap(lambda x: np.log1p(x) if np.issubdtype(type(x), np.number) else x)
    else:
        df = df / 1e3 # helps making OLS cond. a more reliable indicator. Since we only linear transform this change does not influence the results and also does not change the predictors. Just easier to parse and understand the output of summary()
        # has the problem though of producting singularities ... :/

    return df

def fit_model(df, fit, no_validate=False):
    if fit == 'OLS':
       return smf.ols(formula="rapl_psys_sum_uj ~ instructions + ips + wakeups + rx + tx", data=df, missing='raise').fit()

    elif fit == 'OLS-idle':
       return smf.ols(formula="rapl_psys_sum_uj ~ wakeups", data=df, missing='raise').fit()

    elif fit == 'OLS-compute':
        return smf.ols(formula="rapl_psys_sum_uj ~ instructions", data=df, missing='raise').fit()

    elif fit == 'OLS-polynomial':
        print('Warning: Current implemented Polynomial transformation is non-sensical. Is just an example how to do it! Needs context aware implementation.')
        return smf.ols(formula="rapl_psys_sum_uj ~ cpu_ns + I(cpu_ns**2) + mem + instructions + wakeups + diski + disko + rx + tx", data=df, missing='raise').fit()

    elif fit == 'ridge':
        raise NotImplementedError('Ridge is not yet implemented, as it uses SKLearn.')
        model = Ridge(alpha=args.alpha, fit_intercept=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Fit model and estimate weights on data from energy‑logger.sh')
    parser.add_argument('logfile', help='Logfile of energy-logger to use')
    parser.add_argument('--dump-only', action='store_true', help='Dump only the parsed data',)

    parser.add_argument("--fit",
        choices=['OLS', 'OLS-compute', 'OLS-idle', 'OLS-polynomial', 'ridge'],
        help='Select model to use for fitting',
        default='OLS'
    )
    parser.add_argument('--no-validate', action='store_true', help='Do not validate statistical assumptions for model (Should only be used for testing as invalid assumptions can lead to false interpretations)')
    parser.add_argument('--predict', help='Supply a logifle to parse to make predictions on')
    parser.add_argument('--log', action='store_true',  help='Numerically stability the dataframe through logarthmic transformation')



    args = parser.parse_args()

    df = parse_monitor_file(args.logfile)

    df = numerical_stabilization(df, args.log)

    if args.dump_only:
        print(df)
        sys.exit(0)


    model = fit_model(df, args.fit, args.no_validate)

    if not args.no_validate:
        raise NotImplementedError()

    print(model.summary())

    if args.predict:
        df2 = parse_monitor_file(args.predict)

        df2 = numerical_stabilization(df2, args.log)

        predictions = model.predict(df2)

        # Calculate MAE
        mae = mean_absolute_error(df2['rapl_psys_sum_uj'], predictions)
        mape = mean_absolute_percentage_error(df2['rapl_psys_sum_uj'], predictions)
        r2 = r2_score(df2['rapl_psys_sum_uj'], predictions)


        print("MAE:", mae)
        print("MAPE:", mape)
        print("R²:", r2)

#        import plotext as plt

#        plt.scatter(df2['rapl_psys_sum_uj'], predictions)
#        plt.title("Predicted vs Actual")
#        plt.show()

        errors = abs(df2['rapl_psys_sum_uj'] - predictions)
        top_errors = df2.iloc[errors.nlargest(10).index]
        print(top_errors)

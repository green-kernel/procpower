#!/usr/bin/env python3
import re
import sys
import argparse
from pathlib import Path

import numpy as np
import pandas as pd

from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LinearRegression
from sklearn.metrics import r2_score, mean_absolute_error, mean_absolute_percentage_error

import statsmodels.api as sm

def parse_monitor_file(path: str | Path):
    """Parse logfile into a DataFrame of relevant metrics."""
    rows = []

    pid0_re = re.compile(
        r"pid=0.*?"
        r"cpu_ns=(\d+)\s+mem=(\d+)\s+instructions=(\d+)\s+wakeups=(\d+)\s+"
        r"diski=(\d+)\s+disko=(\d+)\s+rx=(\d+)\s+tx=(\d+)"
    )

    with open(path, encoding="utf-8") as f:
        blocks = [b.strip() for b in f.read().split("-------") if b.strip()]

    for block in blocks:
        rapl = re.search(r"rapl_psys_sum_uj=(\d+)", block)
        pid0 = pid0_re.search(block)

        if rapl and pid0:
            rows.append({
                "rapl_psys_sum_uj": int(rapl.group(1)),
                "cpu_ns": int(pid0.group(1)),
                "mem": int(pid0.group(2)),
                "instructions": int(pid0.group(3)),
                "wakeups": int(pid0.group(4)),
                "diski": int(pid0.group(5)),
                "disko": int(pid0.group(6)),
                "rx": int(pid0.group(7)),
                "tx": int(pid0.group(8)),
            })

    return pd.DataFrame(rows)



def fit_statsmodels_ols(X, y, FEATURES, intercept, scaler=None):
    """Return a statsmodels OLS model for summary purposes."""
    X_df = pd.DataFrame(X, columns=FEATURES)
    if intercept:
        X_df = sm.add_constant(X_df)  # adds intercept as 'const'
    model = sm.OLS(y, X_df).fit()

    if scaler is not None:
        beta_scaled = model.params[1:].values  # skip const
        sigma = scaler.scale_
        mu = scaler.mean_
        beta_original = beta_scaled / sigma
        intercept_original = model.params[0] - np.sum(beta_scaled * mu / sigma)

        params_rescaled = pd.Series([intercept_original, *beta_original], index=model.params.index)
        model.params_rescaled = params_rescaled
    else:
        model.params_rescaled = model.params.copy()


    return model


def fit_sklearn_model(X, y, intercept):
    """Return sklearn LinearRegression fitted on scaled data."""
    model = LinearRegression(fit_intercept=intercept)
    model.fit(X, y)
    return model


def calculate_metrics(y_true, y_pred):
    mae = mean_absolute_error(y_true, y_pred)
    mape = mean_absolute_percentage_error(y_true, y_pred)
    r2 = r2_score(y_true, y_pred)
    return mae, mape, r2

def select_fit_and_features(df_inner, fit):
    # add extra features
    df_inner['ips'] = (df_inner['instructions'] / df_inner['cpu_ns'])

    if fit == 'ridge':
        raise NotImplementedError('Ridge is not yet implemented, as it uses SKLearn.')
        #return Ridge(alpha=args.alpha, fit_intercept=True).fit()
    elif fit == 'OLS':
        FEATURES = ['instructions', 'wakeups', 'rx', 'tx']
    elif fit == 'OLS-extra':
        FEATURES = ['instructions', 'ips', 'wakeups', 'rx', 'tx']
    elif fit == 'OLS-idle':
        FEATURES = ['wakeups']
    elif fit == 'OLS-compute':
        FEATURES = ['instructions']
    elif fit == 'OLS-polynomial':
        print('Warning: Current implemented Polynomial transformation is non-sensical. Is just an example how to do it! Needs context aware implementation.')
        df_inner['cpu_ns_squared'] = (df_inner['cpu_ns']**2).astype('int64')
        FEATURES = ['cpu_ns', 'cpu_ns_squared', 'ips', 'mem', 'instructions', 'wakeups', 'diski', 'disko', 'rx', 'tx']

    return df_inner, FEATURES


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fit model and estimate weights on energy-logger data")
    parser.add_argument("logfile", help="Logfile of energy-logger to use")
    parser.add_argument("--predict", help="Logfile to parse for prediction")
    parser.add_argument("--fit",
        choices=['OLS', 'OLS-extra', 'OLS-compute', 'OLS-idle', 'OLS-polynomial', 'ridge'],
        help='Select model to use for fitting',
        default='OLS'
    )
    parser.add_argument("--log", action="store_true", help="Apply log transform. Can improve stability. Will prohibt interpretation of coefficients.")
    parser.add_argument("--scale", action="store_true", help="Apply standard scaling. Can improve stability.")
    parser.add_argument("--add-intercept", action="store_true", default=False, help="Use an intercept for the OLS model")
    parser.add_argument("--dump-raw", action="store_true", help="Dump parsed data")
    parser.add_argument("--dump-diff", action="store_true", help="Dump parsed and diffed data")
    parser.add_argument("--dump-predictions", action="store_true", help="Dump predictions")
    parser.add_argument("--dump-top-errors", action="store_true", help="Dump top errors")
    parser.add_argument("--no-summary", action="store_true", help="Do not print statsmodels OLS summary")
    args = parser.parse_args()


    df = parse_monitor_file(args.logfile)

    if args.dump_raw:
        print(df)

    df = df.diff().drop(index=0).reset_index(drop=True)

    df, FEATURES = select_fit_and_features(df, args.fit)

    TARGET = 'rapl_psys_sum_uj'

    if args.dump_diff:
        print(df)


    if args.log:
        df = df.applymap(lambda x: np.log1p(x) if np.issubdtype(type(x), np.number) else x)

    X = df[FEATURES]
    y = df[TARGET]

    if X.isna().any().any() or y.isna().any():
        raise ValueError('NA Values in df found!')

    scaler = None
    if args.scale:
        scaler = StandardScaler()
        X = scaler.fit_transform(X)

    sk_model = fit_sklearn_model(X, y, args.add_intercept)

    # Fit statsmodels OLS only for summary

    sm_model = fit_statsmodels_ols(X, y, FEATURES, args.add_intercept, scaler)

    if not args.no_summary:
        print(sm_model.summary())
        print('Rescaled params:\n', sm_model.params_rescaled)

    if args.predict:
        df2 = parse_monitor_file(args.predict)

        df2 = df2.diff().drop(index=0).reset_index(drop=True)

        if args.log:
            df2 = df2.applymap(lambda x: np.log1p(x) if np.issubdtype(type(x), np.number) else x)

        df2, FEATURES = select_fit_and_features(df2, args.fit)

        X2 = df2[FEATURES]
        y2_true = df2[TARGET]

        if X2.isna().any().any() or y2_true.isna().any():
            raise ValueError('NA Values in Prediction df found!')

        if args.scale:
            X2 = scaler.transform(df2[FEATURES])


        predictions = sk_model.predict(X2)

        if args.log:
            predictions = np.expm1(predictions)

        if args.dump_predictions:
            X2_df = pd.DataFrame(X2, columns=FEATURES)
            y2_df = pd.Series(predictions, name=TARGET)
            X2_df.insert(0, y2_df.name, y2_df)

            print(X2_df)


        print("MAE:", mean_absolute_error(y2_true, predictions))
        print("MAPE:", mean_absolute_percentage_error(y2_true, predictions))
        print("R²:", r2_score(y2_true, predictions))

        # Show top errors
        if args.dump_top_errors:
            errors = abs(y2_true - predictions)
            top_errors = df2.iloc[errors.nlargest(10).index]
            print(top_errors)

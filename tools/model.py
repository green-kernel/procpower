#!/usr/bin/env python3
import re
import sys
import argparse
from pathlib import Path

import numpy as np
import pandas as pd

from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LinearRegression, Ridge, HuberRegressor
from sklearn.metrics import r2_score, mean_absolute_error, mean_absolute_percentage_error
import plotext as plt

from xgboost import XGBRegressor
import statsmodels.api as sm

TARGET_COL = None # Will be set by argparse

def parse_monitor_file(path: str | Path):
    """Parse logfile into a DataFrame of relevant metrics."""
    rows = []

    pid0_re = re.compile(
        r"pid=0.*?"
        r"cpu_ns=(\d+)\s+mem=(\d+)\s+instructions=(\d+)\s+wakeups=(\d+)\s+"
        r"diski=(\d+)\s+disko=(\d+)\s+rx=(\d+)\s+tx=(\d+)"
    )

    target_col_re = re.compile(rf"{TARGET_COL}=(\d+)")
    timestamp_re =  re.compile(r'timestamp=(\d+)')


    with open(path, encoding="utf-8") as f:
        blocks = [b.strip() for b in f.read().split("-------") if b.strip()]

    for block in blocks:
        rapl = target_col_re.search(block)

        pid0 = pid0_re.search(block)
        timestamp = timestamp_re.search(block)

        if rapl and pid0:
            rows.append({
                TARGET_COL: int(rapl.group(1)),
                "timestamp": int(timestamp.group(1)),
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
        if intercept:
            beta_scaled = model.params[1:].values
            beta_index = model.params.index[1:]
            intercept_value = model.params.iloc[0]

            sigma = scaler.scale_
            mu = scaler.mean_

            beta_original = beta_scaled / sigma
            intercept_uncentered = intercept_value - np.sum(beta_scaled * mu / sigma)

            params_rescaled = pd.Series([intercept_uncentered, *beta_original], index=model.params.index)
        else:
            beta_scaled = model.params.values
            beta_index = model.params.index

            sigma = scaler.scale_
            beta_original = beta_scaled / sigma

            params_rescaled = pd.Series(beta_original, index=beta_index)
        model.params_rescaled = params_rescaled
    else:
        model.params_rescaled = model.params.copy()


    return model


def fit_sklearn_model(model_name, X, y, intercept):
    """Return sklearn LinearRegression fitted on scaled data."""
    if model_name == 'ols':
        model = LinearRegression(fit_intercept=intercept)
    elif model_name == 'ridge':
        model = Ridge(alpha=1e6, fit_intercept=intercept)
    elif model_name == 'huber':
        # HuberRegressor uses epsilon for outlier sensitivity (default 1.35)
        model = HuberRegressor(epsilon=1.35, alpha=1e6, fit_intercept=intercept, max_iter=1000)
    elif model_name == 'xgboost':
        # XGBRegressor doesn't need fit_intercept; it handles internally
        model = XGBRegressor(
            n_estimators=500,
            learning_rate=0.05,
            max_depth=3,
            objective='reg:squarederror',
            random_state=42,
            verbosity=0
        )
    else:
        raise ValueError(f"Unknown model supplied: {model}")

    model.fit(X, y)

    return model


def calculate_metrics(y_true, y_pred):
    mae = mean_absolute_error(y_true, y_pred)
    mape = mean_absolute_percentage_error(y_true, y_pred)
    r2 = r2_score(y_true, y_pred)
    return mae, mape, r2

def select_fit_and_features(df_inner, features):
    # add extra features
    df_inner['ips'] = (df_inner['instructions'] / df_inner['cpu_ns'])

    if features == 'normal':
        feature_list = ['instructions', 'wakeups', 'rx', 'tx']
    elif features == 'extra':
        feature_list = ['instructions', 'ips', 'wakeups', 'rx', 'tx']
    elif features == 'all':
        feature_list = ['cpu_ns', 'mem', 'instructions', 'wakeups', 'diski', 'disko', 'rx', 'tx']
    elif features == 'idle':
        feature_list = ['wakeups']
    elif features == 'compute':
        feature_list = ['instructions']
    elif features == 'polynomial':
        print('Warning: Current implemented Polynomial transformation is non-sensical. Is just an example how to do it! Needs context aware implementation.')
        df_inner['cpu_ns_squared'] = (df_inner['cpu_ns']**2).astype('int64')
        feature_list = ['cpu_ns', 'cpu_ns_squared', 'ips', 'mem', 'instructions', 'wakeups', 'diski', 'disko', 'rx', 'tx']

    return df_inner, feature_list

def safe_mape(y_true, y_pred, eps=1e-8):
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    denom = np.maximum(np.abs(y_true), eps)
    return np.mean(np.abs(y_true - y_pred) / denom)

def wape(y_true, y_pred):
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    return np.sum(np.abs(y_true - y_pred)) / np.sum(np.abs(y_true))

def smape(y_true, y_pred, eps=1e-8):
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    denom = np.maximum(np.abs(y_true) + np.abs(y_pred), eps)
    return np.mean(2 * np.abs(y_pred - y_true) / denom)

def main(args):
    global TARGET_COL

    TARGET_COL = args.target

    df = parse_monitor_file(args.logfile)

    if args.dump_raw:
        print(df)

    df_original = df.copy()
    df = df.diff()
    df["timestamp"] = df_original["timestamp"]
    df["sample_ns"] = df_original["sample_ns"]

    df = df.drop(index=0).reset_index(drop=True)

    if args.plot_only:
        x = df["timestamp"].tolist()
        y = df[TARGET_COL].tolist()

        plt.clear_data()
        plt.plot(x, y, marker='dot')
        plt.xlabel("Time")
        plt.ylabel(TARGET_COL)
        plt.show()
        return

    df, FEATURES = select_fit_and_features(df, args.features)

    if args.dump_diff:
        print(df)


    if args.log:
        df = df.applymap(lambda x: np.log1p(x) if np.issubdtype(type(x), np.number) else x)

    X = df[FEATURES]
    y = df[TARGET_COL]

    if X.isna().any().any() or y.isna().any():
        raise ValueError('NA Values in df found!')

    scaler = None
    if args.scale:
        scaler = StandardScaler()
        X = scaler.fit_transform(X)

    sk_model = fit_sklearn_model(args.model, X, y, args.add_intercept)

    # Fit statsmodels OLS only for summary
    if args.model == 'ols':
        if not args.no_validate:
            raise NotImplementedError('Validation is not implented yet. Please use --no-validate for now ...')

        sm_model = fit_statsmodels_ols(X, y, FEATURES, args.add_intercept, scaler)

        if not args.no_summary:
            print(sm_model.summary())
            print('Rescaled params:\n', sm_model.params_rescaled)

    if args.predict:
        df2 = parse_monitor_file(args.predict)

        df2_original = df2.copy()
        df2 = df2.diff()
        df2["timestamp"] = df2_original["timestamp"]
        df2["sample_ns"] = df2_original["sample_ns"]

        df2 = df2.drop(index=0).reset_index(drop=True)

        if args.log:
            df2 = df2.applymap(lambda x: np.log1p(x) if np.issubdtype(type(x), np.number) else x)

        df2, FEATURES = select_fit_and_features(df2, args.features)

        X2 = df2[FEATURES]
        y2_true = df2[TARGET_COL]

        if X2.isna().any().any() or y2_true.isna().any():
            raise ValueError('NA Values in Prediction df found!')

        if args.scale:
            X2 = scaler.transform(df2[FEATURES])


        predictions = sk_model.predict(X2)

        if args.log:
            predictions = np.expm1(predictions)

        if args.dump_predictions:
            X2_df = pd.DataFrame(X2, columns=FEATURES)
            y2_df = pd.Series(predictions, name=TARGET_COL)
            X2_df.insert(0, y2_df.name, y2_df)
            print(X2_df)


        print("MAE:", mean_absolute_error(y2_true, predictions))
        print("MAPE (%):", 100*mean_absolute_percentage_error(y2_true, predictions))
        print("WAPE (%):", 100 * wape(y2_true, predictions))
        print("sMAPE (%):", 100 * smape(y2_true, predictions))
        print("R²:", r2_score(y2_true, predictions))

        # Show top errors
        if args.dump_top_errors:
            errors = abs(y2_true - predictions)
            top_errors = df2.iloc[errors.nlargest(10).index]
            print(top_errors)



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fit model and estimate weights on energy-logger data")
    parser.add_argument("logfile", help="Logfile of energy-logger to use")
    parser.add_argument("--predict", help="Logfile to parse for prediction")
    parser.add_argument("--features",
        choices=['normal', 'extra', 'compute', 'idle', 'polynomial', 'all'],
        help='Select feature set to include for fitting',
        default='normal'
    )
    parser.add_argument("--model",
        choices=['ols', 'xgboost', 'ridge', 'huber', 'xgboost'],
        help='Select model to use for fitting',
        default='ols'
    )

    parser.add_argument("--log", action="store_true", help="Apply log transform. Can improve stability. Will prohibt interpretation of coefficients.")
    parser.add_argument("--scale", action="store_true", help="Apply standard scaling. Can improve stability.")
    parser.add_argument("--add-intercept", action="store_true", default=False, help="Use an intercept for the OLS model")
    parser.add_argument("--dump-raw", action="store_true", help="Dump parsed data")
    parser.add_argument("--dump-diff", action="store_true", help="Dump parsed and diffed data")
    parser.add_argument("--dump-predictions", action="store_true", help="Dump predictions")
    parser.add_argument("--dump-top-errors", action="store_true", help="Dump top errors")
    parser.add_argument("--no-summary", action="store_true", help="Do not print statsmodels OLS summary")
    parser.add_argument("--no-validate", action="store_true", help="Do not validate OLS model assumptions")
    parser.add_argument("--target", type=str, choices=["rapl_psys_sum_uj", "rapl_core_sum_uj"], default="rapl_psys_sum_uj")
    parser.add_argument("--plot-only", action='store_true', help="Plot the training data file and exit")

    args = parser.parse_args()

    main(args)

#!/usr/bin/env python3
from pathlib import Path
import argparse
import numpy as np
import pandas as pd
from sklearn.linear_model import LinearRegression, Ridge
from sklearn.metrics import (
    r2_score,
    mean_squared_error,
    mean_absolute_error,
    mean_absolute_percentage_error,
)
from sklearn.model_selection import train_test_split, KFold, cross_validate
from sklearn.metrics import mean_squared_error

# ---- reuse helper functions you already have -----------------------------
from parse_log import (
    parse_monitor_file,
    remove_samples,
    compute_deltas,
)
# --------------------------------------------------------------------------

FEATURES = [
    "cpu_ns",
    "mem",
    "instructions",
    "wakeups",
    "diski",
    "disko",
    "rx",
    "tx",
]

def aggregate_sample(sample: dict, use_rate: bool) -> dict:
    """Collapse one timestamp block into a single feature row."""
    row = {f: 0.0 for f in FEATURES}
    for metrics in sample["values"].values():
        for f in FEATURES:
            row[f] += metrics[f]

    if use_rate and sample.get("sample_ns"):
        secs = sample["sample_ns"] / 1e9
        for f in FEATURES:
            row[f] /= secs

    row["target"] = sample["rapl_psys_sum_uj"]
    return row

def load_dataframe(paths: list[Path], deltas: bool, rate: bool) -> pd.DataFrame:
    rows = []
    for path in paths:
        samples = parse_monitor_file(path)
        remove_samples(samples, "alive", True)
        #remove_samples(samples, "kernel", False)
        if deltas:
            compute_deltas(samples)
        rows.extend(aggregate_sample(s, rate) for s in samples)
    return pd.DataFrame(rows)

# --------------------------------------------------------------------------

def print_metrics(y_true, y_pred, label="test"):
    rmse = np.sqrt(mean_squared_error(y_true, y_pred))
    mae  = mean_absolute_error(y_true, y_pred)
    mape = mean_absolute_percentage_error(y_true, y_pred)
    r2   = r2_score(y_true, y_pred)

    print(f"\n# --- {label} metrics ---")
    print(f"R²     : {r2:7.4f}")
    print(f"RMSE   : {rmse:10.2f}  μJ")
    print(f"MAE    : {mae:10.2f}  μJ")
    print(f"MAPE   : {mape*100:7.2f}  %")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("logfiles", nargs="+", type=Path)
    ap.add_argument("--deltas", action="store_true",
                    help="Use per-PID deltas (subtract previous sample)")
    ap.add_argument("--rate", action="store_true",
                    help="Convert counters to per-second rates")
    ap.add_argument("--ridge", action="store_true",
                    help="Use Ridge (L2) instead of plain OLS")
    ap.add_argument("--alpha", type=float, default=1.0,
                    help="Ridge regularisation strength (ignored without --ridge)")
    ap.add_argument("--test-frac", type=float, default=0.25,
                    help="Fraction of data reserved for the hold-out test set")
    ap.add_argument("--cv", type=int, default=0,
                    help="If >0, run k-fold cross-validation instead of single split")
    args = ap.parse_args()

    # ----- data ------------------------------------------------------------
    df = load_dataframe(args.logfiles, args.deltas, args.rate).dropna()
    X = df[FEATURES].values.astype(np.float64)
    y = df["target"].values.astype(np.float64)

    # ----- choose model ----------------------------------------------------
    if args.ridge:
        model = Ridge(alpha=args.alpha, fit_intercept=True)
    else:
        model = LinearRegression(fit_intercept=True)

    # ======= option 1: k-fold CV ===========================================
    if args.cv > 1:
        cv = KFold(n_splits=args.cv, shuffle=True, random_state=42)
        cv_results = cross_validate(
            model,
            X,
            y,
            cv=cv,
            scoring={
                "r2": "r2",
                "neg_rmse": "neg_root_mean_squared_error",
                "neg_mae": "neg_mean_absolute_error",
                "neg_mape": "neg_mean_absolute_percentage_error",
            },
            return_train_score=False,
        )
        print("\n# === cross-validation (k = %d) ===" % args.cv)
        for metric, vals in cv_results.items():
            if metric.startswith("test_"):
                name = metric[5:].lstrip("neg_")
                scores = -vals if metric.startswith("test_neg") else vals
                print(f"{name.upper():5s}: {scores.mean():.4f} ± {scores.std():.4f}")
        # Fit on full data so we can output coefficients below
        model.fit(X, y)

    # ======= option 2: single train/test split =============================
    else:
        X_tr, X_te, y_tr, y_te = train_test_split(
            X, y, test_size=args.test_frac, random_state=42, shuffle=True
        )
        model.fit(X_tr, y_tr)
        y_pred = model.predict(X_te)
        print_metrics(y_te, y_pred)

    # ----- coefficients ----------------------------------------------------
    weights = dict(zip(FEATURES, model.coef_))
    bias    = float(model.intercept_)

    print("\n# --- coefficients ---")
    for k, v in weights.items():
        print(f"{k:14s} = {v}")
    print(f"bias          = {bias:.6e}")

if __name__ == "__main__":
    main()

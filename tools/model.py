#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd
from scipy.optimize import lsq_linear
from sklearn.ensemble import HistGradientBoostingRegressor
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score


NL_LUT_BINS = 8


@dataclass(frozen=True)
class FeatureSpec:
    raw_key: str
    param_name: str
    unit: float
    is_counter: bool


FEATURES: list[FeatureSpec] = [
    FeatureSpec("cpu_ns", "w_cpu_ns", 1_000_000.0, True),              # 1 ms
    FeatureSpec("mem", "w_mem_bytes", float(1 << 20), False),          # 1 MiB
    FeatureSpec("instructions", "w_instructions", 1_000_000.0, True),  # 1M instructions
    FeatureSpec("wakeups", "w_wakeups", 1.0, True),
    FeatureSpec("diski", "w_disk_read_bytes", 4096.0, True),           # 4 KiB
    FeatureSpec("disko", "w_disk_write_bytes", 4096.0, True),          # 4 KiB
    FeatureSpec("rx", "w_net_rx_packets", 1.0, True),
    FeatureSpec("tx", "w_net_tx_packets", 1.0, True),
]

TARGET_COL = None # will be overridden later
FEATURE_COLS = [f.param_name for f in FEATURES]
BASELINE_WEIGHTS = {
    "w_cpu_ns": 5.0,
    "w_mem_bytes": 0.0,
    "w_instructions": 5.0,
    "w_wakeups": 0.0,
    "w_disk_read_bytes": 0.0,
    "w_disk_write_bytes": 0.0,
    "w_net_rx_packets": 0.0,
    "w_net_tx_packets": 0.0,
}

IDX = {
    "cpu": [0, 2, 3],  # cpu_ns + instructions + wakeups
    "mem": [1],
    "disk": [4, 5],    # diski + disko
    "net": [6, 7],     # rx + tx
}


def _parse_numeric(value: str) -> int | str:
    try:
        return int(value, 10)
    except ValueError:
        return value


def _parse_pid_line(line: str) -> dict[str, int | str] | None:
    if not line.startswith("pid="):
        return None

    out: dict[str, int | str] = {}
    for token in line.split():
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        out[key] = _parse_numeric(value)
    return out


def parse_monitor_file(path: Path) -> list[dict]:
    blocks: list[dict] = []
    cur: dict = {"pids": {}}

    def flush_current() -> None:
        nonlocal cur
        if cur.get("timestamp") is not None and cur.get("pids"):
            blocks.append(cur)
        cur = {"pids": {}}

    with path.open("r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            if line.startswith("-------"):
                flush_current()
                continue

            pid_row = _parse_pid_line(line)
            if pid_row is not None:
                if "pid" in pid_row and isinstance(pid_row["pid"], int):
                    cur["pids"][pid_row["pid"]] = pid_row
                continue

            if "=" in line:
                key, value = line.split("=", 1)
                cur[key] = _parse_numeric(value)

    flush_current()
    return blocks


def blocks_to_system_df(blocks: list[dict], source: Path) -> pd.DataFrame:
    rows: list[dict] = []
    for block in blocks:
        pid0 = block.get("pids", {}).get(0)
        if not pid0:
            continue
        if TARGET_COL not in block:
            continue

        row = {
            "source": str(source),
            "timestamp": block.get("timestamp"),
            "sample_ns": block.get("sample_ns"),
            TARGET_COL: block[TARGET_COL],
        }

        for spec in FEATURES:
            raw_val = pid0.get(spec.raw_key, 0)
            if not isinstance(raw_val, int):
                raw_val = 0
            row[spec.raw_key] = raw_val
        rows.append(row)

    df = pd.DataFrame(rows)
    if df.empty:
        return df
    return df.sort_values("timestamp").reset_index(drop=True)


def cpu_util_permille(cpu_delta_ns: pd.Series, period_ns: pd.Series) -> pd.Series:
    denom = period_ns.clip(lower=1)
    util = (cpu_delta_ns.astype(np.float64) * 1000.0) / denom.astype(np.float64)
    return util.clip(lower=0.0, upper=1000.0)


def cpu_util_bin(util_permille: pd.Series) -> pd.Series:
    bins = np.floor((util_permille * NL_LUT_BINS) / 1001.0).astype(int)
    return bins.clip(lower=0, upper=NL_LUT_BINS - 1)


def activity_log2_bin(activity_units: pd.Series) -> pd.Series:
    safe = np.maximum(activity_units.astype(np.float64), 1.0)
    bins = np.floor(np.log2(safe)).astype(int)
    bins[activity_units <= 0] = 0
    return bins.clip(lower=0, upper=NL_LUT_BINS - 1)


def build_training_rows(
    system_df: pd.DataFrame,
    mode: str,
    min_target_uj: float,
) -> pd.DataFrame:
    if system_df.empty:
        return system_df

    if mode != "delta":
        raise ValueError("Only --mode delta is supported")

    work = system_df.copy()
    counter_cols = [f.raw_key for f in FEATURES if f.is_counter]

    work[f"d_{TARGET_COL}"] = work[TARGET_COL].diff()
    for col in counter_cols:
        work[f"d_{col}"] = work[col].diff()

    work = work.iloc[1:].copy()
    work = work[work[f"d_{TARGET_COL}"] >= min_target_uj]

    for col in counter_cols:
        work = work[work[f"d_{col}"] >= 0]

    out = pd.DataFrame(index=work.index)
    out["timestamp"] = work["timestamp"]
    out["sample_ns"] = work["sample_ns"]
    out["target_uj"] = work[f"d_{TARGET_COL}"]

    for spec in FEATURES:
        if spec.is_counter:
            out[spec.param_name] = work[f"d_{spec.raw_key}"] / spec.unit
        else:
            out[spec.param_name] = work[spec.raw_key] / spec.unit  # always include memory

    out["cpu_util_permille"] = cpu_util_permille(work["d_cpu_ns"], work["sample_ns"])
    out["cpu_bin"] = cpu_util_bin(out["cpu_util_permille"])

    out["mem_activity"] = out["w_mem_bytes"]
    out["disk_activity"] = out["w_disk_read_bytes"] + out["w_disk_write_bytes"]
    out["net_activity"] = out["w_net_rx_packets"] + out["w_net_tx_packets"]

    out["mem_bin"] = activity_log2_bin(out["mem_activity"])
    out["disk_bin"] = activity_log2_bin(out["disk_activity"])
    out["net_bin"] = activity_log2_bin(out["net_activity"])

    out = out.replace([np.inf, -np.inf], np.nan).dropna()
    out = out[(out[FEATURE_COLS].sum(axis=1) > 0)]
    return out.reset_index(drop=True)


def gather_rows(paths: Iterable[Path], mode: str, min_target_uj: float) -> pd.DataFrame:
    rows: list[pd.DataFrame] = []
    for path in paths:
        blocks = parse_monitor_file(path)
        system_df = blocks_to_system_df(blocks, path)
        if system_df.empty:
            continue
        data = build_training_rows(system_df, mode, min_target_uj)
        if not data.empty:
            rows.append(data)

    if not rows:
        return pd.DataFrame()
    return pd.concat(rows, ignore_index=True)


def split_random(df: pd.DataFrame, test_frac: float, seed: int) -> tuple[pd.DataFrame, pd.DataFrame]:
    if not 0 < test_frac < 1:
        raise ValueError("test-frac must be in (0, 1)")
    rng = np.random.default_rng(seed)
    idx = rng.permutation(len(df))
    cut = max(1, int(len(df) * (1.0 - test_frac)))
    cut = min(cut, len(df) - 1)
    train_idx = idx[:cut]
    test_idx = idx[cut:]
    return df.iloc[train_idx].copy(), df.iloc[test_idx].copy()


def trim_by_quantile(
    train_df: pd.DataFrame,
    test_df: pd.DataFrame,
    quantile: float,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    if quantile >= 1.0:
        return train_df, test_df
    q = train_df["target_uj"].quantile(quantile)
    return (
        train_df[train_df["target_uj"] <= q],
        test_df[test_df["target_uj"] <= q],
    )


def fit_nonnegative_ridge(X: np.ndarray, y: np.ndarray, alpha: float) -> np.ndarray:
    if alpha < 0:
        raise ValueError("alpha must be >= 0")

    if alpha > 0:
        reg = np.sqrt(alpha) * np.eye(X.shape[1], dtype=np.float64)
        X_aug = np.vstack([X, reg])
        y_aug = np.concatenate([y, np.zeros(X.shape[1], dtype=np.float64)])
    else:
        X_aug = X
        y_aug = y

    res = lsq_linear(X_aug, y_aug, bounds=(0, np.inf), method="trf", lsmr_tol="auto")
    if not res.success:
        raise RuntimeError(f"linear solver failed: {res.message}")
    return res.x


def fit_two_stage_nonnegative_ridge(
    X: np.ndarray,
    y: np.ndarray,
    alpha: float,
    stage1_idx: list[int],
    stage2_idx: list[int],
) -> np.ndarray:
    w = np.zeros(X.shape[1], dtype=np.float64)
    X1 = X[:, stage1_idx]
    w1 = fit_nonnegative_ridge(X1, y, alpha)
    w[stage1_idx] = w1
    residual = y - X1 @ w1

    X2 = X[:, stage2_idx]
    w2 = fit_nonnegative_ridge(X2, residual, alpha)
    w[stage2_idx] = w2
    return w


def _group_base(X_lin: np.ndarray, w: np.ndarray, idxs: list[int]) -> np.ndarray:
    return X_lin[:, idxs] @ w[idxs]


def fit_piecewise_distill_multigroup(
    cpu_base: np.ndarray,
    mem_base: np.ndarray,
    disk_base: np.ndarray,
    net_base: np.ndarray,
    cpu_bins: np.ndarray,
    mem_bins: np.ndarray,
    disk_bins: np.ndarray,
    net_bins: np.ndarray,
    target: np.ndarray,
) -> tuple[float, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    n = len(target)
    cols = 1 + 4 * NL_LUT_BINS
    A = np.zeros((n, cols), dtype=np.float64)
    A[:, 0] = 1.0

    for i in range(NL_LUT_BINS):
        A[cpu_bins == i, 1 + i] = cpu_base[cpu_bins == i]
        A[mem_bins == i, 1 + NL_LUT_BINS + i] = mem_base[mem_bins == i]
        A[disk_bins == i, 1 + 2 * NL_LUT_BINS + i] = disk_base[disk_bins == i]
        A[net_bins == i, 1 + 3 * NL_LUT_BINS + i] = net_base[net_bins == i]

    res = lsq_linear(A, target, bounds=(0, np.inf), method="trf", lsmr_tol="auto")
    if not res.success:
        raise RuntimeError(f"distill solver failed: {res.message}")

    x = res.x
    idle = float(x[0])
    cpu_mul = x[1:1 + NL_LUT_BINS]
    mem_mul = x[1 + NL_LUT_BINS:1 + 2 * NL_LUT_BINS]
    disk_mul = x[1 + 2 * NL_LUT_BINS:1 + 3 * NL_LUT_BINS]
    net_mul = x[1 + 3 * NL_LUT_BINS:1 + 4 * NL_LUT_BINS]
    return idle, cpu_mul, mem_mul, disk_mul, net_mul


def fill_sparse_bins(mults: np.ndarray, bins: np.ndarray, min_samples: int = 20) -> np.ndarray:
    counts = np.bincount(bins, minlength=NL_LUT_BINS)
    filled = mults.copy()
    for i in range(NL_LUT_BINS):
        if counts[i] >= min_samples and filled[i] > 0:
            continue
        left = i - 1
        right = i + 1
        repl = None
        while left >= 0 or right < NL_LUT_BINS:
            if left >= 0 and counts[left] >= min_samples and filled[left] > 0:
                repl = filled[left]
                break
            if right < NL_LUT_BINS and counts[right] >= min_samples and filled[right] > 0:
                repl = filled[right]
                break
            left -= 1
            right += 1
        filled[i] = repl if repl is not None else 1.0
    return filled


def piecewise_predict(
    idle_uj: float,
    cpu_base: np.ndarray,
    mem_base: np.ndarray,
    disk_base: np.ndarray,
    net_base: np.ndarray,
    cpu_bins: np.ndarray,
    mem_bins: np.ndarray,
    disk_bins: np.ndarray,
    net_bins: np.ndarray,
    cpu_mul: np.ndarray,
    mem_mul: np.ndarray,
    disk_mul: np.ndarray,
    net_mul: np.ndarray,
) -> np.ndarray:
    return (
        idle_uj
        + cpu_base * cpu_mul[cpu_bins]
        + mem_base * mem_mul[mem_bins]
        + disk_base * disk_mul[disk_bins]
        + net_base * net_mul[net_bins]
    )


def metric_bundle(y_true: np.ndarray, y_pred: np.ndarray) -> dict[str, float]:
    rmse = float(np.sqrt(mean_squared_error(y_true, y_pred)))
    mae = float(mean_absolute_error(y_true, y_pred))
    r2 = float(r2_score(y_true, y_pred))
    mask = np.abs(y_true) > 1e-9
    mape = float(np.mean(np.abs((y_true[mask] - y_pred[mask]) / y_true[mask])) * 100.0) if np.any(mask) else float("nan")
    return {"r2": r2, "rmse": rmse, "mae": mae, "mape_pct": mape}


def print_metrics(label: str, metrics: dict[str, float]) -> None:
    print(f"\n# --- {label} ---")
    print(f"R2     : {metrics['r2']:.5f}")
    print(f"RMSE   : {metrics['rmse']:.3f} uJ")
    print(f"MAE    : {metrics['mae']:.3f} uJ")
    print(f"MAPE   : {metrics['mape_pct']:.3f} %" if np.isfinite(metrics["mape_pct"]) else "MAPE   : n/a")


def main(args) -> None:
    global TARGET_COL

    for path in args.logfiles:
        if not path.exists():
            raise FileNotFoundError(path)

    TARGET_COL = args.target

    df = gather_rows(args.logfiles, args.mode, args.min_target_uj)
    if df.empty or len(df) < 40:
        raise RuntimeError("Not enough usable rows (need >= 40 after filtering)")

    train_df, test_df = split_random(df, args.test_frac, args.random_seed)
    train_df, test_df = trim_by_quantile(train_df, test_df, args.trim_upper_quantile)
    if train_df.empty or test_df.empty:
        raise RuntimeError("Train/test split produced an empty set")

    X_train_lin = train_df[FEATURE_COLS].to_numpy(dtype=np.float64)
    y_train = train_df["target_uj"].to_numpy(dtype=np.float64)
    X_test_lin = test_df[FEATURE_COLS].to_numpy(dtype=np.float64)
    y_test = test_df["target_uj"].to_numpy(dtype=np.float64)

    stage1_idx = sorted(IDX["cpu"] + IDX["mem"])
    stage2_idx = sorted(IDX["disk"] + IDX["net"])
    w = fit_two_stage_nonnegative_ridge(X_train_lin, y_train, args.alpha, stage1_idx, stage2_idx)
    pred_lin_train = X_train_lin @ w
    pred_lin_test = X_test_lin @ w

    baseline_vec = np.array([BASELINE_WEIGHTS[k] for k in FEATURE_COLS], dtype=np.float64)
    pred_baseline_test = X_test_lin @ baseline_vec

    X_train_nl = np.column_stack([
        X_train_lin,
        train_df["cpu_util_permille"].to_numpy(dtype=np.float64),
        train_df["mem_activity"].to_numpy(dtype=np.float64),
        train_df["disk_activity"].to_numpy(dtype=np.float64),
        train_df["net_activity"].to_numpy(dtype=np.float64),
    ])
    X_test_nl = np.column_stack([
        X_test_lin,
        test_df["cpu_util_permille"].to_numpy(dtype=np.float64),
        test_df["mem_activity"].to_numpy(dtype=np.float64),
        test_df["disk_activity"].to_numpy(dtype=np.float64),
        test_df["net_activity"].to_numpy(dtype=np.float64),
    ])

    nl_model = HistGradientBoostingRegressor(
        loss="squared_error",
        learning_rate=0.05,
        max_iter=600,
        max_depth=6,
        min_samples_leaf=20,
        l2_regularization=1.0,
        random_state=args.random_seed,
    )
    nl_model.fit(X_train_nl, y_train)
    pred_nl_train = np.clip(nl_model.predict(X_train_nl), a_min=0.0, a_max=None)
    pred_nl_test = np.clip(nl_model.predict(X_test_nl), a_min=0.0, a_max=None)

    cpu_base_train = _group_base(X_train_lin, w, IDX["cpu"])
    mem_base_train = _group_base(X_train_lin, w, IDX["mem"])
    disk_base_train = _group_base(X_train_lin, w, IDX["disk"])
    net_base_train = _group_base(X_train_lin, w, IDX["net"])

    cpu_base_test = _group_base(X_test_lin, w, IDX["cpu"])
    mem_base_test = _group_base(X_test_lin, w, IDX["mem"])
    disk_base_test = _group_base(X_test_lin, w, IDX["disk"])
    net_base_test = _group_base(X_test_lin, w, IDX["net"])

    cpu_bins_train = train_df["cpu_bin"].to_numpy(dtype=int)
    mem_bins_train = train_df["mem_bin"].to_numpy(dtype=int)
    disk_bins_train = train_df["disk_bin"].to_numpy(dtype=int)
    net_bins_train = train_df["net_bin"].to_numpy(dtype=int)

    cpu_bins_test = test_df["cpu_bin"].to_numpy(dtype=int)
    mem_bins_test = test_df["mem_bin"].to_numpy(dtype=int)
    disk_bins_test = test_df["disk_bin"].to_numpy(dtype=int)
    net_bins_test = test_df["net_bin"].to_numpy(dtype=int)

    idle_uj, cpu_mul, mem_mul, disk_mul, net_mul = fit_piecewise_distill_multigroup(
        cpu_base=cpu_base_train,
        mem_base=mem_base_train,
        disk_base=disk_base_train,
        net_base=net_base_train,
        cpu_bins=cpu_bins_train,
        mem_bins=mem_bins_train,
        disk_bins=disk_bins_train,
        net_bins=net_bins_train,
        target=pred_nl_train,
    )

    cpu_mul = fill_sparse_bins(cpu_mul, cpu_bins_train)
    mem_mul = fill_sparse_bins(mem_mul, mem_bins_train)
    disk_mul = fill_sparse_bins(disk_mul, disk_bins_train)
    net_mul = fill_sparse_bins(net_mul, net_bins_train)

    pred_distill_train = piecewise_predict(
        idle_uj, cpu_base_train, mem_base_train, disk_base_train, net_base_train,
        cpu_bins_train, mem_bins_train, disk_bins_train, net_bins_train,
        cpu_mul, mem_mul, disk_mul, net_mul,
    )
    pred_distill_test = piecewise_predict(
        idle_uj, cpu_base_test, mem_base_test, disk_base_test, net_base_test,
        cpu_bins_test, mem_bins_test, disk_bins_test, net_bins_test,
        cpu_mul, mem_mul, disk_mul, net_mul,
    )

    print(f"# mode={args.mode} alpha={args.alpha}")
    print(f"# rows_total={len(df)} rows_train={len(train_df)} rows_test={len(test_df)}")

    print_metrics("test metrics (current module defaults)", metric_bundle(y_test, pred_baseline_test))
    print_metrics("test metrics (linear non-negative ridge)", metric_bundle(y_test, pred_lin_test))
    print_metrics("test metrics (nonlinear reference)", metric_bundle(y_test, pred_nl_test))
    print_metrics("test metrics (distilled kernel model)", metric_bundle(y_test, pred_distill_test))
    print_metrics("train metrics (distilled kernel model)", metric_bundle(y_train, pred_distill_train))

    int_weights: dict[str, int] = {}
    print("\n# --- fitted linear weights (float) ---")
    for spec, value in zip(FEATURES, w):
        print(f"{spec.param_name:20s} = {value:.6f}")
        int_weights[spec.param_name] = max(0, int(np.rint(value)))

    w_sys_idle_uj = max(0, int(np.rint(idle_uj)))
    nl_cpu_lut_pmil = np.clip(np.rint(cpu_mul * 1000.0), 0, 1000000).astype(int)
    nl_mem_lut_pmil = np.clip(np.rint(mem_mul * 1000.0), 0, 1000000).astype(int)
    nl_disk_lut_pmil = np.clip(np.rint(disk_mul * 1000.0), 0, 1000000).astype(int)
    nl_net_lut_pmil = np.clip(np.rint(net_mul * 1000.0), 0, 1000000).astype(int)

    print("\n# --- distilled nonlinear params ---")
    print(f"w_sys_idle_uj         = {w_sys_idle_uj}")
    print("nl_cpu_lut_pmil       = " + ",".join(str(v) for v in nl_cpu_lut_pmil.tolist()))
    print("nl_mem_lut_pmil       = " + ",".join(str(v) for v in nl_mem_lut_pmil.tolist()))
    print("nl_disk_lut_pmil      = " + ",".join(str(v) for v in nl_disk_lut_pmil.tolist()))
    print("nl_net_lut_pmil       = " + ",".join(str(v) for v in nl_net_lut_pmil.tolist()))

    print("\n# --- module params (rounded ints) ---")
    for spec in FEATURES:
        print(f"{spec.param_name:20s} = {int_weights[spec.param_name]}")

    params = " ".join(f"{k}={v}" for k, v in int_weights.items())
    cpu_lut = ",".join(str(v) for v in nl_cpu_lut_pmil.tolist())
    mem_lut = ",".join(str(v) for v in nl_mem_lut_pmil.tolist())
    disk_lut = ",".join(str(v) for v in nl_disk_lut_pmil.tolist())
    net_lut = ",".join(str(v) for v in nl_net_lut_pmil.tolist())

    print("\n# reload example")
    print(
        "sudo insmod energy_proc.ko "
        f"{params} w_sys_idle_uj={w_sys_idle_uj} "
        f"nl_cpu_lut_pmil={cpu_lut} "
        f"nl_mem_lut_pmil={mem_lut} "
        f"nl_disk_lut_pmil={disk_lut} "
        f"nl_net_lut_pmil={net_lut}"
    )

    print("\n# runtime update example")
    for key, value in int_weights.items():
        print(f"echo {value} | sudo tee /sys/module/energy_proc/parameters/{key}")
    print(f"echo {w_sys_idle_uj} | sudo tee /sys/module/energy_proc/parameters/w_sys_idle_uj")
    print(f"echo {cpu_lut} | sudo tee /sys/module/energy_proc/parameters/nl_cpu_lut_pmil")
    print(f"echo {mem_lut} | sudo tee /sys/module/energy_proc/parameters/nl_mem_lut_pmil")
    print(f"echo {disk_lut} | sudo tee /sys/module/energy_proc/parameters/nl_disk_lut_pmil")
    print(f"echo {net_lut} | sudo tee /sys/module/energy_proc/parameters/nl_net_lut_pmil")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Train nonlinear PSYS model and distill to kernel-friendly linear+multi-LUT params."
    )
    parser.add_argument("logfiles", nargs="+", type=Path)
    parser.add_argument("--mode", choices=("delta",), default="delta")
    parser.add_argument("--alpha", type=float, default=10.0, help="L2 strength for non-negative linear fit")
    parser.add_argument("--test-frac", type=float, default=0.2)
    parser.add_argument("--min-target-uj", type=float, default=1.0)
    parser.add_argument("--trim-upper-quantile", type=float, default=0.999)
    parser.add_argument("--random-seed", type=int, default=42)
    parser.add_argument("--target", type=str, choices=["rapl_psys_sum_uj", "rapl_core_sum_uj"], default="rapl_psys_sum_uj")

    args = parser.parse_args()

    main(args)

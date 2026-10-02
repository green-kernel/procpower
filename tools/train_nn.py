#!/usr/bin/env python3
"""
Train a feed-forward neural network (MLP) on energy-logger data.

Uses the same log format, parsing, diffing and feature sets as the
linear-regression script, so both can be run on the same files and compared.

Example:
    ./train_nn.py train.log --predict test.log --features all \
        --target psu_energy_ac_mcp_machine --plot-loss
"""
import re
import argparse
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import TensorDataset, DataLoader

from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LinearRegression
from sklearn.metrics import r2_score, mean_absolute_error, mean_absolute_percentage_error
import plotext as plt

TARGET_COL = None  # Will be set by argparse


# --------------------------------------------------------------------------
# Data loading (same format as the linear-regression script)
# --------------------------------------------------------------------------

def parse_monitor_file(path: str | Path):
    """Parse logfile into a DataFrame of relevant metrics."""
    rows = []

    pid0_re = re.compile(
        r"pid=0.*?"
        r"cpu_ns=(\d+)\s+mem=(\d+)\s+instructions=(\d+)\s+wakeups=(\d+)\s+"
        r"diski=(\d+)\s+disko=(\d+)\s+rx=(\d+)\s+tx=(\d+)"
    )
    target_col_re = re.compile(rf"{TARGET_COL}=(\d+)")
    timestamp_re = re.compile(r"timestamp=(\d+)")
    sample_re = re.compile(r"sample_ns=(\d+)")

    with open(path, encoding="utf-8") as f:
        blocks = [b.strip() for b in f.read().split("-------") if b.strip()]

    for block in blocks:
        target = target_col_re.search(block)
        pid0 = pid0_re.search(block)
        timestamp = timestamp_re.search(block)
        sample_ns = sample_re.search(block)

        if target and pid0 and timestamp and sample_ns:
            rows.append({
                TARGET_COL: int(target.group(1)),
                "timestamp": int(timestamp.group(1)),
                "sample_ns": int(sample_ns.group(1)),
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


def select_features(df, features):
    """Add derived features and return (df, feature_list)."""
    # instructions per cpu-ns; guard against division by zero on idle samples
    df["ips"] = (df["instructions"] / df["cpu_ns"].replace(0, np.nan)).fillna(0.0)

    if features == "normal":
        feature_list = ["instructions", "wakeups", "mem"]
    elif features == "extra":
        feature_list = ["instructions", "ips", "wakeups", "rx", "tx"]
    elif features == "all":
        feature_list = ["cpu_ns", "mem", "instructions", "wakeups", "diski", "disko", "rx", "tx"]
    elif features == "idle":
        feature_list = ["wakeups"]
    elif features == "compute":
        feature_list = ["instructions"]
    else:
        raise ValueError(f"Unknown feature set: {features}")

    return df, feature_list


def load_and_prepare(path, features):
    """Parse, diff cumulative counters, and add features. Same steps for train and predict."""
    df = parse_monitor_file(path)
    if len(df) < 2:
        raise ValueError(f"Not enough samples parsed from {path} (got {len(df)}).")

    df_original = df.copy()
    df = df.diff()
    df["timestamp"] = df_original["timestamp"]
    df["sample_ns"] = df_original["sample_ns"]
    df = df.drop(index=0).reset_index(drop=True)

    df, feature_list = select_features(df, features)
    return df, feature_list


def to_arrays(df, feature_list, use_log):
    """Extract X and y as float arrays, optionally log-transformed."""
    X = df[feature_list].to_numpy(dtype=np.float64)
    y = df[TARGET_COL].to_numpy(dtype=np.float64)

    if use_log:
        if (X < 0).any() or (y < 0).any():
            raise ValueError("Negative diffs found (counter reset?). --log requires non-negative values.")
        X = np.log1p(X)
        y = np.log1p(y)

    if not np.isfinite(X).all() or not np.isfinite(y).all():
        raise ValueError("NaN/inf values found in features or target!")

    return X, y


# --------------------------------------------------------------------------
# Model
# --------------------------------------------------------------------------

class MLP(nn.Module):
    """Plain feed-forward network: [Linear -> ReLU -> Dropout] x N -> Linear(1)."""

    def __init__(self, n_inputs, hidden_sizes, dropout):
        super().__init__()
        layers = []
        prev = n_inputs
        for h in hidden_sizes:
            layers += [nn.Linear(prev, h), nn.ReLU(), nn.Dropout(dropout)]
            prev = h
        layers.append(nn.Linear(prev, 1))  # single regression output
        self.net = nn.Sequential(*layers)

    def forward(self, x):
        return self.net(x).squeeze(-1)


def train_model(model, X_tr, y_tr, X_val, y_val, args, device):
    """Mini-batch training with Adam, LR scheduling and early stopping on validation loss."""
    train_ds = TensorDataset(torch.tensor(X_tr, dtype=torch.float32),
                             torch.tensor(y_tr, dtype=torch.float32))
    # Shuffling batches is fine; the train/val split itself is time-based.
    train_loader = DataLoader(train_ds, batch_size=args.batch_size, shuffle=True)

    X_val_t = torch.tensor(X_val, dtype=torch.float32, device=device)
    y_val_t = torch.tensor(y_val, dtype=torch.float32, device=device)

    loss_fn = nn.HuberLoss() if args.loss == "huber" else nn.MSELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr, weight_decay=args.weight_decay)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, factor=0.5, patience=max(1, args.patience // 3)
    )

    best_val = float("inf")
    best_state = None
    epochs_without_improvement = 0
    history = {"train": [], "val": []}

    for epoch in range(1, args.epochs + 1):
        # ---- training pass ----
        model.train()
        total = 0.0
        for xb, yb in train_loader:
            xb, yb = xb.to(device), yb.to(device)
            optimizer.zero_grad()
            loss = loss_fn(model(xb), yb)   # forward pass
            loss.backward()                 # backpropagation
            optimizer.step()                # weight update
            total += loss.item() * len(xb)
        train_loss = total / len(train_ds)

        # ---- validation pass ----
        model.eval()
        with torch.no_grad():
            val_loss = loss_fn(model(X_val_t), y_val_t).item()
        scheduler.step(val_loss)

        history["train"].append(train_loss)
        history["val"].append(val_loss)

        if val_loss < best_val - 1e-7:
            best_val = val_loss
            best_state = {k: v.detach().clone() for k, v in model.state_dict().items()}
            epochs_without_improvement = 0
        else:
            epochs_without_improvement += 1

        if epoch == 1 or epoch % args.print_every == 0:
            lr = optimizer.param_groups[0]["lr"]
            print(f"epoch {epoch:4d}  train_loss {train_loss:.5f}  val_loss {val_loss:.5f}  lr {lr:.1e}")

        if epochs_without_improvement >= args.patience:
            print(f"Early stopping at epoch {epoch} (best val_loss {best_val:.5f})")
            break

    model.load_state_dict(best_state)
    return history


def predict(model, X_scaled, y_scaler, use_log, device):
    """Run the model and map predictions back to the original target units."""
    model.eval()
    with torch.no_grad():
        p = model(torch.tensor(X_scaled, dtype=torch.float32, device=device)).cpu().numpy()
    p = y_scaler.inverse_transform(p.reshape(-1, 1)).ravel()
    if use_log:
        p = np.expm1(p)
    return p


# --------------------------------------------------------------------------
# Metrics
# --------------------------------------------------------------------------

def wape(y_true, y_pred):
    y_true, y_pred = np.asarray(y_true), np.asarray(y_pred)
    return np.sum(np.abs(y_true - y_pred)) / np.sum(np.abs(y_true))


def smape(y_true, y_pred, eps=1e-8):
    y_true, y_pred = np.asarray(y_true), np.asarray(y_pred)
    denom = np.maximum(np.abs(y_true) + np.abs(y_pred), eps)
    return np.mean(2 * np.abs(y_pred - y_true) / denom)


def print_metrics(title, y_true, y_pred):
    print(f"\n== {title} ==")
    print("MAE:      ", mean_absolute_error(y_true, y_pred))
    print("MAPE (%): ", 100 * mean_absolute_percentage_error(y_true, y_pred))
    print("WAPE (%): ", 100 * wape(y_true, y_pred))
    print("sMAPE (%):", 100 * smape(y_true, y_pred))
    print("R²:       ", r2_score(y_true, y_pred))


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def pick_device(name):
    if name != "auto":
        return torch.device(name)
    if torch.cuda.is_available():
        return torch.device("cuda")
    if torch.backends.mps.is_available():
        return torch.device("mps")
    return torch.device("cpu")


def main(args):
    global TARGET_COL
    TARGET_COL = args.target

    torch.manual_seed(args.seed)
    np.random.seed(args.seed)
    device = pick_device(args.device)

    df, FEATURES = load_and_prepare(args.logfile, args.features)

    if args.dump_diff:
        print(df)

    if args.plot_only:
        plt.clear_data()
        plt.plot(df["timestamp"].tolist(), df[TARGET_COL].tolist(), marker="dot")
        plt.xlabel("Time")
        plt.ylabel(TARGET_COL)
        plt.show()
        return

    # ---- time-based train/validation split (no random shuffling across time) ----
    n_val = int(len(df) * args.val_frac)
    n_train = len(df) - n_val
    if n_val < 1 or n_train < 10:
        raise ValueError(f"Too few samples for a split: {n_train} train / {n_val} val.")
    df_train = df.iloc[:n_train].reset_index(drop=True)
    df_val = df.iloc[n_train:].reset_index(drop=True)
    print(f"Samples: {n_train} train / {n_val} validation  |  features: {FEATURES}  |  device: {device}")

    X_tr, y_tr = to_arrays(df_train, FEATURES, args.log)
    X_val, y_val = to_arrays(df_val, FEATURES, args.log)

    # Scalers are fit on training data only, then reused everywhere.
    # Scaling y matters for NNs: raw energy values are huge and would make training unstable.
    x_scaler = StandardScaler().fit(X_tr)
    y_scaler = StandardScaler().fit(y_tr.reshape(-1, 1))

    X_tr_s, X_val_s = x_scaler.transform(X_tr), x_scaler.transform(X_val)
    y_tr_s = y_scaler.transform(y_tr.reshape(-1, 1)).ravel()
    y_val_s = y_scaler.transform(y_val.reshape(-1, 1)).ravel()

    # ---- build and train the network ----
    model = MLP(len(FEATURES), args.hidden, args.dropout).to(device)
    n_params = sum(p.numel() for p in model.parameters())
    print(f"Model: {model}\nTrainable parameters: {n_params}\n")

    history = train_model(model, X_tr_s, y_tr_s, X_val_s, y_val_s, args, device)

    val_pred = predict(model, X_val_s, y_scaler, args.log, device)
    print_metrics("MLP on validation split", df_val[TARGET_COL], val_pred)

    # ---- linear baseline on exactly the same data, for comparison ----
    baseline = None
    if not args.no_baseline:
        baseline = LinearRegression().fit(X_tr_s, y_tr_s)
        base_pred = y_scaler.inverse_transform(baseline.predict(X_val_s).reshape(-1, 1)).ravel()
        if args.log:
            base_pred = np.expm1(base_pred)
        print_metrics("Linear baseline on validation split", df_val[TARGET_COL], base_pred)

    if args.plot_loss:
        plt.clear_data()
        plt.plot(history["train"], label="train")
        plt.plot(history["val"], label="val")
        plt.xlabel("Epoch")
        plt.ylabel("Loss (scaled)")
        plt.title("Training curve")
        plt.show()

    # ---- predict on a separate logfile ----
    if args.predict:
        df2, _ = load_and_prepare(args.predict, args.features)
        X2, _ = to_arrays(df2, FEATURES, args.log)
        X2_s = x_scaler.transform(X2)
        y2_true = df2[TARGET_COL]  # always in original units

        predictions = predict(model, X2_s, y_scaler, args.log, device)
        print_metrics(f"MLP on {args.predict}", y2_true, predictions)

        if baseline is not None:
            base2 = y_scaler.inverse_transform(baseline.predict(X2_s).reshape(-1, 1)).ravel()
            if args.log:
                base2 = np.expm1(base2)
            print_metrics(f"Linear baseline on {args.predict}", y2_true, base2)

        if args.dump_predictions:
            out = df2[FEATURES].copy()
            out.insert(0, f"{TARGET_COL}_pred", predictions)
            out.insert(0, TARGET_COL, y2_true)
            print(out)

        if args.dump_top_errors:
            errors = (y2_true - predictions).abs()
            top = df2.loc[errors.nlargest(10).index].copy()
            top.insert(1, "prediction", predictions[top.index])
            print(top)

    if args.save:
        torch.save({
            "state_dict": model.state_dict(),
            "features": FEATURES,
            "target": TARGET_COL,
            "hidden": args.hidden,
            "dropout": args.dropout,
            "log": args.log,
            "x_mean": x_scaler.mean_, "x_scale": x_scaler.scale_,
            "y_mean": y_scaler.mean_, "y_scale": y_scaler.scale_,
        }, args.save)
        print(f"\nModel saved to {args.save}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train an MLP on energy-logger data")
    parser.add_argument("logfile", help="Logfile of energy-logger to use for training")
    parser.add_argument("--predict", help="Logfile to parse for prediction")
    parser.add_argument("--features", choices=["normal", "extra", "compute", "idle", "all"],
                        default="all", help="Feature set to use")
    parser.add_argument("--target", type=str,
                        choices=["rapl_psys_sum_uj", "rapl_core_sum_uj", "psu_energy_ac_mcp_machine"],
                        default="psu_energy_ac_mcp_machine")
    parser.add_argument("--log", action="store_true", help="Apply log1p transform to features and target")

    # network / training hyperparameters
    parser.add_argument("--hidden", type=int, nargs="+", default=[64, 64],
                        help="Hidden layer sizes, e.g. --hidden 128 64 32")
    parser.add_argument("--dropout", type=float, default=0.1)
    parser.add_argument("--epochs", type=int, default=500)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--lr", type=float, default=1e-3, help="Learning rate")
    parser.add_argument("--weight-decay", type=float, default=1e-5, help="L2 regularization")
    parser.add_argument("--loss", choices=["mse", "huber"], default="huber")
    parser.add_argument("--patience", type=int, default=30, help="Early-stopping patience in epochs")
    parser.add_argument("--val-frac", type=float, default=0.2,
                        help="Fraction of the (time-ordered) training log held out for validation")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--device", default="auto", help="auto, cpu, cuda or mps")
    parser.add_argument("--print-every", type=int, default=10)

    # output options
    parser.add_argument("--no-baseline", action="store_true", help="Skip the linear regression comparison")
    parser.add_argument("--plot-loss", action="store_true", help="Plot the training curve in the terminal")
    parser.add_argument("--plot-only", action="store_true", help="Plot the training data file and exit")
    parser.add_argument("--dump-diff", action="store_true", help="Dump parsed and diffed data")
    parser.add_argument("--dump-predictions", action="store_true", help="Dump predictions")
    parser.add_argument("--dump-top-errors", action="store_true", help="Dump top errors")
    parser.add_argument("--save", help="Path to save the trained model (e.g. model.pt)")

    main(parser.parse_args())

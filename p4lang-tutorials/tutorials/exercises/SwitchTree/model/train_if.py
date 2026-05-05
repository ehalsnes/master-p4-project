#!/usr/bin/env python3
"""
Train an Isolation Forest on UNSW-NB15 CSV data and evaluate it using the
same features and metrics as train_rf.py so the two models can be compared
side-by-side.

Usage:
    python3 train_if.py --data UNSW_NB15_training-set.csv [options]

Isolation Forest is an unsupervised anomaly detector: it assigns an anomaly
score to each sample without using labels during training.  Two training modes
are supported (--train-normal-only / default full-dataset mode):

  Full dataset  — IF trained on the full training split; contamination is
                  estimated from the actual attack fraction in that split.
  Normal-only   — IF trained only on benign samples (classic semi-supervised
                  anomaly detection); contamination is applied at predict time.

Predictions are mapped to binary labels (attack=1, normal=0) for a direct
comparison with the RF classifier output.

Feature mapping from UNSW-NB15 columns to P4 metadata fields:
  sttl        → meta.sttl        (IP source TTL, integer 0-255)
  ct_state_ttl→ meta.ct_state_ttl (flow context TTL feature, integer)
  rate        → meta.rate        (pkt_count proxy on switch)
  dload       → meta.dload       (byte_count proxy on switch; threshold ×1000)
  sinpkt      → meta.sinpkt      (inter-packet time ms; idle_μs>>10 on switch)
  smean       → meta.smean       (mean src packet size, EMA on switch)
"""

import argparse
import json
import os
import sys

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (classification_report, confusion_matrix,
                             roc_auc_score, roc_curve,
                             accuracy_score, precision_score, recall_score, f1_score)
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split

# ── Features and label ────────────────────────────────────────────────────────
FEATURES = ['sttl', 'ct_state_ttl', 'rate', 'dload', 'sinpkt', 'smean']

COL_ALIASES = {
    'sttl':         ['sttl'],
    'ct_state_ttl': ['ct_state_ttl'],
    'rate':         ['rate', 'Rate'],
    'dload':        ['Dload', 'dload'],
    'sinpkt':       ['Sintpkt', 'sinpkt', 'sint_pkt'],
    'smean':        ['smeansz', 'smean', 'Smeansz'],
    'label':        ['Label', 'label', 'attack', 'Attack'],
    'attack_cat':   ['attack_cat', 'Attack_cat', 'attack_category'],
}


def resolve_columns(df):
    rename = {}
    for canonical, aliases in COL_ALIASES.items():
        for alias in aliases:
            if alias in df.columns:
                rename[alias] = canonical
                break
        else:
            if canonical in FEATURES:
                sys.exit(
                    f"ERROR: could not find column for feature '{canonical}'.\n"
                    f"  Expected one of: {aliases}\n"
                    f"  Found columns:   {list(df.columns[:20])}"
                )
    return df.rename(columns=rename)


def load_dataset(paths):
    frames = []
    for p in paths:
        print(f'  Loading {p} …', end=' ', flush=True)
        df = pd.read_csv(p, low_memory=False)
        frames.append(df)
        print(f'{len(df):,} rows')
    df = pd.concat(frames, ignore_index=True)
    df = resolve_columns(df)

    if 'rate' not in df.columns:
        for alias in ['Spkts', 'spkts']:
            if alias in df.columns:
                df['rate'] = df[alias]
                print(f"  Note: 'rate' derived from '{alias}'")
                break
        else:
            sys.exit("ERROR: could not find 'rate' or 'Spkts' column.")

    if 'attack_cat' not in df.columns:
        sys.exit("ERROR: could not find 'attack_cat' column.")
    df['attack_cat'] = df['attack_cat'].astype(str).str.strip()
    df = df[df['attack_cat'].isin(['Normal', 'DoS'])]
    df['label'] = (df['attack_cat'] == 'DoS').astype(int)
    df = df[FEATURES + ['label']].dropna()

    for f in FEATURES:
        df[f] = df[f].clip(lower=0, upper=2**32 - 1)

    print(f'  Dataset: {len(df):,} rows after cleaning  '
          f'(normal={int((df.label==0).sum()):,}  '
          f'attack={int((df.label==1).sum()):,})')
    return df


# ── Main ─────────────────────────────────────────────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))

def parse_args():
    ap = argparse.ArgumentParser(
        description='Train Isolation Forest on UNSW-NB15 and save metrics/charts')
    ap.add_argument('--data', nargs='+', required=True,
                    help='One or more UNSW-NB15 CSV files (training set)')
    ap.add_argument('--out', default=os.path.join(_HERE, 'if_metrics.json'),
                    help='Output metrics JSON path (default: model/if_metrics.json)')
    ap.add_argument('--n-trees', type=int, default=100,
                    help='Number of trees / estimators (default: 100)')
    ap.add_argument('--max-samples', default='auto',
                    help='Samples per tree: int, float, or "auto" (default: auto)')
    ap.add_argument('--contamination', type=float, default=None,
                    help='Expected fraction of anomalies (default: auto-estimated '
                         'from training label ratio)')
    ap.add_argument('--train-normal-only', action='store_true',
                    help='Train IF only on normal (label=0) samples, i.e. classic '
                         'semi-supervised anomaly detection mode')
    ap.add_argument('--test-split', type=float, default=0.2,
                    help='Fraction of data held out for evaluation (default: 0.2)')
    ap.add_argument('--seed', type=int, default=42)
    return ap.parse_args()


def main():
    args = parse_args()

    out = os.path.abspath(args.out)
    os.makedirs(os.path.dirname(out), exist_ok=True)

    # Parse --max-samples: keep as int/float when numeric, else pass the string
    max_samples = args.max_samples
    try:
        max_samples = int(max_samples)
    except ValueError:
        try:
            max_samples = float(max_samples)
        except ValueError:
            pass  # keep as string, e.g. "auto"

    print('[1/4] Loading dataset …')
    df = load_dataset(args.data)

    X = df[FEATURES].values.astype(np.float32)
    y = df['label'].values.astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_split, random_state=args.seed, stratify=y)
    print(f'  Train: {len(X_train):,}  Test: {len(X_test):,}')

    # Estimate contamination from training label distribution unless overridden
    contamination = args.contamination
    if contamination is None:
        contamination = min(float((y_train == 1).sum()) / len(y_train), 0.5)
        print(f'  Contamination auto-estimated from training set: {contamination:.4f}')
    else:
        print(f'  Contamination (user-specified): {contamination:.4f}')

    if args.train_normal_only:
        X_fit = X_train[y_train == 0]
        print(f'  Training on normal samples only: {len(X_fit):,} rows')
        mode_label = 'normal-only'
    else:
        X_fit = X_train
        print(f'  Training on full training split: {len(X_fit):,} rows')
        mode_label = 'full-dataset'

    print(f'[2/4] Training IsolationForest '
          f'(n_estimators={args.n_trees}, max_samples={max_samples}, '
          f'contamination={contamination:.4f}, mode={mode_label}) …')
    iforest = IsolationForest(
        n_estimators=args.n_trees,
        max_samples=max_samples,
        contamination=contamination,
        n_jobs=-1,
        random_state=args.seed,
    )
    iforest.fit(X_fit)

    print('[3/4] Evaluating …')
    # sklearn IF: predict returns 1 (inlier/normal) and -1 (outlier/attack)
    # Map to binary labels: 1→0 (normal), -1→1 (attack)
    raw_pred = iforest.predict(X_test)
    y_pred = np.where(raw_pred == -1, 1, 0)

    # score_samples returns the opposite of anomaly score (higher = more normal)
    # Negate so that higher score → more anomalous → higher probability of attack
    anomaly_scores = -iforest.score_samples(X_test)

    print(classification_report(y_test, y_pred,
                                target_names=['normal', 'attack']))
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    print('Confusion matrix (rows=actual, cols=predicted):')
    print('             normal  attack')
    print(f'  normal     {tn:6d}  {fp:6d}')
    print(f'  attack     {fn:6d}  {tp:6d}')
    auc = roc_auc_score(y_test, anomaly_scores)
    print(f'ROC-AUC: {auc:.4f}')

    metrics = {
        'model':       'IsolationForest',
        'mode':        mode_label,
        'n_estimators': args.n_trees,
        'contamination': contamination,
        'Accuracy':    accuracy_score(y_test, y_pred),
        'Precision':   precision_score(y_test, y_pred, zero_division=0),
        'Recall':      recall_score(y_test, y_pred, zero_division=0),
        'F1-score':    f1_score(y_test, y_pred, zero_division=0),
        'ROC-AUC':     auc,
    }

    plot_metrics = {k: v for k, v in metrics.items()
                    if k in ('Accuracy', 'Precision', 'Recall', 'F1-score', 'ROC-AUC')}

    charts_dir = os.path.join(os.path.dirname(out), 'figures')
    os.makedirs(charts_dir, exist_ok=True)

    # Confusion matrix
    fig, ax = plt.subplots(figsize=(5, 4))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Oranges', ax=ax,
                xticklabels=['normal', 'attack'],
                yticklabels=['normal', 'attack'])
    ax.set_xlabel('Predicted')
    ax.set_ylabel('Actual')
    ax.set_title(f'Confusion Matrix — IF {mode_label}')
    fig.tight_layout()
    fig.savefig(os.path.join(charts_dir, 'if_confusion_matrix.png'), dpi=150)
    plt.close(fig)

    # ROC curve
    fpr, tpr, _ = roc_curve(y_test, anomaly_scores)
    fig, ax = plt.subplots(figsize=(5, 4))
    ax.plot(fpr, tpr, color='darkorange', label=f'AUC = {auc:.4f}')
    ax.plot([0, 1], [0, 1], 'k--')
    ax.set_xlabel('False Positive Rate')
    ax.set_ylabel('True Positive Rate')
    ax.set_title(f'ROC Curve — IF {mode_label}')
    ax.legend()
    fig.tight_layout()
    fig.savefig(os.path.join(charts_dir, 'if_roc_curve.png'), dpi=150)
    plt.close(fig)

    # Classification metrics bar chart
    fig, ax = plt.subplots(figsize=(6, 4))
    bars = ax.bar(plot_metrics.keys(), plot_metrics.values(),
                  color='darkorange', edgecolor='white')
    ax.set_ylim(0, 1.05)
    ax.set_ylabel('Score')
    ax.set_title(f'Classification Metrics — IF {mode_label}')
    for bar, val in zip(bars, plot_metrics.values()):
        ax.text(bar.get_x() + bar.get_width() / 2, val + 0.01,
                f'{val:.4f}', ha='center', va='bottom', fontsize=9)
    fig.tight_layout()
    fig.savefig(os.path.join(charts_dir, 'if_metrics.png'), dpi=150)
    plt.close(fig)

    print(f'  Charts saved → {charts_dir}/')

    print(f'[4/4] Saving metrics to {out} …')
    with open(out, 'w') as f:
        json.dump(metrics, f, indent=2)
    print(f'  Metrics saved → {out}')
    print('[*] Done.')


if __name__ == '__main__':
    main()

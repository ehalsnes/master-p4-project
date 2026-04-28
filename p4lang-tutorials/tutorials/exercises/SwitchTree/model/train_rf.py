#!/usr/bin/env python3
"""
Train a Random Forest on UNSW-NB15 CSV data and export it to rf_model.json
so that populate_tables.py can install the trees onto a BMv2 P4 switch.

Usage:
    python3 train_rf.py --data UNSW_NB15_training-set.csv [options]

The output JSON is consumed directly by controller/populate_tables.py.

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
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

# ── Features and label ────────────────────────────────────────────────────────
# These must match the match-field names in rf_ddos_detect.p4 tree tables.
FEATURES = ['sttl', 'ct_state_ttl', 'rate', 'dload', 'sinpkt', 'smean']

# UNSW-NB15 uses different capitalisation across releases — map all variants.
COL_ALIASES = {
    'sttl':         ['sttl'],
    'ct_state_ttl': ['ct_state_ttl'],
    'rate':         ['rate', 'Rate'],
    'dload':        ['Dload', 'dload'],
    'sinpkt':       ['Sintpkt', 'sinpkt', 'sint_pkt'],
    'smean':        ['smeansz', 'smean', 'Smeansz'],
    'label':        ['Label', 'label', 'attack', 'Attack'],
}


def resolve_columns(df):
    """Rename dataset columns to canonical FEATURES + 'label' names."""
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

    # 'rate' may need to be derived when it is absent as a raw column
    if 'rate' not in df.columns:
        # Fallback: use Spkts (source packet count) as a proxy for rate,
        # matching how the P4 program approximates it via pkt_count_reg.
        for alias in ['Spkts', 'spkts']:
            if alias in df.columns:
                df['rate'] = df[alias]
                print(f"  Note: 'rate' derived from '{alias}'")
                break
        else:
            sys.exit("ERROR: could not find 'rate' or 'Spkts' column.")

    df = df[FEATURES + ['label']].dropna()
    df = df[df['label'].isin([0, 1])]   # keep binary label only

    # Clip extreme values to the bit<32> range used in P4 (0 … 4 294 967 295)
    for f in FEATURES:
        df[f] = df[f].clip(lower=0, upper=2**32 - 1)

    print(f'  Dataset: {len(df):,} rows after cleaning  '
          f'(normal={int((df.label==0).sum()):,}  '
          f'attack={int((df.label==1).sum()):,})')
    return df


# ── sklearn tree → rf_model.json node list ───────────────────────────────────
def export_tree(sk_tree, tree_id, feature_names):
    """
    Walk a sklearn DecisionTreeClassifier internal structure and produce
    the list-of-node dicts consumed by populate_tables.py.

    threshold_int = int(threshold * 1000) for all features.
    populate_tables.py applies an additional ×1000 only for 'dload'
    (because the P4 dload proxy is byte_count, not bytes/sec).
    """
    t = sk_tree.tree_
    nodes = []

    def _walk(node_id):
        if t.feature[node_id] < 0:          # leaf
            cls = int(np.argmax(t.value[node_id][0]))
            nodes.append({'id': node_id, 'is_leaf': True, 'class': cls})
        else:
            feat_idx = int(t.feature[node_id])
            feat     = feature_names[feat_idx]
            thr      = float(t.threshold[node_id])
            nodes.append({
                'id':           node_id,
                'is_leaf':      False,
                'feature':      feat,
                'feature_idx':  feat_idx,
                'threshold':    thr,
                'threshold_int': int(thr * 1000),
                'left_child':   int(t.children_left[node_id]),
                'right_child':  int(t.children_right[node_id]),
            })
            _walk(int(t.children_left[node_id]))
            _walk(int(t.children_right[node_id]))

    _walk(0)
    return {
        'tree_id': tree_id,
        'n_nodes': len(nodes),
        'nodes':   nodes,
    }


def export_model(rf, feature_names, classes):
    return {
        'model_type':    type(rf).__name__,
        'n_trees':       len(rf.estimators_),
        'n_features':    len(feature_names),
        'feature_names': list(feature_names),
        'classes':       [int(c) for c in classes],
        'trees': [
            export_tree(est, i, feature_names)
            for i, est in enumerate(rf.estimators_)
        ],
    }


# ── Main ─────────────────────────────────────────────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))

def parse_args():
    ap = argparse.ArgumentParser(
        description='Train RF on UNSW-NB15 and export rf_model.json')
    ap.add_argument('--data', nargs='+', required=True,
                    help='One or more UNSW-NB15 CSV files (training set)')
    ap.add_argument('--out', default=os.path.join(_HERE, 'rf_model.json'),
                    help='Output JSON path (default: model/rf_model.json next to this script)')
    ap.add_argument('--n-trees', type=int, default=100,
                    help='Number of trees (default: 100)')
    ap.add_argument('--max-depth', type=int, default=None,
                    help='Max tree depth (default: unlimited)')
    ap.add_argument('--test-split', type=float, default=0.2,
                    help='Fraction of data held out for evaluation (default: 0.2)')
    ap.add_argument('--seed', type=int, default=42)
    return ap.parse_args()


def main():
    args = parse_args()

    # Resolve output path to absolute so it works regardless of CWD or __pycache__
    out = os.path.abspath(args.out)
    os.makedirs(os.path.dirname(out), exist_ok=True)

    print('[1/4] Loading dataset …')
    df = load_dataset(args.data)

    X = df[FEATURES].values.astype(np.float32)
    y = df['label'].values.astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_split, random_state=args.seed, stratify=y)
    print(f'  Train: {len(X_train):,}  Test: {len(X_test):,}')

    print(f'[2/4] Training RandomForest '
          f'(n_estimators={args.n_trees}, max_depth={args.max_depth}) …')
    rf = RandomForestClassifier(
        n_estimators=args.n_trees,
        max_depth=args.max_depth,
        n_jobs=-1,
        random_state=args.seed,
    )
    rf.fit(X_train, y_train)

    print('[3/4] Evaluating …')
    y_pred = rf.predict(X_test)
    print(classification_report(y_test, y_pred,
                                target_names=['normal', 'attack']))

    print(f'[4/4] Exporting model to {out} …')
    model_dict = export_model(rf, FEATURES, rf.classes_)
    with open(out, 'w') as f:
        json.dump(model_dict, f, indent=2)
    total_nodes = sum(t['n_nodes'] for t in model_dict['trees'])
    print(f'  {args.n_trees} trees, {total_nodes:,} nodes total → {out}')
    print('[*] Done.  Next step: python3 controller/populate_tables.py '
          f'--rf-model {out} ...')


if __name__ == '__main__':
    main()

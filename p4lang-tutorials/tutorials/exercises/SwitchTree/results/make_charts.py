#!/usr/bin/env python3
"""Generate experiment charts from experiment_results.json.

Produces four PNG figures in results/figures/:
  1. throughput_comparison.png  — bar chart across all phases
  2. throughput_variance.png    — mean ± std dev with individual trial dots
  3. rtt_comparison.png         — avg RTT with min/max error bars
  4. drop_rate.png              — estimated attack drop % per phase
"""

import json
import os
import re

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

RESULTS_DIR  = os.path.dirname(__file__)
RESULTS_FILE = os.path.join(RESULTS_DIR, 'experiment_results.json')
FIGURES_DIR  = os.path.join(RESULTS_DIR, 'figures')

try:
    with open(RESULTS_FILE) as f:
        R = json.load(f)
except FileNotFoundError:
    R = {}

os.makedirs(FIGURES_DIR, exist_ok=True)

BLUE   = '#1e50a0'
RED    = '#c0392b'
GREEN  = '#27ae60'
GREY   = '#7f8c8d'
ORANGE = '#e67e22'

SPINE_OFF = {'top': False, 'right': False}


def _save(name):
    path = os.path.join(FIGURES_DIR, name)
    plt.savefig(path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f'  Saved: {path}')


def _parse_rtt(s):
    """Return (min, avg, max, mdev) floats from an RTT summary string."""
    m = re.search(r'([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)', s or '')
    return tuple(float(x) for x in m.groups()) if m else None


# ── Chart 1: Throughput comparison (mean per phase) ──────────────────────────
def chart_throughput():
    order = [
        ('control_5mbps_legit_mbps', '5 Mbps\n(no detect)', RED),
        ('baseline_mbps',             'Baseline\n(no attack)', GREEN),
        ('attack_2mbps_legit_mbps',   '2 Mbps\n(detect on)', BLUE),
        ('attack_5mbps_legit_mbps',   '5 Mbps\n(detect on)', BLUE),
        ('attack_10mbps_legit_mbps',  '10 Mbps\n(detect on)', BLUE),
        ('recovery_mbps',             'Recovery\n(no attack)', GREEN),
    ]

    labels, values, colors = [], [], []
    for key, label, color in order:
        if key in R and R[key] is not None:
            labels.append(label)
            values.append(R[key])
            colors.append(color)

    if not values:
        print('  No throughput data — skipping chart_throughput.')
        return

    fig, ax = plt.subplots(figsize=(10, 5))
    bars = ax.bar(labels, values, color=colors, width=0.55,
                  edgecolor='white', linewidth=1.2)

    baseline = R.get('baseline_mbps')
    if baseline:
        ax.axhline(baseline, color=GREEN, linestyle='--', linewidth=1.4,
                   alpha=0.7, label=f'Baseline ({baseline} Mbps)')

    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2,
                bar.get_height() + max(values) * 0.02,
                f'{val:.1f}', ha='center', va='bottom',
                fontsize=9, fontweight='bold')

    ax.set_ylabel('Legitimate Throughput h1→h3 (Mbps)', fontsize=11)
    ax.set_title('Legitimate Throughput Under DoS Attack\n'
                 'P4 In-Network RF Detection (BMv2)', fontsize=13, fontweight='bold')
    ax.set_ylim(0, max(values) * 1.3)
    ax.grid(axis='y', alpha=0.3)
    for sp, v in SPINE_OFF.items():
        ax.spines[sp].set_visible(v)

    patches = [
        mpatches.Patch(color=GREEN, label='No attack'),
        mpatches.Patch(color=BLUE,  label='Detection active'),
        mpatches.Patch(color=RED,   label='No detection (control)'),
    ]
    ax.legend(handles=patches, fontsize=9, loc='upper right')
    plt.tight_layout()
    _save('throughput_comparison.png')


# ── Chart 2: Mean ± std dev with individual trial dots ───────────────────────
def chart_variance():
    order = [
        ('control_5mbps_trials',  '5 Mbps\n(no detect)', RED),
        ('baseline_trials',        'Baseline',            GREEN),
        ('attack_2mbps_trials',    '2 Mbps\n(detect)',   BLUE),
        ('attack_5mbps_trials',    '5 Mbps\n(detect)',   BLUE),
        ('attack_10mbps_trials',   '10 Mbps\n(detect)',  BLUE),
        ('recovery_trials',        'Recovery',            GREEN),
    ]

    present = [(lbl, col, R[k]) for k, lbl, col in order
               if k in R and R[k]]
    if not present:
        print('  No trial data — skipping chart_variance.')
        return

    fig, ax = plt.subplots(figsize=(10, 5))
    for x, (lbl, col, trials) in enumerate(present):
        mean = sum(trials) / len(trials)
        std  = (sum((t - mean) ** 2 for t in trials) / len(trials)) ** 0.5
        ax.bar(x, mean, color=col, width=0.55, alpha=0.85,
               edgecolor='white', linewidth=1.2)
        ax.errorbar(x, mean, yerr=std, fmt='none',
                    color='black', capsize=6, linewidth=2, zorder=4)
        for i, t in enumerate(trials):
            jitter = (i - (len(trials) - 1) / 2) * 0.09
            ax.plot(x + jitter, t, 'o', color='white', markersize=6,
                    markeredgecolor='black', markeredgewidth=1, zorder=5)

    ax.set_xticks(range(len(present)))
    ax.set_xticklabels([p[0] for p in present], fontsize=9)
    ax.set_ylabel('Legitimate Throughput h1→h3 (Mbps)', fontsize=11)
    ax.set_title('Throughput per Phase — Mean ± Std Dev (3 trials)\n'
                 'Dots = individual runs', fontsize=13, fontweight='bold')
    ax.grid(axis='y', alpha=0.3)
    for sp, v in SPINE_OFF.items():
        ax.spines[sp].set_visible(v)

    patches = [
        mpatches.Patch(color=GREEN, label='No attack'),
        mpatches.Patch(color=BLUE,  label='Detection active'),
        mpatches.Patch(color=RED,   label='No detection (control)'),
    ]
    ax.legend(handles=patches, fontsize=9, loc='upper right')
    plt.tight_layout()
    _save('throughput_variance.png')


# ── Chart 3: RTT comparison ───────────────────────────────────────────────────
def chart_rtt():
    order = [
        ('baseline_rtt',       'Baseline',          GREEN),
        ('control_5mbps_rtt',  '5 Mbps\n(no det.)', RED),
        ('attack_2mbps_rtt',   '2 Mbps\n(detect)',  BLUE),
        ('attack_5mbps_rtt',   '5 Mbps\n(detect)',  BLUE),
        ('attack_10mbps_rtt',  '10 Mbps\n(detect)', BLUE),
    ]

    present = []
    for key, lbl, col in order:
        parsed = _parse_rtt(R.get(key, ''))
        if parsed:
            present.append((lbl, col, parsed))

    if not present:
        print('  No RTT data — skipping chart_rtt.')
        return

    x    = np.arange(len(present))
    avgs = np.array([p[2][1] for p in present])
    mins = np.array([p[2][0] for p in present])
    maxs = np.array([p[2][2] for p in present])

    fig, ax = plt.subplots(figsize=(9, 4))
    ax.bar(x, avgs, color=[p[1] for p in present], width=0.5,
           alpha=0.85, edgecolor='white', linewidth=1.2)
    ax.errorbar(x, avgs, yerr=[avgs - mins, maxs - avgs],
                fmt='none', color='black', capsize=5, linewidth=1.5)

    for xi, avg in zip(x, avgs):
        ax.text(xi, avg + (maxs.max() - mins.min()) * 0.05,
                f'{avg:.2f}', ha='center', va='bottom', fontsize=9)

    ax.set_xticks(x)
    ax.set_xticklabels([p[0] for p in present], fontsize=9)
    ax.set_ylabel('RTT h1→h3 (ms)', fontsize=11)
    ax.set_title('Ping Latency Under Attack Conditions\n'
                 'Bars = avg, whiskers = min/max', fontsize=13, fontweight='bold')
    ax.grid(axis='y', alpha=0.3)
    for sp, v in SPINE_OFF.items():
        ax.spines[sp].set_visible(v)

    patches = [
        mpatches.Patch(color=GREEN, label='No attack'),
        mpatches.Patch(color=BLUE,  label='Detection active'),
        mpatches.Patch(color=RED,   label='No detection (control)'),
    ]
    ax.legend(handles=patches, fontsize=9, loc='upper right')
    plt.tight_layout()
    _save('rtt_comparison.png')


# ── Chart 4: Estimated attack drop rate ──────────────────────────────────────
def chart_drop_rate():
    order = [
        ('control_5mbps',  '5 Mbps\n(no detect)', RED),
        ('attack_2mbps',   '2 Mbps\n(detect)',    BLUE),
        ('attack_5mbps',   '5 Mbps\n(detect)',    BLUE),
        ('attack_10mbps',  '10 Mbps\n(detect)',   BLUE),
    ]

    # Build drop_pct for each phase.  Control has no drop; attack phases
    # may have drop_pct computed by the topology script, or we derive it
    # from raw packet counters if available.
    present = []
    for prefix, lbl, col in order:
        drop_key = f'{prefix}_drop_pct'
        tx_key   = f'{prefix}_h2_tx_pkts'
        rx_key   = f'{prefix}_h3_rx_pkts'
        if drop_key in R:
            present.append((lbl, col, R[drop_key]))
        elif tx_key in R and rx_key in R and R[tx_key] > 0:
            pct = round(100 * max(0.0, 1 - R[rx_key] / R[tx_key]), 1)
            present.append((lbl, col, pct))

    if not present:
        print('  No drop-rate data — skipping chart_drop_rate.')
        return

    labels = [p[0] for p in present]
    values = [p[2] for p in present]
    colors = [p[1] for p in present]

    fig, ax = plt.subplots(figsize=(8, 4))
    bars = ax.bar(labels, values, color=colors, width=0.5,
                  edgecolor='white', linewidth=1.2)

    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 1.5,
                f'{val:.1f}%', ha='center', va='bottom',
                fontsize=10, fontweight='bold')

    ax.set_ylim(0, 115)
    ax.axhline(100, color=GREY, linestyle='--', linewidth=1, alpha=0.5)
    ax.set_ylabel('Attack Packets Dropped (%)', fontsize=11)
    ax.set_title('RF Classifier — Estimated Attack Drop Rate\n'
                 '(conservative: h3 RX includes h1 iperf traffic)',
                 fontsize=13, fontweight='bold')
    ax.grid(axis='y', alpha=0.3)
    for sp, v in SPINE_OFF.items():
        ax.spines[sp].set_visible(v)

    patches = [
        mpatches.Patch(color=BLUE, label='Detection active'),
        mpatches.Patch(color=RED,  label='No detection (control)'),
    ]
    ax.legend(handles=patches, fontsize=9, loc='upper right')
    plt.tight_layout()
    _save('drop_rate.png')


# ── Latency text file parser ──────────────────────────────────────────────────

def _parse_latency_file(path):
    """Return dict of {metric: float ms} parsed from a latency summary text file."""
    patterns = {
        'min': r'Min\s*:\s*([\d.]+)\s*ms',
        'avg': r'Avg\s*:\s*([\d.]+)\s*ms',
        'std': r'Std dev\s*:\s*([\d.]+)\s*ms',
        'p50': r'Median.*?:\s*([\d.]+)\s*ms',
        'p95': r'p95\s*:\s*([\d.]+)\s*ms',
        'p99': r'p99\s*:\s*([\d.]+)\s*ms',
        'max': r'Max\s*:\s*([\d.]+)\s*ms',
    }
    result = {}
    try:
        with open(path) as f:
            text = f.read()
        for key, pat in patterns.items():
            m = re.search(pat, text)
            if m:
                result[key] = float(m.group(1))
    except FileNotFoundError:
        pass
    return result


# ── Chart 5: Pipeline latency baseline vs RF ─────────────────────────────────

def chart_latency_comparison():
    base = _parse_latency_file(os.path.join(RESULTS_DIR, 'latency_baseline.txt'))
    rf   = _parse_latency_file(os.path.join(RESULTS_DIR, 'latency_rf.txt'))

    if not base and not rf:
        print('  No latency files found — skipping chart_latency_comparison.')
        return

    metrics    = [('avg', 'Avg'), ('p50', 'p50'), ('p95', 'p95'), ('p99', 'p99'), ('max', 'Max')]
    labels     = [m[1] for m in metrics]
    base_vals  = [base.get(m[0], 0.0) for m in metrics]
    rf_vals    = [rf.get(m[0],   0.0) for m in metrics]
    y_ceiling  = max(max(base_vals), max(rf_vals))

    x     = np.arange(len(metrics))
    width = 0.35

    fig, ax = plt.subplots(figsize=(9, 5))
    bars_base = ax.bar(x - width / 2, base_vals, width,
                       label='Baseline', color=BLUE, alpha=0.85, edgecolor='white')
    bars_rf   = ax.bar(x + width / 2, rf_vals,   width,
                       label='RF model', color=RED,  alpha=0.85, edgecolor='white')

    nudge = y_ceiling * 0.015
    for bar, val in zip(bars_base, base_vals):
        if val:
            ax.text(bar.get_x() + bar.get_width() / 2, val + nudge,
                    f'{val:.1f}', ha='center', va='bottom', fontsize=8, color=BLUE)
    for bar, val in zip(bars_rf, rf_vals):
        if val:
            ax.text(bar.get_x() + bar.get_width() / 2, val + nudge,
                    f'{val:.1f}', ha='center', va='bottom', fontsize=8, color=RED)

    # Annotate overhead/saving per metric
    for i, (mk, _) in enumerate(metrics):
        bv, rv = base.get(mk, 0.0), rf.get(mk, 0.0)
        if bv and rv:
            delta_pct = (rv - bv) / bv * 100
            sign      = '+' if delta_pct > 0 else ''
            ax.text(i, y_ceiling * 1.08,
                    f'{sign}{delta_pct:.0f}%',
                    ha='center', va='bottom', fontsize=7.5,
                    color=RED if delta_pct > 0 else GREEN)

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=10)
    ax.set_ylabel('Latency (ms)', fontsize=11)
    ax.set_ylim(0, y_ceiling * 1.25)
    ax.set_title('P4 Pipeline Latency — Baseline vs RF Model\n'
                 'PCAP-measured, ingress → egress (BMv2)',
                 fontsize=13, fontweight='bold')
    ax.legend(fontsize=10)
    ax.grid(axis='y', alpha=0.3)
    for sp, v in SPINE_OFF.items():
        ax.spines[sp].set_visible(v)

    # Summary stats as a text box
    if base and rf:
        std_b = base.get('std', float('nan'))
        std_r = rf.get('std', float('nan'))
        summary = (f"Baseline  avg {base.get('avg',0):.1f} ms  std {std_b:.1f} ms\n"
                   f"RF model  avg {rf.get('avg',0):.1f} ms  std {std_r:.1f} ms")
        ax.text(0.02, 0.97, summary, transform=ax.transAxes,
                fontsize=8, va='top', ha='left',
                bbox=dict(boxstyle='round,pad=0.4', fc='white', alpha=0.7))

    plt.tight_layout()
    _save('latency_comparison.png')


# ── Chart 6: Classification metrics baseline vs RF ───────────────────────────

def _load_classification_stats(json_path, counter_txt_path):
    """Load stats dict from JSON if present and valid, else compute from counter txt."""
    import json as _json
    if os.path.exists(json_path):
        try:
            with open(json_path) as f:
                return _json.load(f)
        except _json.JSONDecodeError:
            pass
    if os.path.exists(counter_txt_path):
        import sys
        sys.path.insert(0, os.path.dirname(RESULTS_DIR))
        try:
            from parse_results import parse_counters, compute_stats
            with open(counter_txt_path) as f:
                return compute_stats(parse_counters(f.read()))
        except ImportError:
            pass
    return None


def chart_classification_comparison():
    parent = os.path.dirname(RESULTS_DIR)
    rf_stats   = _load_classification_stats(
        os.path.join(RESULTS_DIR, 'rf_stats.json'),
        os.path.join(parent, 'counter_output.txt'),
    )
    base_stats = _load_classification_stats(
        os.path.join(RESULTS_DIR, 'baseline_stats.json'),
        os.path.join(parent, 'counter_output_baseline.txt'),
    )

    if rf_stats is None or base_stats is None:
        print('  Missing counter data — skipping chart_classification_comparison.')
        return

    metrics = [
        ('accuracy',  'Accuracy'),
        ('recall',    'Recall'),
        ('precision', 'Precision'),
        ('f1',        'F1 score'),
        ('fpr',       'FPR'),
    ]
    labels = [m[1] for m in metrics]
    base_v = [(base_stats.get(m[0]) or 0) * 100 for m in metrics]
    rf_v   = [(rf_stats.get(m[0])   or 0) * 100 for m in metrics]

    x     = np.arange(len(metrics))
    width = 0.35

    fig, ax = plt.subplots(figsize=(9, 5))
    bars_base = ax.bar(x - width / 2, base_v, width,
                       label='Baseline (IP-based)', color=BLUE, alpha=0.85, edgecolor='white')
    bars_rf   = ax.bar(x + width / 2, rf_v,   width,
                       label='RF model',            color=RED,  alpha=0.85, edgecolor='white')

    nudge = 1.2
    for bar, val in zip(bars_base, base_v):
        if val:
            ax.text(bar.get_x() + bar.get_width() / 2, val + nudge,
                    f'{val:.1f}%', ha='center', va='bottom', fontsize=8,
                    color=BLUE, fontweight='bold')
    for bar, val in zip(bars_rf, rf_v):
        if val:
            ax.text(bar.get_x() + bar.get_width() / 2, val + nudge,
                    f'{val:.1f}%', ha='center', va='bottom', fontsize=8,
                    color=RED, fontweight='bold')

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=10)
    ax.set_ylim(0, 120)
    ax.set_ylabel('Score (%)', fontsize=11)
    ax.set_title(
        'Detection Metrics — Baseline (IP-based) vs RF In-Network\n'
        f"flows: {base_stats['flows']}  |  malware: {base_stats['malware_flows']}  "
        f"|  normal: {base_stats['normal_flows']}",
        fontsize=12, fontweight='bold',
    )
    ax.legend(fontsize=10, loc='upper right')
    ax.grid(axis='y', alpha=0.3)
    ax.annotate('↓ lower is better', xy=(4, 0), xytext=(3.62, 6),
                fontsize=7.5, color=GREY, style='italic')
    for sp, v in SPINE_OFF.items():
        ax.spines[sp].set_visible(v)

    cm_lines = []
    for label, s in [('Baseline', base_stats), ('RF model', rf_stats)]:
        cm_lines.append(
            f"{label}:  TP={s['TP']}  FP={s['FP']}  FN={s['FN']}  TN={s['TN']}"
        )
    ax.text(0.02, 0.97, '\n'.join(cm_lines), transform=ax.transAxes,
            fontsize=8, va='top', ha='left',
            bbox=dict(boxstyle='round,pad=0.4', fc='white', alpha=0.8))

    plt.tight_layout()
    _save('classification_comparison.png')


if __name__ == '__main__':
    print(f'Loading results from {RESULTS_FILE}')
    chart_throughput()
    chart_variance()
    chart_rtt()
    chart_drop_rate()
    chart_latency_comparison()
    chart_classification_comparison()
    print(f'\nAll charts written to {FIGURES_DIR}/')

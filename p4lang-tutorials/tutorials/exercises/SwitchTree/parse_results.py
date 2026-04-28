#!/usr/bin/env python3
"""Parse SwitchTree counter output and print classification statistics.

Usage:
    simple_switch_CLI < get_results.txt | python3 parse_results.py
    python3 parse_results.py counter_output.txt
    python3 parse_results.py --plot counter_output.txt

Counter output format produced by simple_switch_CLI:
    RuntimeCmd: counter_pkts[0]= BmCounterValue(packets=1000, bytes=65000)

Or the older text format:
    counter_pkts[0]= packets: 1000 bytes: 65000
"""

import re
import sys
import json


# ── Parser ─────────────────────────────────────────────────────────────────────

COUNTER_NAMES = [
    "counter_pkts",
    "counter_hash_collisions",
    "counter_malware",
    "counter_timeout",
    "counter_flows",
    "counter_malware_flows",
    "counter_true_detection_flows",
    "counter_false_detection_flows",
    "counter_false_detection",
]

def parse_counters(text: str) -> dict[str, int]:
    counters = {}
    for name in COUNTER_NAMES:
        # BmCounterValue format: counter_foo[0]= BmCounterValue(packets=123, ...)
        m = re.search(rf"{name}\[0\]=\s*BmCounterValue\(packets=(\d+)", text)
        if not m:
            # Older text format: counter_foo[0]= packets: 123
            m = re.search(rf"{name}\[0\]=\s*packets:\s*(\d+)", text)
        counters[name] = int(m.group(1)) if m else 0
    return counters


# ── Statistics ─────────────────────────────────────────────────────────────────

def compute_stats(c: dict[str, int]) -> dict:
    pkts            = c["counter_pkts"]
    collisions      = c["counter_hash_collisions"]
    malware_pkts    = c["counter_malware"]
    timeouts        = c["counter_timeout"]
    flows           = c["counter_flows"]
    malware_flows   = c["counter_malware_flows"]
    tp              = c["counter_true_detection_flows"]
    fp              = c["counter_false_detection_flows"]
    fp_pkts         = c["counter_false_detection"]

    fn = max(0, malware_flows - tp)
    tn = max(0, (flows - malware_flows) - fp)
    normal_flows = flows - malware_flows

    recall    = tp / malware_flows          if malware_flows > 0  else None
    precision = tp / (tp + fp)             if (tp + fp) > 0      else None
    f1        = (2 * precision * recall / (precision + recall)
                 if precision is not None and recall is not None
                    and (precision + recall) > 0
                 else None)
    fpr       = fp / normal_flows          if normal_flows > 0   else None
    col_rate  = collisions / pkts          if pkts > 0           else None

    return {
        "pkts":           pkts,
        "collisions":     collisions,
        "collision_rate": col_rate,
        "malware_pkts":   malware_pkts,
        "timeouts":       timeouts,
        "flows":          flows,
        "malware_flows":  malware_flows,
        "normal_flows":   normal_flows,
        "TP":             tp,
        "FP":             fp,
        "FN":             fn,
        "TN":             tn,
        "fp_pkts":        fp_pkts,
        "recall":         recall,
        "precision":      precision,
        "f1":             f1,
        "fpr":            fpr,
    }


# ── Pretty printer ─────────────────────────────────────────────────────────────

def _pct(v) -> str:
    return f"{v*100:.1f}%" if v is not None else "N/A"

def _n(v) -> str:
    return "N/A" if v is None else str(v)

def print_stats(s: dict):
    print()
    print("=" * 50)
    print("  SwitchTree — Detection Statistics")
    print("=" * 50)
    print(f"  Total packets processed : {s['pkts']:>10,}")
    print(f"  Hash collisions         : {s['collisions']:>10,}  ({_pct(s['collision_rate'])})")
    print(f"  Flow timeouts           : {s['timeouts']:>10,}")
    print()
    print(f"  Total flows             : {s['flows']:>10,}")
    print(f"    Malware flows (GT)    : {s['malware_flows']:>10,}")
    print(f"    Normal flows          : {s['normal_flows']:>10,}")
    print()
    print("  Confusion matrix (flows):")
    print(f"    True  Positives (TP)  : {s['TP']:>10,}")
    print(f"    False Positives (FP)  : {s['FP']:>10,}")
    print(f"    False Negatives (FN)  : {s['FN']:>10,}")
    print(f"    True  Negatives (TN)  : {s['TN']:>10,}")
    print()
    print("  Classification metrics:")
    print(f"    Recall (detection)    : {_pct(s['recall'])}")
    print(f"    Precision             : {_pct(s['precision'])}")
    print(f"    F1 score              : {_pct(s['f1'])}")
    print(f"    False positive rate   : {_pct(s['fpr'])}")
    print("=" * 50)
    print()


# ── Optional chart ─────────────────────────────────────────────────────────────

def plot_stats(s: dict, out_path: str = "switchtree_metrics.png"):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not available — skipping plot.")
        return

    metrics = {
        "Recall\n(detection)": s["recall"],
        "Precision": s["precision"],
        "F1 score": s["f1"],
        "False\nPositive Rate": s["fpr"],
    }
    labels = list(metrics.keys())
    values = [v if v is not None else 0.0 for v in metrics.values()]
    colors = ["#27ae60", "#1e50a0", "#8e44ad", "#c0392b"]

    fig, ax = plt.subplots(figsize=(7, 4))
    bars = ax.bar(labels, [v * 100 for v in values], color=colors,
                  width=0.5, edgecolor="white", linewidth=1.2)

    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 1.5,
                f"{val*100:.1f}%", ha="center", va="bottom",
                fontsize=10, fontweight="bold")

    ax.set_ylim(0, 115)
    ax.set_ylabel("Score (%)", fontsize=11)
    ax.set_title("SwitchTree — RF In-Network Detection Metrics\n"
                 f"(flows: {s['flows']}, malware: {s['malware_flows']})",
                 fontsize=12, fontweight="bold")
    ax.grid(axis="y", alpha=0.3)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"Chart saved: {out_path}")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    args = sys.argv[1:]
    do_plot = "--plot" in args
    args = [a for a in args if a != "--plot"]

    if args:
        with open(args[0]) as f:
            text = f.read()
    else:
        text = sys.stdin.read()

    counters = parse_counters(text)
    stats = compute_stats(counters)
    print_stats(stats)

    if do_plot:
        plot_stats(stats)

    # Optionally dump JSON for downstream use
    if "--json" in sys.argv:
        print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()

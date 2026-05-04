#!/usr/bin/env python3
"""Compare P4 register latency stats: Baseline vs RF model.

Produces results/figures/register_latency_comparison.png
"""

import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

FIGURES_DIR = os.path.join(os.path.dirname(__file__), 'figures')
os.makedirs(FIGURES_DIR, exist_ok=True)

# ── Raw register values (update these after each experiment run) ──────────────

BASELINE = dict(
    deq_count=1025, deq_sum=207381,  deq_min=7,   deq_max=7830,
    ing_count=1026, ing_sum=20002452, ing_min=155,  ing_max=84746,
)

RF = dict(
    deq_count=2028, deq_sum=425562,  deq_min=7,   deq_max=7830,
    ing_count=2029, ing_sum=41657349, ing_min=155,  ing_max=97526,
)

# ── Derived averages ──────────────────────────────────────────────────────────

def avg(d, prefix):
    return d[f'{prefix}_sum'] / d[f'{prefix}_count']

BLUE  = '#1e50a0'
RED   = '#c0392b'
GREEN = '#27ae60'

def make_chart():
    metrics = [
        ('deq', 'Queue delay\n(deq_timedelta)'),
        ('ing', 'Pipeline latency\n(egress − ingress − queue)'),
    ]

    fig, axes = plt.subplots(1, 2, figsize=(11, 5))
    fig.suptitle('P4 Register Latency — Baseline vs RF Model\n(BMv2, units: nanoseconds)',
                 fontsize=13, fontweight='bold')

    for ax, (prefix, title) in zip(axes, metrics):
        b_avg = avg(BASELINE, prefix)
        r_avg = avg(RF,       prefix)
        b_min, b_max = BASELINE[f'{prefix}_min'], BASELINE[f'{prefix}_max']
        r_min, r_max = RF[f'{prefix}_min'],       RF[f'{prefix}_max']

        x      = np.array([0, 1])
        avgs   = np.array([b_avg, r_avg])
        yerr_lo = np.array([b_avg - b_min, r_avg - r_min])
        yerr_hi = np.array([b_max - b_avg, r_max - r_avg])

        bars = ax.bar(x, avgs, color=[BLUE, RED], width=0.45,
                      alpha=0.85, edgecolor='white', linewidth=1.2)
        ax.errorbar(x, avgs, yerr=[yerr_lo, yerr_hi],
                    fmt='none', color='black', capsize=8, linewidth=1.8, zorder=4)

        # Value labels on bars
        y_ceil = max(b_max, r_max)
        nudge  = y_ceil * 0.02
        for bar, val in zip(bars, avgs):
            ax.text(bar.get_x() + bar.get_width() / 2, val + nudge,
                    f'{val:,.0f}', ha='center', va='bottom', fontsize=9, fontweight='bold')

        # Percent overhead annotation (between the two bars)
        if b_avg:
            delta_pct = (r_avg - b_avg) / b_avg * 100
            sign = '+' if delta_pct >= 0 else ''
            color = RED if delta_pct > 0 else GREEN
            ax.annotate(f'{sign}{delta_pct:.1f}%',
                        xy=(0.5, max(b_avg, r_avg)),
                        xytext=(0.5, y_ceil * 1.15),
                        xycoords=('axes fraction', 'data'),
                        textcoords=('axes fraction', 'data'),
                        ha='center', va='bottom', fontsize=10, color=color, fontweight='bold',
                        arrowprops=dict(arrowstyle='->', color=color, lw=1.5))

        ax.set_xticks(x)
        ax.set_xticklabels(['Baseline', 'RF model'], fontsize=10)
        ax.set_ylabel('Latency (ns)', fontsize=10)
        ax.set_ylim(0, y_ceil * 1.35)
        ax.set_title(title, fontsize=11)
        ax.grid(axis='y', alpha=0.3)
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)

        # Min/max annotation box
        summary = (f"Baseline: avg {b_avg:,.0f}  min {b_min}  max {b_max:,}\n"
                   f"RF:       avg {r_avg:,.0f}  min {r_min}  max {r_max:,}")
        ax.text(0.02, 0.97, summary, transform=ax.transAxes,
                fontsize=7.5, va='top', ha='left', family='monospace',
                bbox=dict(boxstyle='round,pad=0.4', fc='white', alpha=0.7))

    plt.tight_layout()
    out = os.path.join(FIGURES_DIR, 'register_latency_comparison.png')
    plt.savefig(out, dpi=150, bbox_inches='tight')
    plt.close()
    print(f'Saved: {out}')


if __name__ == '__main__':
    make_chart()

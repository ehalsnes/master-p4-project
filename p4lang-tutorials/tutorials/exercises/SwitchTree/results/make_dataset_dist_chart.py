#!/usr/bin/env python3
"""Bar chart — UNSW-NB15 traffic category distribution.

Highlights Normal and DoS (the two classes used in the RF model).
Saves figures/dataset_distribution.png.
"""

import os
import csv
from collections import Counter

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

SCRIPT_DIR  = os.path.dirname(__file__)
DATASET_CSV = os.path.join(SCRIPT_DIR, '..', 'model', 'UNSW_NB15_training-set.csv')
FIGURES_DIR = os.path.join(SCRIPT_DIR, 'figures')

# ── Colours ────────────────────────────────────────────────────────────────────
C_NORMAL  = '#27ae60'   # green  — Normal traffic
C_DOS     = '#c0392b'   # red    — DoS (used in classifier)
C_OTHER   = '#95a5a6'   # grey   — other attack categories (not used)

# ── Load data ──────────────────────────────────────────────────────────────────
counts: Counter = Counter()
with open(DATASET_CSV, newline='', encoding='utf-8-sig') as f:
    for row in csv.DictReader(f):
        counts[row['attack_cat'].strip()] += 1

total = sum(counts.values())

# Sort descending by count
categories = sorted(counts.items(), key=lambda x: -x[1])
labels = [c for c, _ in categories]
values = [n for _, n in categories]
colors = [C_NORMAL if c == 'Normal' else C_DOS if c == 'DoS' else C_OTHER
          for c in labels]

# ── Plot ───────────────────────────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(11, 5))

bars = ax.bar(labels, values, color=colors, width=0.65,
              edgecolor='white', linewidth=1.2)

for bar, val in zip(bars, values):
    pct = val / total * 100
    ax.text(bar.get_x() + bar.get_width() / 2,
            bar.get_height() + total * 0.004,
            f'{val:,}\n({pct:.1f}%)',
            ha='center', va='bottom', fontsize=8, fontweight='bold')

ax.set_ylabel('Number of records', fontsize=11)
ax.set_title('UNSW-NB15 Training Set — Traffic Category Distribution\n'
             f'Total: {total:,} records',
             fontsize=13, fontweight='bold')
ax.set_ylim(0, max(values) * 1.20)
ax.tick_params(axis='x', labelsize=9)
ax.grid(axis='y', alpha=0.3)
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)

legend_patches = [
    mpatches.Patch(color=C_NORMAL, label='Normal (used in classifier)'),
    mpatches.Patch(color=C_DOS,    label='DoS / DDoS (used in classifier)'),
    mpatches.Patch(color=C_OTHER,  label='Other attack categories (excluded)'),
]
ax.legend(handles=legend_patches, fontsize=9, loc='upper right')

plt.tight_layout()
os.makedirs(FIGURES_DIR, exist_ok=True)
out = os.path.join(FIGURES_DIR, 'dataset_distribution.png')
plt.savefig(out, dpi=150, bbox_inches='tight')
plt.close()
print(f'Saved: {out}')

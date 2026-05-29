#!/usr/bin/env python3
"""Bar chart — Normal vs DoS class distribution after filtering UNSW-NB15.

Shows the two-class subset used to train the RF model and the resulting
class imbalance. Saves figures/class_imbalance_distribution.png.
"""

import os
import csv
from collections import Counter

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

SCRIPT_DIR  = os.path.dirname(__file__)
DATASET_CSV = os.path.join(SCRIPT_DIR, '..', 'model', 'UNSW_NB15_training-set.csv')
FIGURES_DIR = os.path.join(SCRIPT_DIR, 'figures')

C_NORMAL = '#27ae60'
C_DOS    = '#c0392b'

counts: Counter = Counter()
with open(DATASET_CSV, newline='', encoding='utf-8-sig') as f:
    for row in csv.DictReader(f):
        cat = row['attack_cat'].strip()
        if cat in ('Normal', 'DoS'):
            counts[cat] += 1

total   = sum(counts.values())
labels  = ['Normal', 'DoS']
values  = [counts['Normal'], counts['DoS']]
colors  = [C_NORMAL, C_DOS]
ratio   = counts['Normal'] / counts['DoS']

fig, ax = plt.subplots(figsize=(6, 5))

bars = ax.bar(labels, values, color=colors, width=0.45,
              edgecolor='white', linewidth=1.2)

for bar, val in zip(bars, values):
    pct = val / total * 100
    ax.text(bar.get_x() + bar.get_width() / 2,
            bar.get_height() + total * 0.008,
            f'{val:,}\n({pct:.1f}%)',
            ha='center', va='bottom', fontsize=11, fontweight='bold')

ax.set_ylabel('Number of records', fontsize=12)
ax.set_title(
    'UNSW-NB15 — Normal vs DoS After Class Filtering\n'
    f'Total: {total:,} records  |  Imbalance ratio ≈ {ratio:.1f}:1',
    fontsize=12, fontweight='bold',
)
ax.set_ylim(0, max(values) * 1.22)
ax.tick_params(axis='x', labelsize=12)
ax.grid(axis='y', alpha=0.3)
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)

plt.tight_layout()
os.makedirs(FIGURES_DIR, exist_ok=True)
out = os.path.join(FIGURES_DIR, 'class_imbalance_distribution.png')
plt.savefig(out, dpi=150, bbox_inches='tight')
plt.close()
print(f'Saved: {out}')

#!/usr/bin/env python3
"""Generate CPU utilization comparison charts from SAR output files.

Averages are computed only over the active experiment window (detected
automatically from the 'all' CPU row crossing a busy threshold), so idle
head/tail time before or after the experiment does not dilute the results.

Produces three PNG figures in results/figures/:
  1. cpu_hot_core.png      — hot-core %user / %system / %idle, baseline vs RF
  2. cpu_per_core.png      — all-core average utilization for both scenarios
  3. cpu_timeseries.png    — busy % over time on the hot core, both scenarios
"""

import os
import re
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

RESULTS_DIR    = os.path.dirname(__file__)
FIGURES_DIR    = os.path.join(RESULTS_DIR, 'figures')
ACTIVE_THRESH  = 5.0   # %busy on the 'all' row to consider experiment active
os.makedirs(FIGURES_DIR, exist_ok=True)

BLUE_DARK   = '#1e50a0'
BLUE_MID    = '#5b8fd4'
RED_DARK    = '#c0392b'
RED_MID     = '#e07b72'
GRAY        = '#aab0b5'


# ── Parser ─────────────────────────────────────────────────────────────────────

def parse_sar(path):
    """Return raw timeseries dict: {cpu_label: [(t_secs, user, system, idle)]}."""
    timeseries = {}
    with open(path) as f:
        for line in f:
            m = re.match(
                r'(\d+):(\d+):(\d+)\s+(\S+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)'
                r'\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)',
                line.strip()
            )
            if not m:
                continue
            h, mi, s = int(m.group(1)), int(m.group(2)), int(m.group(3))
            cpu   = m.group(4)
            user  = float(m.group(5))
            sys_  = float(m.group(7))
            idle  = float(m.group(10))
            t     = h * 3600 + mi * 60 + s
            timeseries.setdefault(cpu, []).append((t, user, sys_, idle))
    return timeseries


def detect_active_window(ts, threshold=ACTIVE_THRESH):
    """Return (t_start, t_end) of the active experiment using the 'all' row."""
    active = [(t, u + s) for t, u, s, i in ts.get('all', []) if u + s > threshold]
    if not active:
        all_ts = [t for t, *_ in ts.get('all', [])]
        return (all_ts[0], all_ts[-1]) if all_ts else (0, float('inf'))
    return active[0][0], active[-1][0]


def trim(ts, t_start, t_end):
    """Filter timeseries to [t_start, t_end]."""
    return {
        cpu: [(t, u, s, i) for t, u, s, i in series if t_start <= t <= t_end]
        for cpu, series in ts.items()
    }


def averages(ts):
    """Compute per-core (avg_user, avg_system, avg_idle) from a timeseries dict."""
    avgs = {}
    for cpu, series in ts.items():
        if not series:
            continue
        n = len(series)
        avgs[cpu] = (
            sum(u for _, u, s, i in series) / n,
            sum(s for _, u, s, i in series) / n,
            sum(i for _, u, s, i in series) / n,
        )
    return avgs


def hot_core(avgs):
    """Return the CPU label with the lowest average idle %."""
    numeric = {k: v for k, v in avgs.items() if k != 'all'}
    return min(numeric, key=lambda k: numeric[k][2])


def normalise_to_window(series, t_start):
    """Shift timestamps so t=0 is t_start."""
    return [(t - t_start, u, s, i) for t, u, s, i in series]


# ── Load and trim ──────────────────────────────────────────────────────────────

raw_base = parse_sar(os.path.join(RESULTS_DIR, 'cpu_utilization_baseline.txt'))
raw_rf   = parse_sar(os.path.join(RESULTS_DIR, 'cpu_utilization_rf.txt'))

base_start, base_end = detect_active_window(raw_base)
rf_start,   rf_end   = detect_active_window(raw_rf)

trimmed_base = trim(raw_base, base_start, base_end)
trimmed_rf   = trim(raw_rf,   rf_start,   rf_end)

avgs_base = averages(trimmed_base)
avgs_rf   = averages(trimmed_rf)

hc_base = hot_core(avgs_base)
hc_rf   = hot_core(avgs_rf)

print(f'Baseline active window: {base_end - base_start:.0f}s  (hot core: CPU {hc_base})')
print(f'RF       active window: {rf_end   - rf_start:.0f}s  (hot core: CPU {hc_rf})')


# ── Figure 1: Hot-core stacked bar ─────────────────────────────────────────────

fig, ax = plt.subplots(figsize=(6, 5))

scenarios  = [('Baseline', avgs_base, hc_base, BLUE_DARK, BLUE_MID),
              ('RF',       avgs_rf,   hc_rf,   RED_DARK,  RED_MID)]
x     = np.arange(len(scenarios))
width = 0.5

for i, (label, avgs, hc, c_user, c_sys) in enumerate(scenarios):
    u, s, idle = avgs[hc]
    busy = u + s
    ax.bar(x[i], u,    width,            color=c_user, alpha=0.95)
    ax.bar(x[i], s,    width, bottom=u,  color=c_sys,  alpha=0.85)
    ax.bar(x[i], idle, width, bottom=busy, color=GRAY, alpha=0.4)
    ax.text(x[i], busy + 1.5,
            f'{busy:.1f}%\nbusy',
            ha='center', va='bottom', fontsize=11, fontweight='bold',
            color=c_user)

ax.set_xticks(x)
ax.set_xticklabels([f'Baseline\n(CPU {hc_base})', f'RF\n(CPU {hc_rf})'])
ax.set_ylabel('CPU utilisation (%)')
ax.set_title('BMv2 hot-core utilisation during experiment\n(active window only)')
ax.set_ylim(0, 115)
ax.yaxis.grid(True, linestyle='--', alpha=0.5)
ax.set_axisbelow(True)

legend_handles = [
    plt.Rectangle((0,0),1,1, fc=BLUE_DARK, alpha=0.95, label='%user (baseline)'),
    plt.Rectangle((0,0),1,1, fc=BLUE_MID,  alpha=0.85, label='%system (baseline)'),
    plt.Rectangle((0,0),1,1, fc=RED_DARK,  alpha=0.95, label='%user (RF)'),
    plt.Rectangle((0,0),1,1, fc=RED_MID,   alpha=0.85, label='%system (RF)'),
    plt.Rectangle((0,0),1,1, fc=GRAY,      alpha=0.4,  label='%idle'),
]
ax.legend(handles=legend_handles, loc='upper right', fontsize=8)

plt.tight_layout()
out = os.path.join(FIGURES_DIR, 'cpu_hot_core.png')
plt.savefig(out, dpi=150)
plt.close()
print(f'Saved {out}')


# ── Figure 2: Per-core average utilisation ─────────────────────────────────────

numeric_cores = [hc_base, hc_rf] if hc_base != hc_rf else [hc_base]
numeric_cores = sorted(set(numeric_cores), key=int)
x     = np.arange(len(numeric_cores))
width = 0.35

fig, ax = plt.subplots(figsize=(10, 5))

base_busy = [sum(avgs_base.get(c, (0,0,0))[:2]) for c in numeric_cores]
rf_busy   = [sum(avgs_rf.get(c,   (0,0,0))[:2]) for c in numeric_cores]

ax.bar(x - width/2, base_busy, width, label='Baseline', color=BLUE_DARK, alpha=0.85)
ax.bar(x + width/2, rf_busy,   width, label='RF',       color=RED_DARK,  alpha=0.85)

ax.set_xlabel('CPU core')
ax.set_ylabel('Avg busy % (%user + %system, active window)')
ax.set_title('Per-core CPU utilisation during experiment\n(active window only)')
ax.set_xticks(x)
ax.set_xticklabels([f'CPU {c}' for c in numeric_cores])
ax.legend()
ax.yaxis.grid(True, linestyle='--', alpha=0.5)
ax.set_axisbelow(True)

plt.tight_layout()
out = os.path.join(FIGURES_DIR, 'cpu_per_core.png')
plt.savefig(out, dpi=150)
plt.close()
print(f'Saved {out}')


# ── Figure 3: Time series aligned to experiment start ──────────────────────────

fig, ax = plt.subplots(figsize=(10, 4))

for label, raw_ts, hc, t_start, color in [
    ('Baseline', raw_base, hc_base, base_start, BLUE_DARK),
    ('RF',       raw_rf,   hc_rf,   rf_start,   RED_DARK),
]:
    series = normalise_to_window(raw_ts.get(hc, []), t_start)
    if not series:
        continue
    times = [p[0] for p in series]
    busy  = [p[1] + p[2] for p in series]
    ax.plot(times, busy, color=color, linewidth=1.4, label=f'{label} (CPU {hc})')

ax.axhline(y=0,   color='black', linewidth=0.5)
ax.axvline(x=0,   color='gray',  linewidth=0.8, linestyle='--', label='Experiment start')
ax.set_xlabel('Time relative to experiment start (s)')
ax.set_ylabel('Busy % (%user + %system)')
ax.set_title('Hot-core CPU busy over time (aligned to experiment start)')
ax.set_ylim(-5, 110)
ax.yaxis.grid(True, linestyle='--', alpha=0.5)
ax.set_axisbelow(True)
ax.legend()

plt.tight_layout()
out = os.path.join(FIGURES_DIR, 'cpu_timeseries.png')
plt.savefig(out, dpi=150)
plt.close()
print(f'Saved {out}')

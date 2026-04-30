#!/usr/bin/env python3
"""
Measure per-packet P4 pipeline latency by matching ingress vs egress PCAP timestamps.

Packets are matched by IP 5-tuple (src_ip, dst_ip, src_port, dst_port, proto).
Within each flow, packets are paired in arrival order.

Usage:
    python3 latency.py
    python3 latency.py --ingress pcaps/s1-eth1_in.pcap --egress pcaps/s1-eth2_out.pcap pcaps/s1-eth3_out.pcap
    python3 latency.py --plot
"""

import sys
import os
import argparse
import statistics
from pathlib import Path

try:
    from scapy.all import rdpcap, IP, TCP, UDP
except ImportError:
    print("ERROR: scapy not found. Install with: pip3 install scapy")
    sys.exit(1)


def flow_key(pkt):
    """
    Key for matching packets across ingress/egress PCAPs.

    TCP: full 5-tuple — the P4 deparser emits hdr.tcp so ports are preserved.
    UDP: IP-pair + proto only — the P4 deparser does NOT emit hdr.udp, so the
         egress PCAP has no UDP header. Dropping ports on both sides normalises
         the key so ingress and egress UDP can still be paired.
    Other protocols (OSPF, ICMP, …): skipped (return None).
    """
    if not pkt.haslayer(IP):
        return None
    ip = pkt[IP]
    if ip.proto == 6 and pkt.haslayer(TCP):
        t = pkt[TCP]
        return (ip.src, ip.dst, t.sport, t.dport, 6)
    if ip.proto == 17:
        # Omit ports: egress UDP has no UDP header due to deparser limitation
        return (ip.src, ip.dst, 0, 0, 17)
    return None  # skip OSPF and other non-TCP/UDP


def load_pcap(path):
    """Return dict: flow_key → sorted list of PCAP timestamps (seconds)."""
    if Path(path).stat().st_size == 0:
        return {}
    try:
        pkts = rdpcap(str(path))
    except Exception:
        return {}
    index = {}
    for pkt in pkts:
        key = flow_key(pkt)
        if key is None:
            continue
        index.setdefault(key, []).append(float(pkt.time))
    for times in index.values():
        times.sort()
    return index


def compute_latencies(ingress_index, egress_index, max_latency_ms=2000):
    """
    Pair each ingress packet with the corresponding egress packet (by arrival order
    within flow) and return latency samples in microseconds.

    max_latency_ms: discard pairs whose delta exceeds this — they are cross-run
    matches caused by stale data in PCAPs from a previous make run.
    """
    latencies_us = []
    unmatched = 0
    cross_run = 0
    max_us = max_latency_ms * 1000

    for key, in_times in ingress_index.items():
        if key not in egress_index:
            unmatched += len(in_times)
            continue

        out_times = egress_index[key]
        pairs = min(len(in_times), len(out_times))
        unmatched += len(in_times) - pairs

        for t_in, t_out in zip(in_times[:pairs], out_times[:pairs]):
            delta_us = (t_out - t_in) * 1e6
            if delta_us < 0 or delta_us > max_us:
                cross_run += 1
            else:
                latencies_us.append(delta_us)

    if cross_run:
        print(f"  WARNING: {cross_run} pairs discarded (cross-run stale PCAP data).")
        print("  Run 'make run', reload tables, replay traffic, then re-run this script.")

    return latencies_us, unmatched


def percentile(sorted_data, p):
    idx = int(len(sorted_data) * p / 100)
    return sorted_data[min(idx, len(sorted_data) - 1)]


def print_stats(latencies_us, unmatched, total_ingress):
    print()
    print("=" * 54)
    print("  P4 Pipeline Latency  (ingress → egress)")
    print("=" * 54)
    print(f"  Total ingress pkts   : {total_ingress:>10,}")
    print(f"  Matched packets      : {len(latencies_us):>10,}")
    print(f"  Unmatched / dropped  : {unmatched:>10,}")
    print()

    if not latencies_us:
        print("  No matched packets — check PCAP files.")
        print("=" * 54)
        return

    s = sorted(latencies_us)
    n = len(s)
    avg = statistics.mean(s)
    std = statistics.stdev(s) if n > 1 else 0.0

    def fmt(us):
        return f"{us / 1000:>10.3f} ms  ({us:>8.1f} µs)"

    print(f"  Min                  : {fmt(s[0])}")
    print(f"  Avg                  : {fmt(avg)}")
    print(f"  Std dev              : {std / 1000:>10.3f} ms")
    print(f"  Median  (p50)        : {fmt(percentile(s, 50))}")
    print(f"  p95                  : {fmt(percentile(s, 95))}")
    print(f"  p99                  : {fmt(percentile(s, 99))}")
    print(f"  Max                  : {fmt(s[-1])}")
    print("=" * 54)
    print()


def plot_latency(latencies_us, out_path="figures/latency_hist.png"):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not available — skipping plot.")
        return

    s = sorted(latencies_us)
    ms = [v / 1000 for v in s]
    p95 = percentile(s, 95) / 1000
    p99 = percentile(s, 99) / 1000

    fig, ax = plt.subplots(figsize=(8, 4))
    ax.hist(ms, bins=60, color="#2980b9", edgecolor="white", linewidth=0.5, label="Latency")
    ax.axvline(p95, color="#e74c3c", linestyle="--", linewidth=1.2, label=f"p95 = {p95:.2f} ms")
    ax.axvline(p99, color="#c0392b", linestyle=":",  linewidth=1.2, label=f"p99 = {p99:.2f} ms")

    ax.set_xlabel("Latency (ms)", fontsize=11)
    ax.set_ylabel("Packet count", fontsize=11)
    ax.set_title(
        "P4 In-Network Inference Latency Distribution\n(ingress → egress, per packet)",
        fontsize=12, fontweight="bold"
    )
    ax.legend(fontsize=10)
    ax.grid(axis="y", alpha=0.3)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    plt.tight_layout()
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"Histogram saved: {out_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Measure P4 switching latency from BMv2 PCAP timestamps."
    )
    parser.add_argument(
        "--ingress", default="../pcaps/s1-eth1_in.pcap",
        help="Ingress PCAP (default: pcaps/s1-eth1_in.pcap)"
    )
    parser.add_argument(
        "--egress", nargs="+",
        default=["../pcaps/s1-eth2_out.pcap", "../pcaps/s1-eth3_out.pcap"],
        help="Egress PCAP(s) — all are merged before matching"
    )
    parser.add_argument("--plot", action="store_true", help="Save latency histogram PNG")
    parser.add_argument(
        "--max-latency", type=float, default=2000,
        help="Discard pairs with delta > this value in ms (default: 2000). "
             "Filters cross-run stale PCAP matches."
    )
    args = parser.parse_args()

    ingress_path = Path(args.ingress)
    if not ingress_path.exists():
        print(f"ERROR: ingress PCAP not found: {ingress_path}")
        sys.exit(1)

    print(f"Loading ingress : {ingress_path}")
    ingress_index = load_pcap(ingress_path)
    total_ingress = sum(len(v) for v in ingress_index.values())

    egress_index = {}
    for ep in args.egress:
        ep = Path(ep)
        if not ep.exists():
            print(f"  WARNING: egress PCAP not found: {ep} — skipping")
            continue
        print(f"Loading egress  : {ep}")
        for key, times in load_pcap(ep).items():
            egress_index.setdefault(key, []).extend(times)

    for times in egress_index.values():
        times.sort()

    latencies_us, unmatched = compute_latencies(ingress_index, egress_index, args.max_latency)
    print_stats(latencies_us, unmatched, total_ingress)

    if args.plot:
        plot_latency(latencies_us)


if __name__ == "__main__":
    main()

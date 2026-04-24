#!/usr/bin/env python3
"""
UNSW-NB15 pcap replay script — run from h2 inside the Mininet CLI:

    h2 python3 /home/ubuntu/p4_ddos_thesis/traffic/replay.py [OPTIONS]

Wraps tcpreplay to give the automated experiment fine-grained control over
replay rate, loop count, and pcap selection, with structured stats output.

Prerequisites
-------------
  - Run traffic/preprocess_pcaps.sh first to remap IPs/MACs to topology values.
  - tcpreplay must be installed: sudo apt-get install tcpreplay

Rate options (mutually exclusive)
----------------------------------
  --mbps  N     Replay at N Megabits/sec   (e.g. --mbps 100)
  --pps   N     Replay at N packets/sec    (e.g. --pps 50000)
  --mult  N     Replay at Nx original rate (e.g. --mult 2.0)
  (default: --mbps 100)

Examples
--------
  h2 python3 replay.py --mbps 10
  h2 python3 replay.py --mbps 100 --loop 3
  h2 python3 replay.py --pcap /home/ubuntu/p4_ddos_thesis/pcap/remapped/dos.pcap --mbps 50
  h2 python3 replay.py --list-pcaps
"""

import argparse
import glob
import json
import os
import re
import subprocess
import sys
import time

BASE_DIR    = '/home/ubuntu/p4_ddos_thesis'
PCAP_DIR    = f'{BASE_DIR}/pcap/remapped'
DEFAULT_IFACE = 'h2-eth0'


# ── Helpers ───────────────────────────────────────────────────────────────────
def find_pcaps():
    """Return sorted list of remapped pcap files."""
    files = sorted(glob.glob(f'{PCAP_DIR}/*.pcap') +
                   glob.glob(f'{PCAP_DIR}/*.pcapng'))
    return files


def parse_tcpreplay_stats(output: str) -> dict:
    """
    Extract key metrics from tcpreplay's end-of-run statistics block.

    tcpreplay outputs lines like:
        Actual: 123456 packets (7654321 bytes) sent in 10.00 seconds
        Rated: 765432.1 Bps, 6.12 Mbps, 12345.6 pps
        Statistics for network device: h2-eth0
            Attempted packets:  123456
            Successful packets: 123456
            Failed packets:     0
    """
    stats = {}

    m = re.search(r'Actual:\s+([\d]+)\s+packets\s+\((\d+)\s+bytes\)\s+sent in\s+([\d.]+)\s+seconds',
                  output)
    if m:
        stats['packets_sent'] = int(m.group(1))
        stats['bytes_sent']   = int(m.group(2))
        stats['elapsed_s']    = float(m.group(3))

    m = re.search(r'Rated:\s+([\d.]+)\s+Bps,\s+([\d.]+)\s+Mbps,\s+([\d.]+)\s+pps', output)
    if m:
        stats['actual_mbps'] = float(m.group(2))
        stats['actual_pps']  = float(m.group(3))

    m = re.search(r'Successful packets:\s+(\d+)', output)
    if m:
        stats['successful_packets'] = int(m.group(1))

    m = re.search(r'Failed packets:\s+(\d+)', output)
    if m:
        stats['failed_packets'] = int(m.group(1))

    return stats


def run_replay(pcap: str, iface: str, mbps=None, pps=None, mult=None,
               loop: int = 1, verbose: bool = True) -> dict:
    """
    Invoke tcpreplay and return a stats dict.

    Returns dict with keys: packets_sent, bytes_sent, elapsed_s,
                            actual_mbps, actual_pps, successful_packets,
                            failed_packets, returncode.
    """
    if not os.path.exists(pcap):
        print(f'[replay] ERROR: pcap not found: {pcap}', file=sys.stderr)
        return {'returncode': 1, 'error': 'pcap not found'}

    cmd = ['tcpreplay', f'--intf1={iface}',
           '--mtu=1500', '--mtu-trunc']  # truncate oversized frames instead of dropping

    if mbps is not None:
        cmd += [f'--mbps={mbps}']
    elif pps is not None:
        cmd += [f'--pps={pps}']
    elif mult is not None:
        cmd += [f'--multiplier={mult}']
    else:
        cmd += ['--mbps=100']

    if loop > 1:
        cmd += [f'--loop={loop}']

    cmd.append(pcap)

    if verbose:
        rate_desc = (f'{mbps} Mbps' if mbps else
                     f'{pps} pps'  if pps  else
                     f'{mult}x'    if mult  else '100 Mbps')
        print(f'[replay] {os.path.basename(pcap)}  rate={rate_desc}'
              f'  loop={loop}  iface={iface}')

    t0 = time.time()
    result = subprocess.run(cmd, capture_output=True, text=True)
    wall_time = time.time() - t0

    combined = result.stdout + result.stderr
    stats = parse_tcpreplay_stats(combined)
    stats['returncode'] = result.returncode
    stats['wall_time_s'] = round(wall_time, 2)

    if result.returncode != 0 and verbose:
        print(f'[replay] tcpreplay exited with rc={result.returncode}',
              file=sys.stderr)
        print(combined, file=sys.stderr)

    if verbose and stats:
        sent = stats.get('packets_sent', '?')
        mbps_actual = stats.get('actual_mbps', '?')
        pps_actual  = stats.get('actual_pps', '?')
        elapsed     = stats.get('elapsed_s', wall_time)
        print(f'[replay] Done: {sent} pkts  {mbps_actual} Mbps  '
              f'{pps_actual} pps  {elapsed:.2f}s')

    return stats


# ── CLI ───────────────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(description='UNSW-NB15 pcap replay for P4 thesis')

    p.add_argument('--pcap',   default=None,
                   help='Path to remapped pcap (default: first file in pcap/remapped/)')
    p.add_argument('--iface',  default=DEFAULT_IFACE)
    p.add_argument('--loop',   type=int,   default=1,
                   help='Number of times to loop the pcap (default: 1)')

    rate = p.add_mutually_exclusive_group()
    rate.add_argument('--mbps', type=float, default=None,
                      help='Replay rate in Mbps')
    rate.add_argument('--pps',  type=float, default=None,
                      help='Replay rate in packets/sec')
    rate.add_argument('--mult', type=float, default=None,
                      help='Replay rate as multiplier of original capture rate')

    p.add_argument('--list-pcaps', action='store_true',
                   help='List available remapped pcaps and exit')
    p.add_argument('--json-out', default=None,
                   help='Write stats as JSON to this file path')

    return p.parse_args()


def main():
    args = parse_args()

    if args.list_pcaps:
        pcaps = find_pcaps()
        if not pcaps:
            print(f'[replay] No remapped pcaps found in {PCAP_DIR}')
            print(f'         Run traffic/preprocess_pcaps.sh first.')
        else:
            print(f'[replay] Remapped pcaps in {PCAP_DIR}:')
            for f in pcaps:
                size_mb = os.path.getsize(f) / 1e6
                print(f'  {os.path.basename(f):50s}  {size_mb:.1f} MB')
        return

    # Resolve pcap path
    pcap = args.pcap
    if pcap is None:
        pcaps = find_pcaps()
        if not pcaps:
            print(f'[replay] ERROR: No remapped pcaps found in {PCAP_DIR}',
                  file=sys.stderr)
            print(f'         Run traffic/preprocess_pcaps.sh first.',
                  file=sys.stderr)
            sys.exit(1)
        pcap = pcaps[0]
        print(f'[replay] Auto-selected pcap: {os.path.basename(pcap)}')

    stats = run_replay(
        pcap=pcap,
        iface=args.iface,
        mbps=args.mbps,
        pps=args.pps,
        mult=args.mult,
        loop=args.loop,
        verbose=True,
    )

    if args.json_out:
        with open(args.json_out, 'w') as f:
            json.dump(stats, f, indent=2)
        print(f'[replay] Stats written to {args.json_out}')

    sys.exit(stats.get('returncode', 0))


if __name__ == '__main__':
    main()

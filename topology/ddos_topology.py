# ~/p4_ddos/topology/ddos_topology.py

#!/usr/bin/env python3
"""
DDoS Detection Topology for P4 Thesis Experiment

Topology:
    h1 (legitimate) ──┐
    h2 (attacker)   ──┤── s1 (OVSBridge) ── s2 (BMv2 P4) ── h3 (victim)

s1 is a standard learning bridge: it handles ARP for h1↔h2 automatically.
Static ARP is only needed for the cross-switch pairs (h{1,2} ↔ h3).
BMv2 has two ports: port 0 faces s1, port 1 faces h3.
"""

import os
import sys
import time
import subprocess
from mininet.net   import Mininet
from mininet.node  import Switch, OVSBridge
from mininet.cli   import CLI
from mininet.log   import setLogLevel, info, error
from mininet.clean import cleanup

# ─────────────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────────────
BASE_DIR  = '/home/ubuntu/p4_ddos_thesis'
P4_JSON   = f'{BASE_DIR}/p4/rf_ddos_detect.json'
P4_INFO   = f'{BASE_DIR}/p4/rf_ddos_detect.p4info.txt'
LOG_DIR   = f'{BASE_DIR}/results/logs'
GRPC_PORT = 9559
DEVICE_ID = 1

# ─────────────────────────────────────────────────────────────────────
# Host configuration — single source of truth
# ─────────────────────────────────────────────────────────────────────
HOSTS = {
    'h1': {'ip': '10.0.0.1/24', 'mac': '00:00:00:00:00:01'},  # legitimate
    'h2': {'ip': '10.0.0.2/24', 'mac': '00:00:00:00:00:02'},  # attacker
    'h3': {'ip': '10.0.0.3/24', 'mac': '00:00:00:00:00:03'},  # victim
}


# ─────────────────────────────────────────────────────────────────────
# BMv2 as a Mininet Switch — Mininet creates and wires all interfaces
# ─────────────────────────────────────────────────────────────────────
class BMv2Switch(Switch):
    """
    Wraps simple_switch_grpc as a Mininet Switch node.

    Mininet creates the veth pairs and places interfaces in the root
    namespace before calling start(), so BMv2 can bind to them directly.
    Mininet port N maps to BMv2 port (N-1) because Mininet reserves
    port 0 for loopback.
    """

    def __init__(self, name, json_path, log_dir,
                 grpc_port=9559, device_id=1, **kwargs):
        Switch.__init__(self, name, **kwargs)
        self.json_path  = json_path
        self.log_dir    = log_dir
        self.grpc_port  = grpc_port
        self.device_id  = device_id
        self.bmv2_proc  = None

    def start(self, controllers):
        os.makedirs(self.log_dir, exist_ok=True)
        iface_args = []
        for port_no in sorted(self.intfs):
            if port_no == 0:
                continue  # skip loopback
            iface_args += ['-i', f'{port_no - 1}@{self.intfs[port_no].name}']

        log_file = f'{self.log_dir}/bmv2_{self.name}.log'
        cmd = ['simple_switch_grpc',
               '--device-id', str(self.device_id),
               '--log-file',  log_file,
               '--log-flush']
        cmd += iface_args
        cmd += [self.json_path, '--',
                '--grpc-server-addr', f'0.0.0.0:{self.grpc_port}']

        info(f'*** Starting BMv2: {" ".join(cmd)}\n')
        self.bmv2_proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
        if self.bmv2_proc.poll() is not None:
            error(f'*** BMv2 exited immediately (rc={self.bmv2_proc.returncode}). '
                  f'Check {log_file}\n')
            sys.exit(1)
        info(f'*** BMv2 started (PID={self.bmv2_proc.pid})\n')

    def stop(self):
        if self.bmv2_proc:
            self.bmv2_proc.terminate()
            self.bmv2_proc.wait()
            info('*** BMv2 stopped\n')
        # Do not call Switch.stop() — BMv2 is not an OVS bridge.


# ─────────────────────────────────────────────────────────────────────
# Main Topology
# ─────────────────────────────────────────────────────────────────────
def run_topology(interactive=True):
    info('*** Cleaning up previous runs\n')
    cleanup()

    # ── Build network ────────────────────────────────────────────────
    info('*** Building Mininet network\n')
    net = Mininet(controller=None)

    h1 = net.addHost('h1', ip=HOSTS['h1']['ip'], mac=HOSTS['h1']['mac'])
    h2 = net.addHost('h2', ip=HOSTS['h2']['ip'], mac=HOSTS['h2']['mac'])
    h3 = net.addHost('h3', ip=HOSTS['h3']['ip'], mac=HOSTS['h3']['mac'])

    # s1: standard learning bridge — handles ARP for h1↔h2 automatically
    s1 = net.addSwitch('s1', cls=OVSBridge)

    # s2: BMv2 P4 switch inline on the path to the victim
    s2 = net.addSwitch('s2', cls=BMv2Switch,
                       json_path=P4_JSON, log_dir=LOG_DIR,
                       grpc_port=GRPC_PORT, device_id=DEVICE_ID)

    # Link order fixes BMv2 port numbers:
    #   s2 Mininet port 1 → BMv2 port 0  (faces s1)
    #   s2 Mininet port 2 → BMv2 port 1  (faces h3)
    net.addLink(h1, s1)
    net.addLink(h2, s1, bw=10)   # cap attack traffic so BMv2 isn't CPU-saturated
    net.addLink(s1, s2)
    net.addLink(s2, h3)

    info('*** Starting network\n')
    net.start()

    # ── Disable TCP offloads on all host interfaces ───────────────────
    # GSO/GRO/TSO allow the kernel to batch TCP segments into ~64 KB
    # super-packets before handing them to BMv2.  Without this, BMv2
    # processes 1 packet's worth of CPU but delivers 45 packets' worth
    # of data, inflating throughput measurements ~37×.
    info('*** Disabling TCP offloads (GSO/GRO/TSO) on host interfaces\n')
    for host in net.hosts:
        for intf in host.intfs.values():
            if intf.name != 'lo':
                host.cmd(f'ethtool -K {intf.name} '
                         f'tx off rx off gso off gro off tso off 2>/dev/null')

    # ── Static ARP for cross-switch pairs only ───────────────────────
    # OVS handles h1↔h2 ARP via MAC learning. BMv2 drops non-IPv4, so
    # h{1,2}↔h3 ARP must be pre-loaded. This is the minimal static set.
    info('*** Adding cross-switch ARP entries (h{1,2} ↔ h3)\n')
    h3_ip  = HOSTS['h3']['ip'].split('/')[0]
    h3_mac = HOSTS['h3']['mac']
    for hname in ('h1', 'h2'):
        net.get(hname).cmd(f'arp -s {h3_ip} {h3_mac}')

    for hname in ('h1', 'h2'):
        peer_ip  = HOSTS[hname]['ip'].split('/')[0]
        peer_mac = HOSTS[hname]['mac']
        h3.cmd(f'arp -s {peer_ip} {peer_mac}')

    # ── Populate P4 forwarding tables ────────────────────────────────
    info('*** Populating P4 Runtime tables\n')
    try:
        result = subprocess.run(
            ['python3', f'{BASE_DIR}/controller/populate_tables.py',
             '--p4info',    P4_INFO,
             '--bmv2-json', P4_JSON,
             '--rf-model',  f'{BASE_DIR}/model/rf_model.json',
             '--grpc-addr', f'127.0.0.1:{GRPC_PORT}'],
            capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            info('*** Tables populated successfully\n')
        else:
            error(f'*** Table population failed:\n{result.stderr}\n')
    except subprocess.TimeoutExpired:
        error('*** Table population timed out — BMv2 may not be ready\n')

    # ── Connectivity check ────────────────────────────────────────────
    info('*** Testing connectivity\n')
    out = h1.cmd('ping -c 3 -W 1 10.0.0.3')
    info(out)
    if '0 received' in out or '100% packet loss' in out:
        error('*** Connectivity test FAILED — check controller logs\n')
    else:
        info('*** Connectivity test PASSED\n')

    # ── Run experiment ────────────────────────────────────────────────
    if interactive:
        info('\n' + '='*60 + '\n')
        info('  Mininet CLI ready. Experiment commands:\n')
        info('='*60 + '\n')
        info('  pingall                              — reachability check\n')
        info('  h1 ping h3                           — connectivity test\n')
        info('  h3 iperf -s &                        — start iperf server\n')
        info('  h1 iperf -c 10.0.0.3 -t 5           — baseline throughput\n')
        info('  h2 python3 /home/ubuntu/p4_ddos_thesis/traffic/replay.py --mbps 100 &\n')
        info('                                       — UNSW-NB15 replay at 100 Mbps\n')
        info('  h2 python3 /home/ubuntu/p4_ddos_thesis/traffic/replay.py --mbps 50 &\n')
        info('                                       — UNSW-NB15 replay at 50 Mbps\n')
        info('  h2 python3 /home/ubuntu/p4_ddos_thesis/traffic/replay.py --list-pcaps\n')
        info('                                       — list available pcap files\n')
        info('  h3 tcpdump -i h3-eth0 udp            — watch h3 receives\n')
        info('  h1 tcpdump -i h1-eth0 -w /tmp/cap.pcap &  — capture\n')
        info('  exit                                 — stop experiment\n')
        info('='*60 + '\n')
        CLI(net)
    else:
        run_automated_experiment(net)

    # ── Cleanup ───────────────────────────────────────────────────────
    info('*** Stopping network\n')
    net.stop()
    info('*** Experiment complete\n')


# ─────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────
def _parse_iperf(output):
    """Return Mbps from iperf (not iperf3) text output, or None on failure."""
    import re
    for line in output.splitlines():
        # iperf reports: "... 12.3 Mbits/sec" or "... 12.3 Kbits/sec"
        m = re.search(r'([\d.]+)\s+(K|M|G)bits/sec', line)
        if m:
            val, unit = float(m.group(1)), m.group(2)
            return round(val * {'K': 1e-3, 'M': 1, 'G': 1e3}[unit], 2)
    return None


def _start_replay(h2, mbps=100):
    """Start UNSW-NB15 pcap replay from h2 in the background."""
    h2.cmd(
        f'python3 {BASE_DIR}/traffic/replay.py '
        f'--mbps {mbps} --loop 999 --iface h2-eth0 '
        f'> /tmp/replay.log 2>&1 &'
    )


def _stop_replay(h2):
    h2.cmd('pkill -f tcpreplay 2>/dev/null; pkill -f replay.py 2>/dev/null; true')


def _refresh_offloads(hosts):
    """Re-disable TCP offloads on every host interface before a measurement.

    Called before each iperf run because ethtool settings can be silently
    reset by some Linux/veth driver versions after a new TCP connection is
    established, producing inflated software-switch throughput readings.
    """
    for host in hosts:
        for intf in host.intfs.values():
            if intf.name != 'lo':
                host.cmd(f'ethtool -K {intf.name} '
                         f'tx off rx off gso off gro off tso off 2>/dev/null')


def _populate(with_rf=True):
    """(Re-)install P4Runtime table entries via the controller script.

    with_rf=False installs forwarding only (no RF trees) for the
    no-detection control phase.
    """
    cmd = ['python3', f'{BASE_DIR}/controller/populate_tables.py',
           '--p4info',    P4_INFO,
           '--bmv2-json', P4_JSON,
           '--rf-model',  f'{BASE_DIR}/model/rf_model.json',
           '--grpc-addr', f'127.0.0.1:{GRPC_PORT}']
    if not with_rf:
        cmd.append('--no-rf')
    label = 'with RF detection' if with_rf else 'forwarding only (no RF)'
    info(f'*** Re-populating P4 tables ({label})\n')
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            error(f'*** Table re-population failed:\n{result.stderr}\n')
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        error('*** Table re-population timed out\n')
        return False


def _iface_packets(host):
    """Return (rx_pkts, tx_pkts) for the host's primary interface.

    Reads /proc/net/dev inside the host's network namespace.
    """
    intf = host.defaultIntf()
    if not intf:
        return 0, 0
    out = host.cmd(f'grep "{intf.name}:" /proc/net/dev 2>/dev/null')
    # /proc/net/dev columns: iface: rx_bytes rx_pkts errs drop ... tx_bytes tx_pkts ...
    parts = out.strip().split()
    if len(parts) < 11:
        return 0, 0
    try:
        return int(parts[2]), int(parts[10])
    except (ValueError, IndexError):
        return 0, 0


def _iperf_mean(h1, runs=3, duration=15):
    """Run iperf RUNS times and return (mean_mbps, [individual_readings]).

    Multiple back-to-back runs average out BMv2 software scheduling noise,
    producing a more stable and defensible throughput measurement.
    """
    readings = []
    for i in range(runs):
        out = h1.cmd(f'iperf -c 10.0.0.3 -t {duration} -i 0')
        val = _parse_iperf(out)
        if val is not None:
            readings.append(val)
        if i < runs - 1:
            time.sleep(2)
    if not readings:
        return None, []
    return round(sum(readings) / len(readings), 2), readings


# ─────────────────────────────────────────────────────────────────────
# Automated Experiment
# ─────────────────────────────────────────────────────────────────────
def _restart_iperf_server(h3):
    """Kill any existing iperf server on h3 and start a fresh one.

    Uses background '&' rather than daemon mode (-D) so the process stays
    inside Mininet's network namespace.  Polls ss/netstat until port 5001
    is actually in LISTEN state before returning, so the caller can rely on
    the server being ready immediately.
    """
    h3.cmd('pkill -f "iperf" 2>/dev/null; true')
    time.sleep(0.3)
    h3.cmd('iperf -s > /tmp/iperf_server.log 2>&1 &')
    # Poll until port 5001 is in LISTEN state (max 10 s)
    for _ in range(40):
        status = h3.cmd('ss -tlnp 2>/dev/null | grep 5001 || '
                        'netstat -tlnp 2>/dev/null | grep 5001 || echo ""')
        if '5001' in status:
            return
        time.sleep(0.25)
    error('*** [WARN] iperf server did not reach LISTEN state on h3\n')


def run_automated_experiment(net):
    import json
    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')
    hosts = [h1, h2, h3]
    results = {}

    # ── Phase 0: Control — 5 Mbps attack, RF detection DISABLED ─────────────
    # Shows what happens to legitimate throughput WITHOUT the P4 classifier.
    # Expected: significant throughput degradation, proving the classifier
    # adds value when it is enabled in subsequent phases.
    info('\n*** Phase 0 — Control: 5 Mbps attack, detection DISABLED\n')
    _populate(with_rf=False)
    _start_replay(h2, mbps=5)
    time.sleep(5)
    h1.cmd('ping -c 2 -W 1 10.0.0.3 > /dev/null 2>&1')

    h2_rx0, h2_tx0 = _iface_packets(h2)
    h3_rx0, _      = _iface_packets(h3)

    _refresh_offloads(hosts)
    _restart_iperf_server(h3)
    mean, trials = _iperf_mean(h1, runs=3, duration=15)
    results['control_5mbps_legit_mbps'] = mean
    results['control_5mbps_trials']     = trials
    info(f'    Control (no detect, 5 Mbps): {mean} Mbps  trials={trials}\n')

    for line in h1.cmd('ping -c 20 -i 0.05 10.0.0.3').split('\n'):
        if 'rtt' in line:
            results['control_5mbps_rtt'] = line.strip()
            info(f'    RTT (control): {line.strip()}\n')

    _, h2_tx1 = _iface_packets(h2)
    h3_rx1, _ = _iface_packets(h3)
    results['control_5mbps_h2_tx_pkts'] = h2_tx1 - h2_tx0
    results['control_5mbps_h3_rx_pkts'] = h3_rx1 - h3_rx0
    info(f'    Packets — h2 sent: {h2_tx1-h2_tx0}, h3 received: {h3_rx1-h3_rx0}\n')

    _stop_replay(h2)
    time.sleep(5)

    # ── Restore RF detection ──────────────────────────────────────────────────
    _populate(with_rf=True)

    # ── Phase 1: Baseline (no attack) ────────────────────────────────────────
    info('\n*** Phase 1 — Baseline throughput (no attack)\n')
    _refresh_offloads(hosts)
    _restart_iperf_server(h3)
    mean, trials = _iperf_mean(h1, runs=3, duration=15)
    results['baseline_mbps']   = mean
    results['baseline_trials'] = trials
    info(f'    Baseline: {mean} Mbps  trials={trials}\n')

    info('\n*** Phase 1b — Baseline latency (no attack)\n')
    for line in h1.cmd('ping -c 50 -i 0.02 10.0.0.3').split('\n'):
        if 'rtt' in line:
            results['baseline_rtt'] = line.strip()
            info(f'    {line.strip()}\n')

    # ── Phases 2–4: Three replay intensities, detection ON ───────────────────
    for mbps in (2, 5, 10):
        label = f'{mbps}mbps'
        info(f'\n*** Phase — UNSW-NB15 replay at {mbps} Mbps (detection ON)\n')

        _start_replay(h2, mbps=mbps)
        time.sleep(5)
        h1.cmd('ping -c 2 -W 1 10.0.0.3 > /dev/null 2>&1')

        h2_rx0, h2_tx0 = _iface_packets(h2)
        h3_rx0, _      = _iface_packets(h3)

        _refresh_offloads(hosts)
        _restart_iperf_server(h3)
        mean, trials = _iperf_mean(h1, runs=3, duration=15)
        results[f'attack_{label}_legit_mbps'] = mean
        results[f'attack_{label}_trials']     = trials
        info(f'    Legit throughput under {mbps} Mbps attack: {mean} Mbps  trials={trials}\n')

        for line in h1.cmd('ping -c 20 -i 0.05 10.0.0.3').split('\n'):
            if 'rtt' in line:
                results[f'attack_{label}_rtt'] = line.strip()
                info(f'    RTT under attack: {line.strip()}\n')

        _, h2_tx1 = _iface_packets(h2)
        h3_rx1, _ = _iface_packets(h3)
        h2_tx_delta = h2_tx1 - h2_tx0
        h3_rx_delta = h3_rx1 - h3_rx0
        results[f'attack_{label}_h2_tx_pkts'] = h2_tx_delta
        results[f'attack_{label}_h3_rx_pkts'] = h3_rx_delta
        if h2_tx_delta > 0:
            # Conservative estimate: includes h1's legitimate iperf packets in
            # h3_rx_delta, so the true drop rate is slightly higher than reported.
            drop_pct = round(100 * max(0.0, 1 - h3_rx_delta / h2_tx_delta), 1)
            results[f'attack_{label}_drop_pct'] = drop_pct
            info(f'    Packets — h2 sent: {h2_tx_delta}, '
                 f'h3 received: {h3_rx_delta}, drop≈{drop_pct}%\n')

        _stop_replay(h2)
        time.sleep(5)

    # ── Phase 5: Recovery ─────────────────────────────────────────────────────
    info('\n*** Phase 5 — Post-attack recovery throughput\n')
    _refresh_offloads(hosts)
    _restart_iperf_server(h3)
    mean, trials = _iperf_mean(h1, runs=3, duration=15)
    results['recovery_mbps']   = mean
    results['recovery_trials'] = trials
    info(f'    Recovery: {mean} Mbps  trials={trials}\n')

    # ── Summary ───────────────────────────────────────────────────────────────
    info('\n' + '='*60 + '\n')
    info('  EXPERIMENT SUMMARY\n')
    info('='*60 + '\n')
    for k, v in results.items():
        info(f'  {k:<40s} {v}\n')
    info('='*60 + '\n')

    results_path = f'{BASE_DIR}/results/experiment_results.json'
    os.makedirs(os.path.dirname(results_path), exist_ok=True)
    with open(results_path, 'w') as f:
        json.dump(results, f, indent=2)
    info(f'\n*** Results saved to {results_path}\n')


# ─────────────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    setLogLevel('info')

    if not os.path.exists(P4_JSON):
        error(f'P4 JSON not found: {P4_JSON}\n')
        error('Compile first:  p4c --target bmv2 --arch v1model p4/rf_ddos_detect.p4\n')
        sys.exit(1)

    run_topology(interactive='--auto' not in sys.argv)

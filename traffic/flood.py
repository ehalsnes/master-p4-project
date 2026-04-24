#!/usr/bin/env python3
"""
UDP flood script — run from h2 inside the Mininet CLI:
    h2 python3 /home/ubuntu/p4_ddos_thesis/traffic/flood.py &

Sends a burst of UDP packets to 10.0.0.3:80 as fast as scapy allows.
The P4 switch (s2) classifies high-rate flows as DDoS and drops them.
"""

import sys
import time
from scapy.all import IP, UDP, Ether, sendp, conf

DST_IP   = '10.0.0.3'
DST_MAC  = '00:00:00:00:00:03'
SRC_IP   = '10.0.0.2'
SRC_MAC  = '00:00:00:00:00:02'
DST_PORT = 80
COUNT    = int(sys.argv[1]) if len(sys.argv) > 1 else 10000
IFACE    = sys.argv[2] if len(sys.argv) > 2 else 'h2-eth0'

conf.verb = 0

pkt = (Ether(src=SRC_MAC, dst=DST_MAC) /
       IP(src=SRC_IP, dst=DST_IP, ttl=64) /
       UDP(sport=12345, dport=DST_PORT) /
       b'X' * 64)

print(f'[flood] Sending {COUNT} UDP packets to {DST_IP}:{DST_PORT} via {IFACE}')
t0 = time.time()
sendp(pkt, iface=IFACE, count=COUNT, inter=0, verbose=False)
elapsed = time.time() - t0
print(f'[flood] Done: {COUNT} packets in {elapsed:.2f}s ({COUNT/elapsed:.0f} pkt/s)')

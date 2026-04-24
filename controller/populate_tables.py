#!/usr/bin/env python3
"""
P4Runtime controller: load RF decision-tree rules and forwarding entries
into a BMv2 simple_switch_grpc instance.

Usage:
    python3 populate_tables.py \
        --p4info    /path/to/rf_ddos_detect.p4info.txt \
        --bmv2-json /path/to/rf_ddos_detect.json \
        --rf-model  /path/to/rf_model.json \
        --grpc-addr 127.0.0.1:9559

NOTE: requires grpcio  →  pip3 install grpcio
"""

import argparse
import json
import os
import struct
import sys
import threading

# ── Ensure grpcio is present ──────────────────────────────────────────
try:
    import grpc
except ImportError:
    sys.exit(
        "ERROR: grpcio not installed.\n"
        "  Fix: pip3 install grpcio\n"
        "   or: sudo pip3 install grpcio"
    )

# ── Add PI proto Python bindings to path ─────────────────────────────
_HERE   = os.path.dirname(os.path.abspath(__file__))
_PI_OUT = os.path.join(_HERE, '..', 'PI', 'proto', 'py_out')

# Import protobuf from the system path first so google.protobuf is cached.
# Then insert PI_OUT and extend google.__path__ so that google.rpc (which
# lives in PI/proto/py_out/google/rpc/) is also reachable without shadowing
# the system google.protobuf.
import google.protobuf          # noqa: E402  — must precede sys.path change
from google.protobuf import text_format

_PI_OUT_ABS = os.path.abspath(_PI_OUT)
sys.path.insert(0, _PI_OUT_ABS)

import google as _google_pkg
_pi_google = os.path.join(_PI_OUT_ABS, 'google')
if _pi_google not in _google_pkg.__path__:
    _google_pkg.__path__.append(_pi_google)

from p4.v1        import p4runtime_pb2
from p4.v1        import p4runtime_pb2_grpc
from p4.config.v1 import p4info_pb2

# ── Constants ─────────────────────────────────────────────────────────
DEVICE_ID       = 1
ELECTION_LOW    = 1
MAX32           = (1 << 32) - 1
TABLE_MAX       = 512        # P4 table size cap per tree
N_TREES_IN_P4   = 3          # tree_0 … tree_2 exist in the P4 program
VOTE_THRESH     = 2          # majority of 3 trees  (P4 hardcodes 5 — see note)

# NOTE: the compiled P4 has VOTE_THRESH=5 but only 3 trees are instantiated,
# so the maximum attainable vote is 3.  To make detection work without
# recompiling, we accept that the controller cannot override the P4 constant.
# Recompile with VOTE_THRESH=2 for live detection, or extend the P4 program
# with tree_3 … tree_9 (each using 512 entries) and keep VOTE_THRESH=5.

# Map RF feature names → P4 metadata field names (table match field names)
FEAT_TO_P4 = {
    'sttl':         'meta.sttl',
    'ct_state_ttl': 'meta.ct_state_ttl',
    'rate':         'meta.rate',
    'dload':        'meta.dload',
    'sinpkt':       'meta.sinpkt',
    'smean':        'meta.smean',
}


# ── Argument parsing ──────────────────────────────────────────────────
def parse_args():
    ap = argparse.ArgumentParser(description='Populate P4 tables for DDoS RF')
    ap.add_argument('--p4info',    required=True, help='P4Info text-proto file')
    ap.add_argument('--bmv2-json', required=True, help='BMv2 compiled JSON')
    ap.add_argument('--rf-model',  required=True, help='RF model JSON')
    ap.add_argument('--grpc-addr', default='127.0.0.1:9559',
                    help='gRPC address of the switch (default: 127.0.0.1:9559)')
    ap.add_argument('--no-rf', action='store_true',
                    help='Install forwarding table only; skip RF tree entries '
                         '(use for no-detection control experiment)')
    return ap.parse_args()


# ── P4Info helpers ────────────────────────────────────────────────────
def load_p4info(path):
    p4info = p4info_pb2.P4Info()
    with open(path) as f:
        text_format.Merge(f.read(), p4info)
    return p4info

def _table_id(p4info, name):
    for t in p4info.tables:
        if t.preamble.name == name:
            return t.preamble.id
    raise KeyError(f'Table not found: {name}')

def _action_id(p4info, name):
    for a in p4info.actions:
        if a.preamble.name == name:
            return a.preamble.id
    raise KeyError(f'Action not found: {name}')

def _field_id(p4info, table_name, field_name):
    for t in p4info.tables:
        if t.preamble.name == table_name:
            for mf in t.match_fields:
                if mf.name == field_name:
                    return mf.id
    raise KeyError(f'Field {field_name} not in table {table_name}')


# ── gRPC / P4Runtime session ──────────────────────────────────────────
class P4RuntimeClient:
    def __init__(self, addr, device_id=DEVICE_ID):
        self.device_id = device_id
        self.channel   = grpc.insecure_channel(addr)
        self.stub      = p4runtime_pb2_grpc.P4RuntimeStub(self.channel)
        self._stream   = None
        self._stream_thread = None
        self._claim_mastership()

    def _claim_mastership(self):
        self._req_queue = []
        self._arb_done  = threading.Event()

        def _gen():
            req = p4runtime_pb2.StreamMessageRequest()
            req.arbitration.device_id   = self.device_id
            req.arbitration.election_id.low = ELECTION_LOW
            yield req
            # keep stream alive until client closes
            self._arb_done.wait(timeout=30)

        self._stream = self.stub.StreamChannel(_gen())
        # Read the arbitration response in a background thread
        def _read():
            try:
                for msg in self._stream:
                    if msg.HasField('arbitration'):
                        if msg.arbitration.status.code == 0:  # OK
                            print('[*] Mastership granted')
                        else:
                            print(f'[!] Arbitration status: '
                                  f'{msg.arbitration.status}')
                        break
            except Exception:
                pass
        self._stream_thread = threading.Thread(target=_read, daemon=True)
        self._stream_thread.start()
        self._stream_thread.join(timeout=5)

    def set_pipeline(self, p4info, bmv2_json_path):
        req = p4runtime_pb2.SetForwardingPipelineConfigRequest()
        req.device_id        = self.device_id
        req.election_id.low  = ELECTION_LOW
        req.action = (
            p4runtime_pb2
            .SetForwardingPipelineConfigRequest
            .VERIFY_AND_COMMIT
        )
        req.config.p4info.CopyFrom(p4info)
        with open(bmv2_json_path, 'rb') as f:
            req.config.p4_device_config = f.read()
        self.stub.SetForwardingPipelineConfig(req)

    def write_entry(self, entry):
        req = p4runtime_pb2.WriteRequest()
        req.device_id       = self.device_id
        req.election_id.low = ELECTION_LOW
        upd = req.updates.add()
        upd.type = p4runtime_pb2.Update.INSERT
        upd.entity.table_entry.CopyFrom(entry)
        self.stub.Write(req)

    def close(self):
        self._arb_done.set()
        self.channel.close()


# ── Entry builders ────────────────────────────────────────────────────
def _enc32(v):
    """Encode a 32-bit unsigned integer as 4 big-endian bytes."""
    return struct.pack('!I', int(v) & MAX32)

def _enc9(v):
    """Encode a 9-bit port number as 2 big-endian bytes."""
    return struct.pack('!H', int(v) & 0x1FF)

def _enc_ip(ip_str):
    parts = [int(x) for x in ip_str.split('.')]
    val = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
    return struct.pack('!I', val)


def make_range_entry(p4info, table_name, ranges, action_name, priority):
    """
    Build a TableEntry with RANGE match fields.
    ranges: {p4_field_name: (lo, hi)}  — both inclusive, bit<32>
    """
    entry = p4runtime_pb2.TableEntry()
    entry.table_id = _table_id(p4info, table_name)
    entry.priority = priority

    for fname, (lo, hi) in ranges.items():
        mf = entry.match.add()
        mf.field_id   = _field_id(p4info, table_name, fname)
        mf.range.low  = _enc32(lo)
        mf.range.high = _enc32(hi)

    entry.action.action.action_id = _action_id(p4info, action_name)
    return entry


def make_forward_entry(p4info, ip_str, prefix_len, port):
    """Build an LPM ipv4_forward entry that calls forward(port)."""
    entry = p4runtime_pb2.TableEntry()
    entry.table_id = _table_id(p4info, 'MyIngress.ipv4_forward')

    mf = entry.match.add()
    mf.field_id       = _field_id(p4info, 'MyIngress.ipv4_forward',
                                   'hdr.ipv4.dst_addr')
    mf.lpm.value      = _enc_ip(ip_str)
    mf.lpm.prefix_len = prefix_len

    entry.action.action.action_id = _action_id(p4info, 'MyIngress.forward')
    p = entry.action.action.params.add()
    p.param_id = 1
    p.value    = _enc9(port)
    return entry


# ── Decision-tree → P4 range entries ─────────────────────────────────
def _extract_leaves(nodes_by_id, node_id, bounds, out, limit):
    """
    Iterative DFS: collect (bounds_copy, class) for each leaf.
    Stops after `limit` leaves to respect P4 table size.
    """
    stack = [(node_id, {f: list(r) for f, r in bounds.items()})]
    while stack and len(out) < limit:
        nid, bnd = stack.pop()
        node = nodes_by_id[nid]
        if node['is_leaf']:
            out.append((dict(bnd), node['class']))
            continue
        feat = node['feature']
        thr  = int(node['threshold'])   # raw integer (not *1000 scaled)

        # Right child first (pushed to stack second → processed second)
        right_bnd = {f: list(r) for f, r in bnd.items()}
        right_bnd[feat][0] = thr + 1
        stack.append((node['right_child'], right_bnd))

        left_bnd = {f: list(r) for f, r in bnd.items()}
        left_bnd[feat][1] = thr
        stack.append((node['left_child'], left_bnd))


def tree_to_entries(p4info, table_name, tree, limit=TABLE_MAX):
    nodes_by_id = {n['id']: n for n in tree['nodes']}
    init_bounds = {feat: [0, MAX32] for feat in FEAT_TO_P4}

    leaves = []
    _extract_leaves(nodes_by_id, 0, init_bounds, leaves, limit)

    entries = []
    for priority, (bounds, cls) in enumerate(leaves, start=1):
        action = ('MyIngress.vote_attack' if cls == 1
                  else 'MyIngress.vote_normal')
        p4_ranges = {FEAT_TO_P4[f]: (lo, hi) for f, (lo, hi) in bounds.items()}
        entries.append(
            make_range_entry(p4info, table_name, p4_ranges, action, priority)
        )
    return entries


# ── Main ──────────────────────────────────────────────────────────────
def main():
    args = parse_args()

    print(f'[*] Loading P4Info from {args.p4info}')
    p4info = load_p4info(args.p4info)

    print(f'[*] Loading RF model from {args.rf_model}')
    rf_model = json.load(open(args.rf_model))
    trees = rf_model['trees']
    print(f'    {len(trees)} trees, using first {N_TREES_IN_P4}')

    print(f'[*] Connecting to switch at {args.grpc_addr}')
    client = P4RuntimeClient(args.grpc_addr)

    print(f'[*] Setting forwarding pipeline config')
    client.set_pipeline(p4info, args.bmv2_json)

    # ── ipv4_forward ─────────────────────────────────────────────────
    print('[*] Populating ipv4_forward table')
    # BMv2 (s2) has two ports:
    #   port 0 → faces OVS bridge s1  (delivers to h1, h2)
    #   port 1 → faces h3 directly
    for ip, prefix, port in [('10.0.0.1', 32, 0),
                              ('10.0.0.2', 32, 0),
                              ('10.0.0.3', 32, 1)]:
        client.write_entry(make_forward_entry(p4info, ip, prefix, port))
        print(f'    {ip}/{prefix} → port {port}')

    # ── RF tree tables ────────────────────────────────────────────────
    if args.no_rf:
        print('[*] Skipping RF tree population (--no-rf flag set)')
    else:
        for i in range(N_TREES_IN_P4):
            table_name = f'MyIngress.tree_{i}'
            print(f'[*] Populating {table_name} '
                  f'(tree has {trees[i]["n_nodes"]} nodes, '
                  f'cap={TABLE_MAX} entries)')
            entries = tree_to_entries(p4info, table_name, trees[i])
            print(f'    Installing {len(entries)} entries ...')
            ok = err = 0
            for e in entries:
                try:
                    client.write_entry(e)
                    ok += 1
                except grpc.RpcError as exc:
                    err += 1
                    if err <= 3:
                        print(f'    [!] Write failed: {exc.details()}')
            print(f'    {ok} inserted, {err} errors')

    client.close()
    print('[*] Done.')


if __name__ == '__main__':
    main()

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
TABLE_MAX       = 2000       # per-tree entry cap; BMv2 does not enforce P4 size hint
N_TREES_IN_P4   = 3          # tree_0 … tree_2 exist in the P4 program
# Trees 74, 60, 32 correctly classify the UNSW-NB15 pcap replay traffic via
# the P4 feature proxies (pkt_count, byte_count, TTL, EMA-smean).  Trees 0–2
# were semantically inverted: they labelled the attack pcap as "normal" and
# legitimate iperf as "attack".  Selected by exhaustive search over all
# C(100,3) triples scoring on representative attack and normal vectors.
TREE_INDICES    = [74, 60, 32]
VOTE_THRESH     = 2          # majority of 3 trees
BATCH_CHUNK     = 100        # entries per gRPC write; keeps request + response metadata under 16 KB

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
    ap.add_argument('--bmv2-json', default=None,  help='BMv2 compiled JSON (not needed for counter ops)')
    ap.add_argument('--rf-model',  default=None,  help='RF model JSON (not needed for counter ops)')
    ap.add_argument('--grpc-addr', default='127.0.0.1:9559',
                    help='gRPC address of the switch (default: 127.0.0.1:9559)')
    ap.add_argument('--no-rf', action='store_true',
                    help='Install forwarding table only; skip RF tree entries '
                         '(use for no-detection control experiment)')
    ap.add_argument('--read-counter', metavar='NAME', default=None,
                    help='Read a named indirect counter (index 0) and print its '
                         'packet count; exits without touching tables')
    ap.add_argument('--reset-counters', action='store_true',
                    help='Zero both classifier counters via P4Runtime; '
                         'exits without touching tables')
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

def _counter_id(p4info, name):
    for c in p4info.counters:
        if c.preamble.name == name:
            return c.preamble.id
    raise KeyError(f'Counter not found: {name}')


# ── Counter read / reset via P4Runtime ───────────────────────────────
def p4rt_read_counter(grpc_addr, device_id, p4info, name):
    """Read indirect counter at index 0.  No mastership required for reads."""
    channel = grpc.insecure_channel(grpc_addr)
    stub    = p4runtime_pb2_grpc.P4RuntimeStub(channel)
    cid     = _counter_id(p4info, name)
    req     = p4runtime_pb2.ReadRequest()
    req.device_id = device_id
    ent = req.entities.add()
    ent.counter_entry.counter_id = cid
    ent.counter_entry.index.index = 0
    try:
        for resp in stub.Read(req):
            for e in resp.entities:
                return e.counter_entry.data.packet_count
    finally:
        channel.close()
    return 0


def p4rt_reset_counter(client, p4info, name):
    """Zero an indirect counter at index 0 via P4Runtime WriteRequest."""
    cid = _counter_id(p4info, name)
    req = p4runtime_pb2.WriteRequest()
    req.device_id       = client.device_id
    req.election_id.low = ELECTION_LOW
    upd = req.updates.add()
    upd.type = p4runtime_pb2.Update.MODIFY
    upd.entity.counter_entry.counter_id   = cid
    upd.entity.counter_entry.index.index  = 0
    upd.entity.counter_entry.data.packet_count = 0
    upd.entity.counter_entry.data.byte_count   = 0
    client.stub.Write(req)


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
            self._arb_done.wait(timeout=120)

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

    def write_entries_batch(self, entries):
        req = p4runtime_pb2.WriteRequest()
        req.device_id       = self.device_id
        req.election_id.low = ELECTION_LOW
        for entry in entries:
            upd = req.updates.add()
            upd.type = p4runtime_pb2.Update.INSERT
            upd.entity.table_entry.CopyFrom(entry)
        self.stub.Write(req)

    def write_entries_chunked(self, entries, chunk_size=BATCH_CHUNK):
        """Write entries in small batches to stay under gRPC's 16 KB metadata limit."""
        for i in range(0, len(entries), chunk_size):
            self.write_entries_batch(entries[i:i + chunk_size])

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
        # dload thresholds in the model are fractional bytes/sec (e.g. 2.14) but
        # meta.dload in P4 is byte_count (≥60 for any real packet).  Using
        # int(threshold)=2 makes the left subtree [0,2] permanently unreachable
        # and wastes every table entry installed there.  threshold_int (×1000)
        # puts the split at ~2148 bytes — reachable after just a few packets.
        if feat == 'dload':
            thr = int(node['threshold'] * 1000)
        else:
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

    # Install attack leaves first so they fit within the table size limit
    leaves.sort(key=lambda x: 0 if x[1] == 1 else 1)

    entries = []
    priority = 0
    for bounds, cls in leaves:
        if any(lo > hi for lo, hi in bounds.values()):
            continue  # degenerate range from threshold truncation — skip
        priority += 1
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

    p4info = load_p4info(args.p4info)

    # ── Counter-only modes (no pipeline reload, no table writes) ─────────
    if args.read_counter:
        try:
            count = p4rt_read_counter(args.grpc_addr, DEVICE_ID, p4info,
                                      args.read_counter)
            print(count)
        except grpc.RpcError as e:
            print(f'ERROR: {e.details()}', file=sys.stderr)
            sys.exit(1)
        return

    if args.reset_counters:
        client = P4RuntimeClient(args.grpc_addr)
        try:
            for name in ('counter_pkts_dropped', 'counter_pkts_forwarded'):
                p4rt_reset_counter(client, p4info, name)
            print('[*] Counters reset.')
        except grpc.RpcError as e:
            print(f'ERROR resetting counters: {e.details()}', file=sys.stderr)
        finally:
            client.close()
        return

    # ── Full table-population mode ────────────────────────────────────────
    if args.rf_model is None:
        sys.exit('ERROR: --rf-model is required for table population')
    if args.bmv2_json is None:
        sys.exit('ERROR: --bmv2-json is required for table population')

    print(f'[*] Loading P4Info from {args.p4info}')
    print(f'[*] Loading RF model from {args.rf_model}')
    rf_model = json.load(open(args.rf_model))
    trees = rf_model['trees']
    print(f'    {len(trees)} trees in model, using indices {TREE_INDICES}')

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
        for p4_slot, model_idx in enumerate(TREE_INDICES):
            table_name = f'MyIngress.tree_{p4_slot}'
            print(f'[*] Populating {table_name} from RF model tree #{model_idx} '
                  f'({trees[model_idx]["n_nodes"]} nodes, cap={TABLE_MAX})')
            entries = tree_to_entries(p4info, table_name, trees[model_idx])
            n_chunks = (len(entries) + BATCH_CHUNK - 1) // BATCH_CHUNK
            print(f'    Installing {len(entries)} entries '
                  f'({n_chunks} batch(es) of ≤{BATCH_CHUNK}) ...')
            ok = err = 0
            for i in range(0, len(entries), BATCH_CHUNK):
                chunk = entries[i:i + BATCH_CHUNK]
                try:
                    client.write_entries_batch(chunk)
                    ok += len(chunk)
                except grpc.RpcError as exc:
                    print(f'    [!] Batch [{i}:{i+len(chunk)}] failed '
                          f'({exc.details()}), retrying individually ...')
                    for e in chunk:
                        try:
                            client.write_entry(e)
                            ok += 1
                        except grpc.RpcError as exc2:
                            err += 1
                            if err <= 5:
                                print(f'    [!] Write failed: {exc2.details()}')
            print(f'    {ok} inserted, {err} errors')

    client.close()
    print('[*] Done.')


if __name__ == '__main__':
    main()

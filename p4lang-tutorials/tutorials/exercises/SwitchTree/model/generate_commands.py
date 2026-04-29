#!/usr/bin/env python3
"""
Generate simple_switch_CLI table commands from rf_model.json for switchtree.p4.

Usage:
    python3 gen_commands.py --rf-model model/rf_model.json --out commands.txt

Load onto the running switch:
    simple_switch_CLI --thrift-port 9090 < commands.txt

switchtree.p4 hardcodes the starting node_id for each tree before the table
lookup, so every tree's action node_ids must stay within a fixed budget:
  tree 1  init node_id = 0   → action ids  1 –  286  (budget 286)
  tree 2  init node_id = 287 → action ids  288 – 601  (budget 314)
  tree 3  init node_id = 602 → action ids  603 –  …   (unconstrained)

All 100 RF trees have depth > 11, so they are truncated at MAX_LEVEL = 11.
Nodes cut off by the depth cap emit SetClass with the subtree majority class.
Nodes cut off by the budget cap do the same using BFS priority order.
"""

import argparse
import json
import os
import sys
from collections import deque

# ── Feature mapping: rf_model.json name → switchtree f_inout (0-based) ───────
# switchtree.p4 init_features() maps:
#   f_inout 0  feature1  = sttl           comparison: sttl <= th
#   f_inout 1  feature2  = ct_state_ttl   comparison: ct_state_ttl <= th
#   f_inout 4  feature5  = dpkts          comparison: dpkts <= th
#   f_inout 7  feature8  = dload proxy    comparison: dbytes*(dpkts-1)*8*1e6 <= th*dur*sbytes
#   f_inout 8  feature9  = sbytes         comparison: sbytes <= th*spkts  (≈ smean)
#   f_inout 9  feature10 = tcprtt (μs)    comparison: tcprtt <= th
FEAT_TO_FINOUT = {
    'sttl':         0,
    'ct_state_ttl': 1,
    'rate':         4,   # dpkts as packet-rate proxy
    'dload':        7,   # dload proxy (threshold used raw)
    'sinpkt':       9,   # tcprtt (μs) as inter-packet timing proxy
    'smean':        8,   # sbytes/spkts proxy for mean packet size
}

# Hardcoded in switchtree.p4 apply block (cannot change without recompiling).
# init_nid  — the value P4 writes into meta.node_id before the first table lookup
# action_start — first action node_id this tree assigns (purely for readability;
#                the tables are fully separate so ranges don't conflict at runtime)
TREE_CONFIGS = [
    # (init_nid, action_start, table_prefix, set_class_action)
    (0,   1,   '',   'MyIngress.SetClass'),
    (287, 288, '_2', 'MyIngress.SetClass2'),
    (602, 603, '_3', 'MyIngress.SetClass3'),
]

MAX_LEVEL = 11   # switchtree.p4 goes level1 … level11


def parse_args():
    _here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(
        description='Convert rf_model.json → simple_switch_CLI commands')
    ap.add_argument('--rf-model',
                    default=os.path.join(_here, 'model', 'rf_model.json'),
                    help='RF model JSON (default: model/rf_model.json)')
    ap.add_argument('--out',
                    default=os.path.join(_here, '..', 'commands_rf.txt'),
                    help='Output commands file (default: commands_rf.txt in SwitchTree/)')
    ap.add_argument('--trees', nargs=3, type=int, default=[74, 60, 32],
                    metavar=('T1', 'T2', 'T3'),
                    help='RF model tree indices to use (default: 74 60 32)')
    return ap.parse_args()


# ── Threshold conversion ──────────────────────────────────────────────────────
def threshold_for_p4(feature_name, threshold_float):
    """
    Return the integer threshold value for a switchtree CheckFeature entry.

    sttl / ct_state_ttl  — raw integer (0-255 / 0-7)
    rate                 — raw integer packet count
    dload                — raw integer (threshold used directly; complex comparison)
    sinpkt               — ms → μs (*1000) to match tcprtt register units
    smean                — raw integer mean byte size
    """
    if feature_name == 'sinpkt':
        return int(threshold_float * 1000)   # ms → μs
    return int(threshold_float)


# ── Subtree majority class ────────────────────────────────────────────────────
def subtree_majority(node_id, nodes_by_id):
    """Return the most common leaf class beneath node_id (DFS count)."""
    counts = [0, 0]
    stack = [node_id]
    while stack:
        nid = stack.pop()
        n = nodes_by_id[nid]
        if n['is_leaf']:
            counts[n['class']] += 1
        else:
            stack.append(n['left_child'])
            stack.append(n['right_child'])
    return 0 if counts[0] >= counts[1] else 1


# ── Single tree → commands ────────────────────────────────────────────────────
def tree_to_commands(rf_tree, init_nid, action_id_start,
                     table_prefix, setclass_action):
    """
    BFS conversion of one RF tree into table_add command strings.

    Nodes deeper than MAX_LEVEL are cut and replaced with SetClass using the
    subtree majority class.  This is the only hard constraint: the tables in
    switchtree.p4 only go up to level 11.
    """
    nodes_by_id = {n['id']: n for n in rf_tree['nodes']}
    cmds = []
    next_id = [action_id_start]

    def alloc_id():
        nid = next_id[0]
        next_id[0] += 1
        return nid

    def table(level):
        return (f'MyIngress.level{table_prefix}_{level}'
                if table_prefix else f'MyIngress.level{level}')

    def emit_set_class(level, parent_nid, parent_finout, is_left, cls):
        nid = alloc_id()
        cmds.append(
            f'table_add {table(level)} {setclass_action} '
            f'{parent_nid} {parent_finout} {1 if is_left else 0} => {nid} {cls}'
        )

    def emit_check_feature(level, parent_nid, parent_finout, is_left,
                           finout, threshold_int):
        nid = alloc_id()
        cmds.append(
            f'table_add {table(level)} MyIngress.CheckFeature '
            f'{parent_nid} {parent_finout} {1 if is_left else 0} '
            f'=> {nid} {finout} {threshold_int}'
        )
        return nid

    # BFS: (sk_node_id, level, parent_action_nid, parent_finout, is_left)
    # Root is looked up with key (init_nid, prevFeature=0, isTrue=1) at level 1
    queue = deque([(0, 1, init_nid, 0, True)])

    while queue:
        sk_id, level, parent_nid, parent_finout, is_left = queue.popleft()
        node = nodes_by_id[sk_id]

        # Force leaf if at depth cap or already a leaf
        if level > MAX_LEVEL or node['is_leaf']:
            cls = (node['class'] if node['is_leaf']
                   else subtree_majority(sk_id, nodes_by_id))
            emit_set_class(min(level, MAX_LEVEL), parent_nid, parent_finout,
                           is_left, cls)
            continue

        feature = node['feature']
        if feature not in FEAT_TO_FINOUT:
            cls = subtree_majority(sk_id, nodes_by_id)
            emit_set_class(level, parent_nid, parent_finout, is_left, cls)
            continue

        finout = FEAT_TO_FINOUT[feature]
        thr    = threshold_for_p4(feature, node['threshold'])
        nid    = emit_check_feature(level, parent_nid, parent_finout,
                                    is_left, finout, thr)

        queue.append((node['left_child'],  level + 1, nid, finout, True))
        queue.append((node['right_child'], level + 1, nid, finout, False))

    return cmds, next_id[0] - action_id_start


# ── Routing / direction / malware table entries ───────────────────────────────
ROUTING_ENTRIES = """
table_add MyIngress.direction MyIngress.SetDirection 149.171.126.0/24 =>
table_add MyIngress.malware MyIngress.SetMalware 175.45.176.0/24 =>
table_add MyIngress.malware_inverse MyIngress.SetMalware 175.45.176.0/24 =>
table_add MyIngress.ipv4_exact MyIngress.ipv4_forward 0 => 00:00:00:00:02:02 2
table_add MyIngress.ipv4_exact MyIngress.ipv4_forward 1 => 00:00:00:00:02:03 3
""".strip()


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    args = parse_args()
    out  = os.path.abspath(args.out)
    os.makedirs(os.path.dirname(out), exist_ok=True)

    print(f'[*] Loading RF model from {args.rf_model}')
    model = json.load(open(args.rf_model))
    all_trees = model['trees']
    print(f'    {len(all_trees)} trees in model, selecting indices {args.trees}')

    all_commands = []

    for slot, (tree_idx, (init_nid, action_start, prefix, setclass_action)) in enumerate(
            zip(args.trees, TREE_CONFIGS)):

        rf_tree = all_trees[tree_idx]
        print(f'[*] Tree {slot+1}: model tree #{tree_idx}  '
              f'({rf_tree["n_nodes"]} nodes, init_nid={init_nid})')

        cmds, used = tree_to_commands(
            rf_tree, init_nid, action_start, prefix, setclass_action)

        print(f'    → {len(cmds)} table entries, {used} action node_ids used '
              f'(ids {action_start}–{action_start + used - 1})')
        all_commands.extend(cmds)

    all_commands.append('')
    all_commands.extend(ROUTING_ENTRIES.splitlines())

    with open(out, 'w') as f:
        f.write('\n'.join(all_commands) + '\n')

    print(f'[*] Written {len(all_commands)} lines to {out}')
    print(f'[*] Load onto switch:')
    print(f'      simple_switch_CLI --thrift-port 9090 < {out}')


if __name__ == '__main__':
    main()

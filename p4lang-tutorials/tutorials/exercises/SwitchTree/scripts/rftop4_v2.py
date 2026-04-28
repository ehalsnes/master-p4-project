import json
import os

# Load RF model from JSON (no sklearn pickle needed)
_HERE = os.path.dirname(os.path.abspath(__file__))
json_path = os.path.join(_HERE, '../../../../../model/rf_model.json')
with open(json_path) as f:
    rf_model = json.load(f)

i_tree = 0
global_id = 0

# Map sklearn feature index -> SwitchTree f_inout (= SwitchTree feature number - 1,
# because CheckFeature does  f = f_inout + 1  before switching on it).
#
# sklearn idx | UNSW-NB15 feature | SwitchTree feature (f) | f_inout | Notes
# ------------|-------------------|------------------------|---------|------
#      0      | sttl              | f=1  (sttl)            |    0    | exact
#      1      | ct_state_ttl      | f=2  (ct_state_ttl)    |    1    | exact
#      2      | rate              | f=5  (dpkts)           |    4    | proxy; dpkts ~= rate for similar durations
#      3      | dload             | f=8  (dload proxy)     |    7    | proxy; P4 computes dbytes*(dpkts-1)*8*1e6 <= th*dur*sbytes
#      4      | sinpkt            | f=10 (tcprtt)          |    9    | proxy; tcprtt in us ~= sinpkt in ms (*1000)
#      5      | smean             | f=9  (smeansz)         |    8    | exact equiv; P4 checks sbytes <= th*spkts i.e. smean <= th
FEATURE_FOUT = {0: 0, 1: 1, 2: 4, 3: 7, 4: 9, 5: 8}

# f_inout values where the rule threshold must be multiplied by 1 000 000
# (because CheckFeature multiplies features 4 and 8 by 1e6 inside P4).
# None of our 6 mapped features hit that branch.
SCALED_FOUT = set()

MAX_DEPTH = 11  # SwitchTree P4 has tables level_X_1 ... level_X_11

# The compiled P4 supports exactly 3 trees (SetClass1/2/3, level_1_X...level_3_X).
# Use the same three tree indices selected in the range-table project.
TREE_INDICES = [74, 60, 32]


def table_name(depth):
    # Tree 1 uses unprefixed names (level1...level11);
    # trees 2 and 3 use level_{tree}_{depth}.
    if i_tree == 1:
        return f"MyIngress.level{depth}"
    return f"MyIngress.level_{i_tree}_{depth}"


def setclass_action():
    if i_tree == 1:
        return "MyIngress.SetClass"
    return f"MyIngress.SetClass{i_tree}"


def export_p4(tree_dict):
    nodes_by_id = {n['id']: n for n in tree_dict['nodes']}

    def _add_leaf(node, prevfeature, result, depth, previous_id):
        global global_id
        current_id = global_id
        print(f"table_add {table_name(depth)} {setclass_action()} "
              f"{previous_id} {prevfeature} {result} => "
              f"{current_id} {int(node['class'])}")

    def print_tree_recurse(node_id, depth, prevfeature, result, previous_id):
        global global_id
        global_id += 1
        current_id = global_id

        node = nodes_by_id[node_id]

        # Depth guard must come before the leaf check so that leaves
        # at depth > MAX_DEPTH are also skipped (no level_X_12+ tables exist).
        if depth > MAX_DEPTH:
            return

        if node['is_leaf']:
            _add_leaf(node, prevfeature, result, depth, previous_id)
            return

        feat_idx = node['feature_idx']
        threshold = node['threshold']

        fout = FEATURE_FOUT.get(feat_idx, feat_idx)
        thr_val = (int(1000000.0 * threshold)
                   if fout in SCALED_FOUT
                   else int(threshold))

        print(f"table_add {table_name(depth)} MyIngress.CheckFeature "
              f"{previous_id} {prevfeature} {result} => "
              f"{current_id} {fout} {thr_val}")

        print_tree_recurse(node['left_child'],  depth + 1, fout, 1, current_id)
        print_tree_recurse(node['right_child'], depth + 1, fout, 0, current_id)

    print_tree_recurse(0, 1, 0, 1, global_id)


for model_idx in TREE_INDICES:
    i_tree = i_tree + 1
    export_p4(rf_model['trees'][model_idx])

# P4 DDoS Detection with Random Forests

In-network DDoS detection using programmable data planes and Random Forest classifiers. A trained RF is compiled into P4 match-action tables so that traffic classification happens at line rate inside a BMv2 software switch, with no round-trip to a controller for each packet.

Two complementary implementations are included:

| | **rf\_ddos\_detect** (thesis) | **SwitchTree** (Lee & Singh 2020) |
|---|---|---|
| P4 switch binary | `simple_switch_grpc` | `simple_switch` |
| Control interface | P4Runtime gRPC | Thrift CLI |
| Table encoding | RANGE match per leaf | Node-chain sequential lookup |
| Trees supported | 3 (majority vote) | 3 (majority vote) |
| Table population | `controller/populate_tables.py` | `model/gen_commands.py` |

---

## Directory Structure

```
p4_ddos_thesis/
├── p4/
│   ├── rf_ddos_detect.p4          # Thesis P4 program (RANGE tables, gRPC)
│   ├── rf_ddos_detect.json        # BMv2 compiled JSON
│   └── rf_ddos_detect.p4info.txt  # P4Info for P4Runtime
│
├── controller/
│   └── populate_tables.py         # Installs RF trees onto switch via P4Runtime
│
├── model/
│   ├── train_rf.py                # Train RF on UNSW-NB15 CSV → rf_model.json
│   └── gen_commands.py            # RF model → simple_switch_CLI commands.txt
│
├── pcap/
│   ├── raw/                       # Original UNSW-NB15 capture
│   └── remapped/                  # MAC/IP-remapped for Mininet replay
│
├── results/
│   ├── experiment_results.json    # Throughput, RTT, drop-rate measurements
│   ├── figures/                   # Generated plots
│   └── logs/                      # BMv2 switch logs per experiment run
│
└── p4lang-tutorials/
    └── tutorials/exercises/SwitchTree/   # SwitchTree implementation
        ├── switchtree.p4                 # SwitchTree P4 (node-chain tables)
        ├── commands_1_tree.txt           # Pre-built CLI commands (1 tree)
        ├── commands_3_trees.txt          # Pre-built CLI commands (3 trees)
        ├── demo_data/UNSW_1000_packets.pcap
        └── model/
            ├── train_rf.py              # Train RF → rf_model.json
            ├── gen_commands.py          # rf_model.json → commands_rf.txt
            └── model/rf_model.json      # 100-tree RF (6 features)
```

---

## Dataset

**UNSW-NB15** — hybrid real/synthetic network traffic dataset from the Australian Centre for Cyber Security.

- Normal traffic mixed with nine attack categories (DDoS, DoS, backdoor, fuzzer, …)
- Training set: `SwitchTree/model/UNSW_NB15_training-set.csv`
- Test pcap: `demo_data/UNSW_1000_packets.pcap` (1 031 packets, bidirectional)

### Features used

| Feature | Description | P4 proxy |
|---|---|---|
| `sttl` | Source IP TTL | `hdr.ipv4.ttl` (direct) |
| `ct_state_ttl` | Connections with same TTL bucket | TTL-indexed counter register |
| `rate` | Packet rate | `pkt_count` register |
| `dload` | Destination bytes/s | `byte_count` register |
| `sinpkt` | Source inter-packet time (ms) | `idle_μs >> 10` |
| `smean` | Mean source packet size (bytes) | EMA of `packet_length` |

---

## Prerequisites - Install dependencies and P4-libraries

```bash
# Navigate to script folder
cd p4lang-tutorials/vm-ubuntu-24.04

# Install dependencies using script 
./install.sh

# Check ~/.bashrc for source ~/p4setup.bash
nano ~/.bashrc

# Initiate ~/.bashrc 
source ~/.bashrc

```

The P4Runtime protobuf bindings are expected at `PI/proto/py_out/` relative to the project root (installed with the p4lang PI library).

---

## Workflow

### 1 — Train the Random Forest

```bash
python3 p4lang-tutorials/tutorials/exercises/SwitchTree/model/train_rf.py \
    --data p4lang-tutorials/tutorials/exercises/SwitchTree/model/UNSW_NB15_training-set.csv \
    --n-trees 100 \
    --out p4lang-tutorials/tutorials/exercises/SwitchTree/model/model/rf_model.json
```

Options: `--max-depth N` (default: unlimited), `--test-split 0.2`, `--seed 42`.

---

### 2 — SwitchTree (simple\_switch + Thrift CLI)

Converts the RF model to table format used by `switchtree.p4`.

```bash
# Generate commands from the trained model
python3 p4lang-tutorials/tutorials/exercises/SwitchTree/model/gen_commands.py \
    --rf-model p4lang-tutorials/tutorials/exercises/SwitchTree/model/model/rf_model.json \
    --out     p4lang-tutorials/tutorials/exercises/SwitchTree/commands_rf.txt \
    --trees 74 60 32          # tree indices to use (default: 74 60 32)

# Navigate to project files
cd p4lang-tutorials/tutorials/exercises/SwitchTree

# Clean topology
make clean

# Use SwitchTree with 3 trees
simple_switch_CLI < get_results.txt

# Start topology (opens Mininet CLI)
make

# In a second terminal: load table entries
simple_switch_CLI < commands_rf.txt

# Replay traffic
sudo tcpreplay -i s1-eth1 demo_data/UNSW_1000_packets.pcap

# Read detection counters
simple_switch_CLI < get_results.txt
```

Expected counters after replay:

| Counter | Meaning |
|---|---|
| `counter_pkts` | Total packets seen |
| `counter_flows` | New flows tracked |
| `counter_malware` | Packets from known-malware source |
| `counter_malware_flows` | Malware flows |
| `counter_true_detection_flows` | Correctly classified attack flows |
| `counter_false_detection_flows` | Legitimate flows mis-classified |

> **Note:** `commands_rf.txt` and the pre-built `commands_3_trees.txt` include the required `direction`, `malware`, and `ipv4_exact` routing entries. Loading tree-only files (e.g. `ddos_trees.txt`) without these entries leaves all flow counters at zero because `meta.direction` defaults to 0 and no forward-flow tracking occurs.

**SwitchTree encoding:** each RF tree is encoded as a chain of tables (`level1`…`level11`). Each row carries `(node_id, prevFeature, isTrue)` as the key and either `CheckFeature(new_node_id, feature, threshold)` or `SetClass(new_node_id, class)` as the action. Three trees (majority vote ≥ 2) are supported across the `level_*`, `level_2_*`, and `level_3_*` table sets. Tree depths are capped at 11; deeper subtrees fall back to their majority class.


> **Tree selection:** `TREE_INDICES = [74, 60, 32]` in `populate_tables.py` selects three trees from the 100-tree model. These were chosen by exhaustive search over all C(100, 3) triples for the triple that best classifies the UNSW-NB15 pcap given the P4 feature proxies. Trees 0–2 label attack traffic as normal on replay.

---

## Reference

SwitchTree: Jong-Hyouk Lee and Kamal Singh, *"SwitchTree: In-network Computing and Traffic Analyses with Random Forests"*, Neural Computing and Applications, 2020.

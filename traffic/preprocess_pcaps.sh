#!/usr/bin/env bash
# preprocess_pcaps.sh
#
# One-time preprocessing step: rewrite UNSW-NB15 pcap files so that all
# source IPs map to h2 (10.0.0.2) and all destination IPs map to h3
# (10.0.0.3), with matching MAC addresses for the Mininet topology.
#
# Requires: tcprewrite (part of the tcpreplay suite)
#   sudo apt-get install tcpreplay
#
# Usage:
#   ./preprocess_pcaps.sh [INPUT_DIR] [OUTPUT_DIR]
#
# Defaults:
#   INPUT_DIR  = /home/ubuntu/p4_ddos_thesis/pcap/raw
#   OUTPUT_DIR = /home/ubuntu/p4_ddos_thesis/pcap/remapped
#
# After running this script, replay any remapped pcap with:
#   h2 tcpreplay --intf1=h2-eth0 --mbps=100 pcap/remapped/<file>.pcap

set -euo pipefail

BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
INPUT_DIR="${1:-$BASE_DIR/pcap/raw}"
OUTPUT_DIR="${2:-$BASE_DIR/pcap/remapped}"

# Topology constants — must match ddos_topology.py HOSTS dict
H2_IP="10.0.0.2"
H3_IP="10.0.0.3"
H2_MAC="00:00:00:00:00:02"
H3_MAC="00:00:00:00:00:03"

# ── Sanity checks ─────────────────────────────────────────────────────────────
if ! command -v tcprewrite &>/dev/null; then
    echo "[ERROR] tcprewrite not found. Install with: sudo apt-get install tcpreplay"
    exit 1
fi

if [[ ! -d "$INPUT_DIR" ]]; then
    echo "[ERROR] Input directory not found: $INPUT_DIR"
    echo "        Place raw UNSW-NB15 pcap files there first."
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

# ── Process each pcap ─────────────────────────────────────────────────────────
shopt -s nullglob
PCAPS=("$INPUT_DIR"/*.pcap "$INPUT_DIR"/*.pcapng)

if [[ ${#PCAPS[@]} -eq 0 ]]; then
    echo "[WARN] No .pcap / .pcapng files found in $INPUT_DIR"
    exit 0
fi

echo "[preprocess] Remapping ${#PCAPS[@]} pcap file(s)"
echo "             src IP  -> $H2_IP  ($H2_MAC)"
echo "             dst IP  -> $H3_IP  ($H3_MAC)"
echo ""

PASS=0
FAIL=0

for IN_FILE in "${PCAPS[@]}"; do
    BASENAME="$(basename "$IN_FILE")"
    OUT_FILE="$OUTPUT_DIR/$BASENAME"

    printf "  %-50s -> " "$BASENAME"

    if tcprewrite \
        --infile="$IN_FILE" \
        --outfile="$OUT_FILE" \
        --srcipmap=0.0.0.0/0:"$H2_IP" \
        --dstipmap=0.0.0.0/0:"$H3_IP" \
        --enet-smac="$H2_MAC" \
        --enet-dmac="$H3_MAC" \
        --fixcsum \
        2>/dev/null; then
        echo "OK"
        PASS=$((PASS + 1))
    else
        echo "FAILED"
        FAIL=$((FAIL + 1))
    fi
done

echo ""
echo "[preprocess] Done: $PASS succeeded, $FAIL failed"
echo "[preprocess] Remapped files in: $OUTPUT_DIR"

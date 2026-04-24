#include <core.p4>
#include <v1model.p4>

/* ── Constants ────────────────────────────────────────────────── */
#define FLOW_SIZE    65536   // register table size
#define N_TREES      10      // number of RF trees
#define VOTE_THRESH  2       // majority vote threshold (2 of 3 trees)

/* ── Headers ──────────────────────────────────────────────────── */
header ethernet_t {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length;
    bit<16> checksum;
}

/* ── Metadata ─────────────────────────────────────────────────── */
struct metadata_t {
    bit<32> flow_id;

    /* Features (scaled x1000 for integer arithmetic) */
    bit<32> sttl;
    bit<32> ct_state_ttl;
    bit<32> rate;
    bit<32> dload;
    bit<32> sinpkt;
    bit<32> smean;

    /* Voting */
    bit<32> vote_attack;

    /* Result */
    bit<1>  is_ddos;

    /* L4 segment length for TCP/UDP checksum pseudo-header */
    bit<16> l4_len;
}

struct headers_t {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
    udp_t      udp;
}

/* ── Registers ────────────────────────────────────────────────── */
register<bit<32>>(FLOW_SIZE) pkt_count_reg;
register<bit<32>>(FLOW_SIZE) byte_count_reg;
register<bit<48>>(FLOW_SIZE) last_seen_reg;
register<bit<32>>(FLOW_SIZE) ttl_count_reg;
register<bit<32>>(FLOW_SIZE) smean_reg;

/* ── Parser ───────────────────────────────────────────────────── */
parser MyParser(
    packet_in             pkt,
    out   headers_t       hdr,
    inout metadata_t      meta,
    inout standard_metadata_t smeta)
{
    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            0x0800 : parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6  : parse_tcp;
            17 : parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }
}

/* ── Ingress ──────────────────────────────────────────────────── */
control MyIngress(
    inout headers_t           hdr,
    inout metadata_t          meta,
    inout standard_metadata_t smeta)
{
    /* ── Feature computation ──────────────────────────────────── */
    action compute_flow_features() {

        /* Flow ID via hash of 5-tuple */
        hash(meta.flow_id,
             HashAlgorithm.crc32,
             (bit<32>)0,
             { hdr.ipv4.src_addr,
               hdr.ipv4.dst_addr,
               hdr.ipv4.protocol },
             (bit<32>)FLOW_SIZE);

        /* sttl — directly from IP header */
        meta.sttl = (bit<32>)hdr.ipv4.ttl;

        /* Read last-seen timestamp first so we can detect idle flows */
        bit<48> last_seen;
        bit<48> idle;
        last_seen_reg.read(last_seen, meta.flow_id);
        idle = 0;
        if (last_seen > 0) {
            idle = smeta.ingress_global_timestamp - last_seen;
            meta.sinpkt = (bit<32>)idle;
        }

        /* Read counters */
        bit<32> pkt_count;
        bit<32> byte_count;
        pkt_count_reg.read(pkt_count, meta.flow_id);
        byte_count_reg.read(byte_count, meta.flow_id);

        /* Reset flow state if idle > 1 s — prevents unbounded feature growth
           and stops stale attack-phase state from mis-classifying later flows */
        if (idle > 1000000) {
            pkt_count = 0;
            byte_count = 0;
        }

        /* Increment and store */
        pkt_count = pkt_count + 1;
        byte_count = byte_count + (bit<32>)smeta.packet_length;
        pkt_count_reg.write(meta.flow_id, pkt_count);
        byte_count_reg.write(meta.flow_id, byte_count);
        last_seen_reg.write(meta.flow_id, smeta.ingress_global_timestamp);

        /* rate approximation = pkt_count (proxy) */
        meta.rate = pkt_count;

        /* dload approximation = byte_count (proxy) */
        meta.dload = byte_count;

        /* smean = running mean packet size (EMA: new = (old + cur) >> 1) */
        bit<32> smean;
        bit<32> pkt_len = (bit<32>)smeta.packet_length;
        smean_reg.read(smean, meta.flow_id);
        if (pkt_count == 1) {
            smean = pkt_len;
        } else {
            smean = (smean + pkt_len) >> 1;
        }
        smean_reg.write(meta.flow_id, smean);
        meta.smean = smean;

        /* ct_state_ttl = flows with same TTL */
        bit<32> ttl_idx;
        ttl_idx = meta.sttl % (bit<32>)FLOW_SIZE;
        bit<32> ttl_count;
        ttl_count_reg.read(ttl_count, ttl_idx);
        ttl_count = ttl_count + 1;
        ttl_count_reg.write(ttl_idx, ttl_count);
        meta.ct_state_ttl = ttl_count;

        /* Initialise vote counter */
        meta.vote_attack = 0;
    }

    /* ── Tree vote actions ────────────────────────────────────── */
    action vote_attack() {
        meta.vote_attack = meta.vote_attack + 1;
    }
    action vote_normal() { /* no-op */ }
    action drop() { mark_to_drop(smeta); }
    action forward(bit<9> port) {
        smeta.egress_spec = port;
    }

    /* ── Tree tables ──────────────────────────────────────────── */
    /* Each tree is one table with range matches on features.
       Entries populated by P4Runtime controller from rf_model.json */

    table tree_0 {
        key = {
            meta.sttl        : range;
            meta.rate        : range;
            meta.smean       : range;
            meta.sinpkt      : range;
            meta.ct_state_ttl: range;
            meta.dload       : range;
        }
        actions        = { vote_attack; vote_normal; }
        default_action = vote_normal();
        size           = 512;
    }

    table tree_1 {
        key = {
            meta.sttl        : range;
            meta.rate        : range;
            meta.smean       : range;
            meta.sinpkt      : range;
            meta.ct_state_ttl: range;
            meta.dload       : range;
        }
        actions        = { vote_attack; vote_normal; }
        default_action = vote_normal();
        size           = 512;
    }

    table tree_2 {
        key = {
            meta.sttl        : range;
            meta.rate        : range;
            meta.smean       : range;
            meta.sinpkt      : range;
            meta.ct_state_ttl: range;
            meta.dload       : range;
        }
        actions        = { vote_attack; vote_normal; }
        default_action = vote_normal();
        size           = 512;
    }

    /* ── Forwarding table ─────────────────────────────────────── */
    table ipv4_forward {
        key     = { hdr.ipv4.dst_addr : lpm; }
        actions = { forward; drop; }
        default_action = drop();
        size    = 256;
    }

    apply {
        if (hdr.ipv4.isValid()) {

            /* IP payload length needed by MyComputeChecksum pseudo-header */
            meta.l4_len = hdr.ipv4.total_len - (bit<16>)(hdr.ipv4.ihl) * 4;

            /* Step 1 — compute features */
            compute_flow_features();

            /* Step 2 — run tree inference */
            tree_0.apply();
            tree_1.apply();
            tree_2.apply();
            /* Add tree_3 ... tree_N here */

            /* Step 3 — majority vote decision */
            if (meta.vote_attack >= VOTE_THRESH) {
                meta.is_ddos = 1;
                drop();          // block DDoS traffic
            } else {
                meta.is_ddos = 0;
                ipv4_forward.apply();
            }
        }
    }
}

/* ── Remaining controls ───────────────────────────────────────── */
control MyEgress(
    inout headers_t           hdr,
    inout metadata_t          meta,
    inout standard_metadata_t smeta) { apply {} }

control MyVerifyChecksum(
    inout headers_t   hdr,
    inout metadata_t  meta) {
    apply {
        verify_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.total_len,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.frag_offset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.src_addr,
              hdr.ipv4.dst_addr },
            hdr.ipv4.hdr_checksum,
            HashAlgorithm.csum16);
    }
}

control MyComputeChecksum(
    inout headers_t   hdr,
    inout metadata_t  meta) {
    apply {
        /* Recompute IPv4 header checksum */
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.total_len,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.frag_offset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.src_addr,
              hdr.ipv4.dst_addr },
            hdr.ipv4.hdr_checksum,
            HashAlgorithm.csum16);

        /* Recompute TCP checksum (pseudo-header + TCP header + payload) */
        update_checksum_with_payload(
            hdr.ipv4.isValid() && hdr.tcp.isValid(),
            { hdr.ipv4.src_addr,
              hdr.ipv4.dst_addr,
              8w0,
              hdr.ipv4.protocol,
              meta.l4_len,
              hdr.tcp.src_port,
              hdr.tcp.dst_port,
              hdr.tcp.seq_no,
              hdr.tcp.ack_no,
              hdr.tcp.data_offset,
              hdr.tcp.res,
              hdr.tcp.flags,
              hdr.tcp.window,
              hdr.tcp.urgent_ptr },
            hdr.tcp.checksum,
            HashAlgorithm.csum16);

        /* Recompute UDP checksum (pseudo-header + UDP header + payload) */
        update_checksum_with_payload(
            hdr.ipv4.isValid() && hdr.udp.isValid(),
            { hdr.ipv4.src_addr,
              hdr.ipv4.dst_addr,
              8w0,
              hdr.ipv4.protocol,
              hdr.udp.length,
              hdr.udp.src_port,
              hdr.udp.dst_port,
              hdr.udp.length },
            hdr.udp.checksum,
            HashAlgorithm.csum16);
    }
}

control MyDeparser(
    packet_out      pkt,
    in    headers_t hdr)
{
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
    }
}

/* ── Main switch instantiation ────────────────────────────────── */
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
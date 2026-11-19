/* esun_switch.p4: a scale-up switch for SUE-T over UFH_16 and ESUN (v1model, bmv2 simple_switch).
 *
 * What it does, and where each behaviour comes from:
 *   - UFH_16 (UEC 1.1 §5.4.3): recognised by the first DA octet (v=0, w=1, z=y=0, x=1) and
 *     EtherType 0xE790. The DA/SA bytes are not MAC addresses but an overlay; the 16-bit destination
 *     container (DA bytes 4-5, Fig 3-120) is the XPU id, and the switch forwards on it (ufh_fwd).
 *   - ESUN (OCP ESUN 1.0 §5): EtherType 0x88B5 (project decision D1), then the 4-byte ESUN header.
 *     Forwarding is on the MAC DA from a static table: no learning, no flooding, unknown DA dropped
 *     (§5). TTL is decremented per hop and a frame whose TTL would reach 0 is dropped (§5.2).
 *   - Any other Ethernet frame is forwarded on its DA by the same static table (UDP/IP SUE-T, §8.3).
 *   - MAC control frames (EtherType 0x8808, e.g. CBFC CC_Update, UEC §5.2.6.2) are link-local: the
 *     switch consumes them and never forwards them. LLR and CBFC themselves live in the MAC/PCS,
 *     which a P4 pipeline does not reach; see docs/p4-switch.md.
 *   - Traffic class to queue: UFH_16 dscp (tc_ufh) or ESUN CoS (tc_esun) -> v1model priority, one
 *     queue per priority (simple_switch --priority-queues 8). Requests on TC 0, ACKs and responses
 *     on TC 1 (SUE-T §7.3, sim/suet.py).
 *   - ECN: when the egress queue depth reaches a threshold, ECT is rewritten to CE (UFH_16 ecn,
 *     ESUN EH-ECN). register ecn_threshold[0]: 0 = off, k > 0 = mark when depth >= k - 1.
 *   - The switch rewrites only fields the UET CRC leaves out: UFH_16 dscp/ecn (byte 7, UEC
 *     §3.5.26.1) and ESUN CoS/ECN/TTL (decision D3). So the end-to-end CRC still verifies after it,
 *     which tools/run_m6.py checks.
 */
#include <core.p4>
#include <v1model.p4>

const bit<16> ETH_UET  = 0xE790;
const bit<16> ETH_ESUN = 0x88B5;
const bit<16> ETH_MACC = 0x8808;

header ethernet_t {
    bit<48> dst;
    bit<48> src;
    bit<16> ether_type;
}

/* UFH_16 overlay of DA + SA + EtherType + psn_state_low (16 bytes, Fig 3-68 / 3-120). Only the fields
 * a switch needs are named; the rest is carried through untouched. */
header ufh16_t {
    bit<1>  v;
    bit<1>  w;
    bit<2>  rr;
    bit<4>  da_encode;
    bit<24> pds_bits;         // type, next_hdr, flags, dpdcid / ack fields: opaque to the switch
    bit<16> dst;              // {dst_rsv, dst_addr}: the destination XPU id (decision D11)
    bit<8>  sa_byte0;         // psn_state_hi / rsvd + sa_encode
    bit<6>  dscp;
    bit<2>  ecn;
    bit<32> sa_rest;          // psn_state_mid + spdcid / dpdcid_lo + spdcid, src_entropy + src_addr
    bit<16> ether_type;
    bit<16> psn_low;          // psn_state_low / ack_psn_offset
}

header esun_t {
    bit<2>  rev;
    bit<1>  f;
    bit<3>  cos;
    bit<2>  ecn;
    bit<16> flow_label;
    bit<4>  ttl;
    bit<2>  ud;
    bit<2>  rsvd;
}

struct headers_t {
    ethernet_t eth;
    ufh16_t    ufh;
    esun_t     esun;
}

struct meta_t {
    bit<1> is_ufh;
}

parser SwParser(packet_in pkt, out headers_t hdr, inout meta_t meta, inout standard_metadata_t sm) {
    state start {
        /* UFH_16: first octet v=0 w=1 z=y=0 x=1 (mask 0xCE -> 0x42), EtherType 0xE790 at bytes 12-13 */
        transition select(pkt.lookahead<bit<112>>()[111:104] & 0xCE, pkt.lookahead<bit<112>>()[15:0]) {
            (0x42, ETH_UET): parse_ufh;
            default: parse_eth;
        }
    }
    state parse_ufh {
        pkt.extract(hdr.ufh);
        meta.is_ufh = 1;
        transition accept;
    }
    state parse_eth {
        pkt.extract(hdr.eth);
        transition select(hdr.eth.ether_type) {
            ETH_ESUN: parse_esun;
            default: accept;
        }
    }
    state parse_esun {
        pkt.extract(hdr.esun);
        transition accept;
    }
}

control SwVerify(inout headers_t hdr, inout meta_t meta) { apply { } }

control SwIngress(inout headers_t hdr, inout meta_t meta, inout standard_metadata_t sm) {
    counter(8, CounterType.packets) tc_ctr;          // packets per queue (priority)
    counter(4, CounterType.packets) drop_ctr;        // 0 no route, 1 TTL expired, 2 MAC control, 3 parse

    action drop(bit<32> why) {
        drop_ctr.count(why);
        mark_to_drop(sm);
    }
    action set_port(bit<9> port) {
        sm.egress_spec = port;
    }
    action set_queue(bit<3> q) {
        sm.priority = q;
    }

    table ufh_fwd {                                  // UFH_16: destination XPU id -> port
        key = { hdr.ufh.dst: exact; }
        actions = { set_port; drop; }
        default_action = drop(0);
        size = 4096;
    }
    table l2_fwd {                                   // ESUN / Ethernet: static DA -> port, no learning
        key = { hdr.eth.dst: exact; }
        actions = { set_port; drop; }
        default_action = drop(0);
        size = 4096;
    }
    table tc_ufh {
        key = { hdr.ufh.dscp: exact; }
        actions = { set_queue; }
        default_action = set_queue(0);
    }
    table tc_esun {
        key = { hdr.esun.cos: exact; }
        actions = { set_queue; }
        default_action = set_queue(0);
    }

    apply {
        // what the parser found, for the packet viewer's M6 overlay (bmv2 --log-console prints these)
        if (hdr.ufh.isValid()) {
            log_msg("parsed ufh16 dst={} dscp={} ecn={} da_encode={}", {hdr.ufh.dst, hdr.ufh.dscp, hdr.ufh.ecn, hdr.ufh.da_encode});
        } else if (hdr.esun.isValid()) {
            log_msg("parsed esun da={} cos={} ecn={} ttl={} flow_label={}", {hdr.eth.dst, hdr.esun.cos, hdr.esun.ecn, hdr.esun.ttl, hdr.esun.flow_label});
        } else if (hdr.eth.isValid()) {
            log_msg("parsed ethernet da={} ether_type={}", {hdr.eth.dst, hdr.eth.ether_type});
        }
        if (hdr.ufh.isValid()) {
            ufh_fwd.apply();
            tc_ufh.apply();
        } else if (hdr.eth.isValid()) {
            if (hdr.eth.ether_type == ETH_MACC) {
                drop(2);                             // link-local: CC_Update and other MAC control
                return;
            }
            if (hdr.esun.isValid()) {
                if (hdr.esun.ttl <= 1) {
                    drop(1);
                    return;
                }
                hdr.esun.ttl = hdr.esun.ttl - 1;
                log_msg("esun ttl decremented to {}", {hdr.esun.ttl});
                tc_esun.apply();
            }
            l2_fwd.apply();
        } else {
            drop(3);
            return;
        }
        tc_ctr.count((bit<32>) sm.priority);
        log_msg("ingress result egress_spec={} priority={}", {sm.egress_spec, sm.priority});
    }
}

control SwEgress(inout headers_t hdr, inout meta_t meta, inout standard_metadata_t sm) {
    register<bit<32>>(1) ecn_threshold;
    counter(1, CounterType.packets) ce_ctr;

    apply {
        bit<32> thr;
        ecn_threshold.read(thr, 0);
        if (thr != 0 && (bit<32>) sm.enq_qdepth >= thr - 1) {
            if (hdr.ufh.isValid() && (hdr.ufh.ecn == 1 || hdr.ufh.ecn == 2)) {
                hdr.ufh.ecn = 3;
                ce_ctr.count(0);
                log_msg("egress ecn marked CE, queue depth {}", {sm.enq_qdepth});
            } else if (hdr.esun.isValid() && (hdr.esun.ecn == 1 || hdr.esun.ecn == 2)) {
                hdr.esun.ecn = 3;
                ce_ctr.count(0);
                log_msg("egress ecn marked CE, queue depth {}", {sm.enq_qdepth});
            }
        }
    }
}

control SwCompute(inout headers_t hdr, inout meta_t meta) { apply { } }

control SwDeparser(packet_out pkt, in headers_t hdr) {
    apply {
        pkt.emit(hdr.ufh);
        pkt.emit(hdr.eth);
        pkt.emit(hdr.esun);
    }
}

V1Switch(SwParser(), SwVerify(), SwIngress(), SwEgress(), SwCompute(), SwDeparser()) main;

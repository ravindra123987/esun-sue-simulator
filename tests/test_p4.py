"""The P4 switch (p4/esun_switch.p4): the compiled program agrees with the Scapy layers, and the recorded
bmv2 results (tools/run_m6.py, run in the VM) passed. bmv2 itself runs only in the VM."""

import json
from pathlib import Path

from sue import consts as C
from sue.layers import ESUN, UFH16RODL

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "docs" / "experiments" / "p4-results.json"
PROG = json.loads((ROOT / "p4" / "build" / "esun_switch.json").read_text())


def fields(name):
    h = next(h for h in PROG["header_types"] if h["name"] == name)
    return [(f[0], f[1]) for f in h["fields"]]


def offsets(fs):
    out, bit = {}, 0
    for n, w in fs:
        out[n] = (bit, w)
        bit += w
    return out, bit


def scapy_offsets(cls):
    out, bit = {}, 0
    for f in cls.fields_desc:
        w = f.size if hasattr(f, "size") else 8 * f.sz
        out[f.name] = (bit, w)
        bit += w
    return out, bit


def test_ufh16_overlay_matches_the_scapy_layer():
    p4, total = offsets(fields("ufh16_t"))
    sc, sc_total = scapy_offsets(UFH16RODL)
    assert total == sc_total == 8 * C.UFH16_HDR_LEN
    assert p4["dst"] == (sc["dst_rsv"][0], 16)                        # the 16-bit destination container (D11)
    assert p4["dscp"] == sc["dscp"] and p4["ecn"] == sc["ecn"]
    assert p4["dscp"][0] // 8 == C.UFH16_TC_BYTE                       # the byte the UET CRC masks
    assert p4["ether_type"] == sc["ethertype"]


def test_esun_header_matches_the_scapy_layer():
    p4, total = offsets(fields("esun_t"))
    sc, sc_total = scapy_offsets(ESUN)
    assert total == sc_total == 32
    for f in ("cos", "ecn", "ttl", "flow_label"):
        assert p4[f] == sc[f], f


def test_program_has_the_tables_the_lab_programs():
    names = {t["name"] for p in PROG["pipelines"] for t in p["tables"]}
    assert {"SwIngress.ufh_fwd", "SwIngress.l2_fwd", "SwIngress.tc_ufh", "SwIngress.tc_esun"} <= names


def test_recorded_bmv2_run_passed():
    r = json.loads((ROOT / "docs" / "experiments" / "p4-results.json").read_text())
    assert r["checks"] and all(c["ok"] for c in r["checks"]), [c["check"] for c in r["checks"] if not c["ok"]]
    t = r["traffic"]
    assert t["1-plane-pinned"]["completed"] and t["4-plane-spray"]["completed"]
    assert t["4-plane-spray-plane-kill"]["completed"] and t["4-plane-spray-plane-kill"]["failed"] == 0
    assert not t["4-plane-pinned-plane-kill"]["completed"]
    q = t["4-plane-spray"]["bmv2"]["0"]["tc_packets"]
    assert q[0] > 0 and q[1] > 0 and sum(q[2:]) == 0                  # requests on queue 0, ACKs on queue 1


LOG = """\
[05:14:00.623] [bmv2] [D] [thread 7] [0.0] [cxt 0] Processing packet received on port 1
[05:14:00.623] [bmv2] [D] [thread 7] [0.0] [cxt 0] Parser 'parser' entering state 'start'
[05:14:00.624] [bmv2] [D] [thread 7] [0.0] [cxt 0] Parser 'parser' entering state 'parse_eth'
[05:14:00.624] [bmv2] [D] [thread 7] [0.0] [cxt 0] Extracting header 'eth'
[05:14:00.624] [bmv2] [D] [thread 7] [0.0] [cxt 0] Parser 'parser' entering state 'parse_esun'
[05:14:00.624] [bmv2] [D] [thread 7] [0.0] [cxt 0] Extracting header 'esun'
[05:14:00.625] [bmv2] [I] [thread 7] esun ttl decremented to 14
[05:14:00.625] [bmv2] [D] [thread 7] [0.0] [cxt 0] Looking up key:
* hdr.eth.dst         : 02a000000003

[05:14:00.625] [bmv2] [D] [thread 7] [0.0] [cxt 0] Table 'SwIngress.l2_fwd': hit with handle 3
[05:14:00.625] [bmv2] [D] [thread 7] [0.0] [cxt 0] Action entry is SwIngress.set_port - 3,
[05:14:00.625] [bmv2] [D] [thread 7] [0.0] [cxt 0] Looking up key:

[05:14:00.625] [bmv2] [D] [thread 7] [0.0] [cxt 0] Table 'tbl_act': miss
[05:14:00.625] [bmv2] [D] [thread 7] [0.0] [cxt 0] Action entry is act - 
[05:14:00.626] [bmv2] [D] [thread 7] [0.0] [cxt 0] Egress port is 3
[05:14:00.626] [bmv2] [D] [thread 7] [1.0] [cxt 0] Processing packet received on port 0
[05:14:00.626] [bmv2] [D] [thread 7] [1.0] [cxt 0] Looking up key:
* hdr.ufh.dst         : 0009

[05:14:00.626] [bmv2] [D] [thread 7] [1.0] [cxt 0] Table 'SwIngress.ufh_fwd': miss
[05:14:00.626] [bmv2] [D] [thread 7] [1.0] [cxt 0] Action entry is SwIngress.drop - 0,
[05:14:00.626] [bmv2] [D] [thread 7] [1.0] [cxt 0] Egress port is 511
[05:14:00.626] [bmv2] [D] [thread 7] [1.0] [cxt 0] Dropping packet at the end of ingress
[05:14:00.627] [bmv2] [D] [thread 9] [0.0] [cxt 0] Deparsing header 'eth'
[05:14:00.627] [bmv2] [D] [thread 9] [0.0] [cxt 0] Deparsing header 'esun'
[05:14:00.627] [bmv2] [D] [thread 9] [0.0] [cxt 0] Transmitting packet of size 302 out of port 3
"""


def test_bmv2_log_parser_keeps_packets_apart():
    """Two packets interleaved on one thread, and the first one's egress on another: each line goes to its packet,
    the compiler's own tables (tbl_*) are left out, an [I] log_msg line belongs to the thread's current packet."""
    from emu.p4check import parse_bmv2_log
    a, b = parse_bmv2_log(LOG)
    assert a["port_in"] == 1 and a["states"] == ["start", "parse_eth", "parse_esun"] and a["headers"] == ["eth", "esun"]
    assert a["tables"] == [{"key": {"hdr.eth.dst": "02a000000003"}, "table": "SwIngress.l2_fwd", "hit": True,
                            "action": "SwIngress.set_port", "params": ["3"]}]
    assert a["msgs"] == ["esun ttl decremented to 14"]
    assert (a["egress_port"], a["tx_port"], a["dropped"], a["deparsed"]) == (3, 3, False, ["eth", "esun"])
    assert b["tables"][0]["hit"] is False and b["tables"][0]["action"] == "SwIngress.drop"
    assert (b["egress_port"], b["tx_port"], b["dropped"]) == (511, None, True)


def test_recorded_packets_pair_with_bmv2s_log():
    """Every frame the checks sent has its own bmv2 record; what bmv2 decided matches what the XPUs received."""
    r = json.loads(RESULTS.read_text())
    assert r["pairing"]["sent"] == r["pairing"]["bmv2_packets"] == len(r["packets"]) > 0
    for p in r["packets"]:
        b = p["bmv2"]
        assert b["dropped"] == (not p["out"]), p["check"]
        if not b["dropped"]:
            assert list(p["out"]) == [str(b["tx_port"])], p["check"]
    unk = next(p for p in r["packets"] if p["check"] == "unknown DA not flooded")
    assert unk["in"]["ttl"] > 1, "the unknown-DA frame must get past the TTL check to test the DA table"
    assert [t["hit"] for t in unk["bmv2"]["tables"] if t["table"].endswith("l2_fwd")] == [False]

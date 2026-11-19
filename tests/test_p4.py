"""The P4 switch (p4/esun_switch.p4): the compiled program agrees with the Scapy layers, and the recorded
bmv2 results (tools/run_m6.py, run in the VM) passed. bmv2 itself runs only in the VM."""

import json
from pathlib import Path

from sue import consts as C
from sue.layers import ESUN, UFH16RODL

ROOT = Path(__file__).resolve().parent.parent
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

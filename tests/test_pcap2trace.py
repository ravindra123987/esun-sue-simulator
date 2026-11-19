"""Emulator captures turned into viewer events (tools/pcap2trace.py, pcaps/emu/path)."""

from pathlib import Path

import pytest
from scapy.layers.l2 import Ether
from scapy.utils import PcapWriter

from tools import pcap2trace as P

ROOT = Path(__file__).resolve().parent.parent
CAP = ROOT / "pcaps" / "emu" / "path"
META = {"id": "x", "title": "", "summary": "", "watch": ""}


@pytest.fixture(scope="module")
def runs():
    return {d.name: P.convert(d, META) for d in sorted(CAP.iterdir())}


def frames(tr, d, kind="data"):
    return [e for e in tr["events"] if e["ev"] == "frame" and e["dir"] == d and e["kind"] == kind]


def test_frames_cross_hop_1_before_hop_2(runs):
    for name, tr in runs.items():
        a, s = frames(tr, "a2s"), frames(tr, "s2b")
        assert a and s and a[0]["t0"] < s[0]["t0"], name             # the switch forwards what XPU A sent
        assert all(e["arrive"] > e["t0"] for e in tr["events"] if e["ev"] == "frame")


def test_llr_repairs_hop_2_errors_without_rodl_noticing(runs):
    tr = runs["cap-ber-hop2"]
    r = tr["result"]
    assert r["bad"] > 0 and r["llr_nacks"] > 0 and r["replayed"] > 0
    assert all(e["fate"] == "ok" for e in frames(tr, "a2s"))          # errors were on hop 2 only
    assert r["rodl_retx"] == 0 and not any(e["ev"] == "pkt_rx" and e["res"] == "gap" for e in tr["events"])
    assert any(n["kind"] == "nack" and n["at"] == "B" for n in tr["notes"])
    assert not any("after a FLUSH" in n["text"] for n in tr["notes"])   # no FLUSH here: only the start-up handshake


def test_without_llr_rodl_repairs_end_to_end(runs):
    tr = runs["cap-no-llr"]
    assert not any(e["ev"] == "ctlos" and e["kind"].startswith("LLR") for e in tr["events"])
    assert tr["cfg"]["llr"]["enabled"] is False and tr["result"]["replayed"] == 0
    assert tr["result"]["rodl_retx"] > 0 and tr["result"]["rodl_nacks"] > 0
    assert any(e["ev"] == "pkt_rx" and e["res"] == "gap" for e in tr["events"])


def test_outage_is_inferred_and_followed_by_reinit_and_rodl(runs):
    tr = runs["cap-outage-hop1"]
    (a, b), = tr["cfg"]["hops"][0]["down"]
    assert b - a > 300 and not tr["cfg"]["hops"][1]["down"]
    kinds = [n["kind"] for n in tr["notes"] if n["t"] >= a]
    assert "init" in kinds and "retx" in kinds and kinds.index("down") < kinds.index("init")


def test_clean_run_has_no_problems(runs):
    r = runs["cap-clean"]["result"]
    assert r["bad"] == r["replayed"] == r["llr_nacks"] == r["rodl_retx"] == 0 and r["frames"] > 0


def test_a_backward_clock_step_is_undone(tmp_path):
    f = tmp_path / "x.pcap"
    w = PcapWriter(str(f), linktype=1, sync=True)
    for ts in (10.000, 10.010, 9.900, 9.905):                          # the clock steps back 110 ms between 2 and 3
        p = Ether(bytes(60)); p.time = ts; w.write(p)
    w.close()
    ts = [t for t, _ in P.read(f)]
    assert ts == sorted(ts) and ts[2] == pytest.approx(10.010) and ts[3] - ts[2] == pytest.approx(0.005)

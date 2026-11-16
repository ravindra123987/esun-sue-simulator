"""Event traces (sim/trace.py) and the visualiser data (docs/viz/traces.js)."""

import pytest

from sim.link import run_link
from sim.model import CBFCCfg, LinkCfg
from tools import make_traces as MT


@pytest.mark.parametrize("seed", [1, 2])
def test_tracing_does_not_change_the_simulation(seed):
    kw = dict(link=LinkCfg(ber=2e-6, seed=seed), cbfc=CBFCCfg(drain_gbps=400, total_credits=256), sim_ns=8_000)
    assert run_link(**kw) == run_link(**kw, trace=[])


@pytest.fixture(scope="module")
def traces():
    return {t["id"]: t for t in MT.build()}


def kinds(t, at=None):
    return [n["kind"] for n in t["notes"] if at is None or n["at"] == at]


def test_every_good_frame_is_received_at_its_arrival_time(traces):
    for t in traces.values():
        for d, rx in (("a2s", "S1"), ("s2b", "B")):
            got = {(e["fid"], e["t"]) for e in t["events"] if e["ev"] == "rx" and e["mac"] == rx}
            for f in (e for e in t["events"] if e["ev"] == "frame" and e["dir"] == d and e["fate"] != "down"):
                if f["arrive"] <= t["cfg"]["sim_ns"]:
                    assert (f["fid"], f["arrive"]) in got, (t["id"], f)


def test_frames_take_serialisation_time_and_propagation(traces):
    t = traces["clean"]
    for d, h in (("a2s", 0), ("s2b", 1)):
        f = next(e for e in t["events"] if e["ev"] == "frame" and e["dir"] == d)
        ser = (1024 + 20) / 100                                                   # 800G = 100 B/ns
        assert f["t1"] - f["t0"] == pytest.approx(ser, abs=0.01) or f["t1"] - f["t0"] == pytest.approx(ser + 0.08, abs=0.01)  # + one CtlOS
        assert f["arrive"] - f["t1"] == pytest.approx(t["cfg"]["hops"][h]["prop_ns"], abs=0.01)


def test_port_7_starts_sending_exactly_when_it_takes_the_frame_from_the_buffer(traces):
    for t in traces.values():
        fwd = {e["fid"]: e["t"] for e in t["events"] if e["ev"] == "fwd"}
        for e in t["events"]:
            if e["ev"] == "frame" and e["dir"] == "s2b" and e["kind"] == "data" and not e["replay"]:
                assert e["t0"] == fwd[e["fid"]], (t["id"], e)


def test_a_frame_leaves_the_switch_only_after_port_1_accepted_it(traces):
    for t in traces.values():
        acc = {e["fid"]: e["t"] for e in t["events"] if e["ev"] == "rx" and e["mac"] == "S1" and e["res"] == "accept"
               and e["kind"] == "data"}                                   # CC_Updates number their own fids
        for e in t["events"]:
            if e["ev"] == "frame" and e["dir"] == "s2b" and e["kind"] == "data":
                assert acc[e["fid"]] <= e["t0"] + 1e-6, (t["id"], e)


def test_scenarios_show_what_their_titles_promise(traces):
    k = kinds(traces["bit-error"])
    assert k.index("bad") < k.index("nack") < k.index("replay") and "replay" in kinds(traces["bit-error"], "A")
    k = traces["bit-error-2"]
    assert "replay" in kinds(k, "S7") and "replay" not in kinds(k, "A") and "bad" in kinds(k, "B")
    assert "timer" in kinds(traces["lost-nack"]) and "lost on the cable" in next(
        n["text"] for n in traces["lost-nack"]["notes"] if n["kind"] == "nack")
    bp = traces["backpressure"]["notes"]
    first = {at: next(n["t"] for n in bp if n["kind"] == "stall" and n["at"] == at) for at in ("S7", "A")}
    assert first["S7"] < first["A"]                                    # backpressure moves back hop by hop
    assert {"S1", "B"} <= {n["at"] for n in bp if n["kind"] == "fill"}
    assert "stall" in kinds(traces["small-pool"], "A")
    assert traces["outage-short"]["result"]["lost"] == 0 and "flush" not in kinds(traces["outage-short"])
    k = kinds(traces["outage-flush"])
    assert k.index("flush") < k.index("init") < k.index("cc")
    assert traces["outage-flush"]["result"]["lost"] > 0
    nl = traces["no-llr"]
    assert nl["result"]["lost"] == 1 and nl["result"]["replayed"] == 0 and "cc" in kinds(nl)
    for t in traces.values():
        assert t["result"]["in_order"]
        assert "overflow" not in kinds(t)
        assert all(n["at"] in ("A", "S1", "S7", "B", "h1", "h2") for n in t["notes"])


def test_endpoint_scenarios_show_what_their_titles_promise(traces):
    st = traces["suet-stores"]
    assert st["cfg"]["kind"] == "endpoint" and st["result"]["done"] == 64 and st["result"]["pack"] > 4
    assert "pack" in kinds(st, "A") and "accept" in kinds(st, "B") and "done" in kinds(st, "A")
    assert max(e["n"] for e in st["events"] if e["ev"] == "pkt_tx" and e["kind"] == "req") == 8     # 2 KB cap
    dl = traces["suet-delivery"]
    assert dl["result"]["pkts"] > 2 * st["result"]["pkts"] and any(e["ev"] == "txn_in" and e["kind"] == "resp" for e in dl["events"])
    assert dl["result"]["eff"] < st["result"]["eff"]
    ld = traces["suet-loads"]
    assert any(e["ev"] == "pkt_tx" and e["kind"] == "ack" and e["data"] > 0 for e in ld["events"])
    bd = traces["suet-bidir"]
    assert any("carries" in n["text"] for n in bd["notes"]) and bd["result"]["acks"] < bd["result"]["pkts"] / 4
    gb = traces["suet-gbn"]
    k = kinds(gb)
    assert k.index("bad") < k.index("gap") < k.index("rnack") < k.index("goback") < k.index("retx")
    assert gb["result"]["done"] == 64 and gb["result"]["retx"] >= 1 and gb["result"]["failed"] == 0
    lt = traces["suet-lite"]
    assert "fatal" in kinds(lt, "A") and lt["result"]["failed"] == 64 and lt["result"]["retx"] == 0
    sx = traces["suet-slow-xpu"]
    assert sx["result"]["pack"] == 1.0 and sx["result"]["eff"] < 0.8
    for t in traces.values():
        if t["cfg"]["kind"] != "endpoint":
            continue
        assert all(n["at"] in ("A", "S1", "S7", "B") for n in t["notes"])
        # packets the other way leave port 1 only after port 7 accepted them, like forward ones
        acc = {e["fid"]: e["t"] for e in t["events"] if e["ev"] == "rx" and e["mac"] == "S7" and e["res"] == "accept" and e["kind"] == "data"}
        for e in t["events"]:
            if e["ev"] == "frame" and e["dir"] == "s2a" and e["kind"] == "data":
                assert acc[e["fid"]] <= e["t0"] + 1e-6, (t["id"], e)
        # every packet on the wire was logged by its endpoint
        sent = {e["fid"] for e in t["events"] if e["ev"] == "pkt_tx"}
        assert all(e["fid"] in sent for e in t["events"] if e["ev"] == "frame" and e["kind"] == "data")


def test_flush_caption_counts_the_frames(traces):
    t = traces["outage-flush"]
    flush = next(e for e in t["events"] if e["ev"] == "flush")
    note = next(n["text"] for n in t["notes"] if n["kind"] == "flush")
    assert f"{len(flush['seqs'])} frame(s)" in note
    assert t["result"]["lost"] < len(flush["fids"])          # some had crossed; only their ACKs died


def test_build_is_deterministic():
    same = MT.render(MT.build()) == MT.render(MT.build())
    assert same, "two builds differ: a scenario hook keeps state between runs"


def test_traces_js_is_up_to_date():
    same = MT.OUT.read_text() == MT.render(MT.build())     # no pytest diff: the file is ~1 MB
    assert same, "docs/viz/traces.js is stale: run tools/make_traces.py"

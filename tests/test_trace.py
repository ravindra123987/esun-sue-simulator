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


def kinds(t):
    return [n["kind"] for n in t["notes"]]


def test_every_good_frame_is_received_at_its_arrival_time(traces):
    for t in traces.values():
        rx = {(e["fid"], e["t"]) for e in t["events"] if e["ev"] == "rx" and e["mac"] == "B"}
        for f in (e for e in t["events"] if e["ev"] == "frame" and e["dir"] == "a2b" and e["fate"] != "down"):
            if f["arrive"] <= t["cfg"]["sim_ns"]:
                assert (f["fid"], f["arrive"]) in rx, (t["id"], f)


def test_frames_take_serialisation_time_and_propagation(traces):
    t = traces["clean"]
    f = next(e for e in t["events"] if e["ev"] == "frame")
    assert f["t1"] - f["t0"] == pytest.approx((1024 + 20) / 100, abs=0.01)      # 800G = 100 B/ns
    assert f["arrive"] - f["t1"] == pytest.approx(t["cfg"]["prop_ns"], abs=0.01)


def test_scenarios_show_what_their_titles_promise(traces):
    k = kinds(traces["bit-error"])
    assert k.index("bad") < k.index("nack") < k.index("replay")
    assert traces["bit-error"]["result"]["lost"] == 0
    assert "timer" in kinds(traces["lost-nack"]) and "nack" in kinds(traces["lost-nack"])
    assert "lost on the wire" in next(n["text"] for n in traces["lost-nack"]["notes"] if n["kind"] == "nack")
    assert "stall" in kinds(traces["slow-receiver"])
    assert traces["outage-short"]["result"]["lost"] == 0 and "flush" not in kinds(traces["outage-short"])
    k = kinds(traces["outage-flush"])
    assert k.index("flush") < k.index("init") < k.index("cc")
    assert traces["outage-flush"]["result"]["lost"] > 0
    nl = traces["no-llr"]
    assert nl["result"]["lost"] == 1 and nl["result"]["replayed"] == 0 and "cc" in kinds(nl)
    for t in traces.values():
        assert t["result"]["in_order"]
        assert "overflow" not in kinds(t)


def test_flush_caption_counts_frames_the_receiver_already_had(traces):
    t = traces["outage-flush"]
    flush = next(e for e in t["events"] if e["ev"] == "flush")
    note = next(n["text"] for n in t["notes"] if n["kind"] == "flush")
    assert f"{len(flush['seqs'])} frame(s)" in note
    assert t["result"]["lost"] < len(flush["fids"])          # some were delivered; only their ACKs died
    assert "already had" in note


def test_build_is_deterministic():
    same = MT.render(MT.build()) == MT.render(MT.build())
    assert same, "two builds differ: a scenario hook keeps state between runs"


def test_traces_js_is_up_to_date():
    same = MT.OUT.read_text() == MT.render(MT.build())     # no pytest diff: the file is ~600 KB
    assert same, "docs/viz/traces.js is stale: run tools/make_traces.py"

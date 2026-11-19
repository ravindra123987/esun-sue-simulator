"""Event traces (sim/trace.py) and the visualiser data (docs/viz/traces.js)."""

import pytest

from sim.link import run_link
from sim.model import CBFCCfg, LinkCfg
from tools import make_traces as MT


@pytest.mark.parametrize("seed", [1, 2])
def test_tracing_does_not_change_the_simulation(seed):
    kw = dict(link=LinkCfg(ber=2e-6, seed=seed), cbfc=CBFCCfg(drain_gbps=400, total_credits=256), sim_ns=8_000)
    assert run_link(**kw) == run_link(**kw, trace=[])


@pytest.fixture(scope="session")
def built():
    return MT.build()


@pytest.fixture(scope="module")
def traces(built):
    return {t["id"]: t for t in built}


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


def simulated(traces):
    """Runs from the simulator (captured runs have no internal events, and their crossings are drawn, not timed)."""
    return [t for t in traces.values() if t["cfg"]["kind"] in ("link", "endpoint")]


def test_port_7_starts_sending_exactly_when_it_takes_the_frame_from_the_buffer(traces):
    for t in simulated(traces):
        fwd = {e["fid"]: e["t"] for e in t["events"] if e["ev"] == "fwd"}
        for e in t["events"]:
            if e["ev"] == "frame" and e["dir"] == "s2b" and e["kind"] == "data" and not e["replay"]:
                assert e["t0"] == fwd[e["fid"]], (t["id"], e)


def test_a_frame_leaves_the_switch_only_after_port_1_accepted_it(traces):
    for t in simulated(traces):
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
    for t in simulated(traces):
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


def test_build_is_deterministic(built):
    """A second build gives the same bytes (the fast kinds in full, and one planes scenario)."""
    fast = {"link", "endpoint", "captured", "p4"}
    first = [t for t in built if t["cfg"]["kind"] in fast or t["id"] == "planes-reorder"]
    again = MT.build(kinds=fast) + MT.build(ids={"planes-reorder"})
    by_id = lambda ts: sorted(ts, key=lambda t: t["id"])
    assert MT.render(by_id(first)) == MT.render(by_id(again)), "two builds differ: a scenario hook keeps state between runs"


def test_traces_js_is_up_to_date(built):
    same = MT.OUT.read_text() == MT.render(built)     # no pytest diff: the file is several MB
    assert same, "docs/viz/traces.js is stale: run tools/make_traces.py"


def test_planes_scenarios_carry_every_design_and_tell_the_m5_story(traces):
    pl = {k: t for k, t in traces.items() if t["cfg"]["kind"] == "planes"}
    assert set(pl) >= {"planes-plane-kill", "planes-plane-flap", "planes-remote-link", "planes-plane-ber", "planes-plane-credits", "planes-reorder"}
    for t in pl.values():
        assert t["events"] == [] and t["notes"] and t["extra"]["order"]
        for k in t["extra"]["order"]:
            s = t["extra"]["designs"][k]["series"]
            assert len(s["up"]) == t["cfg"]["n"] and len(s["up"][0]) == t["cfg"]["p"] and len(s["up"][0][0]) == s["bins"]
            assert all(0 <= u <= 100 for row in s["up"] for col in row for u in col)
        assert {n["at"] for n in t["notes"]} <= set(t["extra"]["order"]) | {"fab"}
    r = pl["planes-plane-kill"]["result"]
    assert r["sue-t"]["finished_us"] is None and r["sue-t"]["failed"] > 0
    assert all(r[k]["finished_us"] is not None and r[k]["failed"] == 0 for k in ("sue-t+fo", "metaroce", "mrc", "mrc+llr"))
    assert pl["planes-plane-ber"]["result"]["mrc+llr"]["finished_us"] < pl["planes-plane-ber"]["result"]["mrc"]["finished_us"]
    ro = pl["planes-reorder"]["result"]
    assert ro["rud-spray"]["finished_us"] < ro["rodl-spray"]["finished_us"] / 3


def test_p4_scenario_walks_every_recorded_frame(traces):
    t = traces["p4-pipeline"]
    fr = t["extra"]["frames"]
    assert t["cfg"]["kind"] == "p4" and len(fr) == t["result"]["frames"] == 14 and t["cfg"]["sim_ns"] == 14 * t["cfg"]["step"]
    assert t["result"]["checks_ok"] == t["result"]["checks"]
    for f in fr:
        assert f["dropped"] == (not f["out"]) and bool(f["drop"]) == f["dropped"], f["check"]
        if not f["dropped"]:
            assert 0 <= f["queue"] <= 7
            for o in f["out"].values():
                if f["ttl"] is not None:
                    assert o["ttl"] == int(f["ttl"]) == f["in"]["ttl"] - 1
                if f["ecn_marked"]:
                    assert o["ecn"] == 3 and f["in"]["ecn"] in (1, 2)
    why = {f["check"]: f["drop"] for f in fr if f["dropped"]}
    assert "ufh_fwd" in why["ufh16 unknown destination dropped"] and "l2_fwd" in why["unknown DA not flooded"]
    assert "TTL" in why["esun TTL 1 dropped"] and "MAC control" in why["CC_Update not forwarded"]
    assert sorted(f["queue"] for f in fr if f["check"].startswith("TC to queue")) == [0, 1, 3]
    assert {n["at"] for n in t["notes"]} == {"p4"} and len(t["notes"]) == 2 * len(fr)

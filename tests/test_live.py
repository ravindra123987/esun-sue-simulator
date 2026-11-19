"""The live server (tools/live.py): stepping, captions and commands act on a running simulation."""

from sim.path import PathSession
from tools import live as L
from tools import make_traces as MT


def scenario(sid):
    return next(s for s in MT.SCENARIOS if s["id"] == sid)


def test_stepping_in_chunks_gives_the_same_events_as_one_run():
    kw, _ = MT.setup(scenario("bit-error-2"))
    one = []
    PathSession(trace=one, **kw).run(600)
    lv = L.Live(scenario("bit-error-2"))
    got = []
    for until in range(37, 640, 37):
        got += lv.step(min(until, 600))["events"]
    assert got == one


def test_live_captions_match_the_recorded_ones():
    lv = L.Live(scenario("outage-flush"))
    notes = []
    for until in range(100, 2700, 100):
        notes += lv.step(until)["notes"]
    rec = next(t for t in MT.build() if t["id"] == "outage-flush")["notes"]
    assert sorted(notes, key=lambda n: n["t"]) == rec


def test_commands_change_the_running_simulation():
    lv = L.Live(scenario("clean"))
    lv.step(100)
    lv.cmd("corrupt_frame", {"hop": 2})
    notes = lv.step(600)["notes"]
    assert notes[0]["kind"] == "cmd"
    assert [n["at"] for n in notes if n["kind"] == "replay"] == ["S7"]          # the switch repairs hop 2

    lv.cmd("hbm", {"gbps": 200})
    ev = lv.step(1000)["events"]
    eg = [e for e in ev if e["ev"] == "egress"]
    assert eg and all(abs((e["t_end"] - e["t"]) - 1024 / 25) < 1e-6 for e in eg)   # 200 Gb/s = 25 B/ns

    lv.cmd("link_down", {"hop": 1, "ns": 300})
    out = lv.step(1400)
    assert any(f["ev"] == "frame" and f["dir"] == "a2s" and f["fate"] == "down" for f in out["events"])
    assert [(n["kind"], n["at"]) for n in out["notes"]][:2] == [("down", "h1"), ("up", "h1")]


def test_live_offers_link_and_endpoint_scenarios():
    kinds = {s.get("kind", "link") for s in L.SCENARIOS}
    assert kinds == {"link", "endpoint"}


def test_endpoint_live_session_runs_and_takes_commands():
    sc = scenario("suet-stores")
    lv = L.Live(L.custom(sc, {"suet": {"xpu_gbps": 400}, "hop2": {"cable_m": 10}}))
    assert type(lv).__name__ == "EndpointLive" and lv.cfg["suet"]["xpu_gbps"] == 400 and lv.cfg["hops"][1]["cable_m"] == 10
    out = lv.step(1000)
    assert any(e["ev"] == "pkt_tx" and e["xpu"] == "A" for e in out["events"])     # relabelled to the viewer's names
    assert any(n["kind"] == "issue" for n in out["notes"])
    lv.cmd("xpu", {"gbps": 3200})
    lv.cmd("corrupt_frame", {"hop": 1})
    out = lv.step(3000)
    assert lv.cfg["suet"]["xpu_gbps"] == 3200
    assert any(e["ev"] == "rx" and e["mac"] == "S1" and e["res"] == "bad" for e in out["events"])
    lv.cmd("link_down", {"hop": 2, "ns": 200})
    out = lv.step(4500)
    assert any(e["ev"] == "frame" and e["dir"] == "s2b" and e["fate"] == "down" for e in out["events"])
    assert lv.step(1e12)["t"] <= 4500 + L.MAX_STEP_NS


def test_one_request_never_runs_away():
    lv = L.Live(scenario("clean"))
    assert lv.step(1e12)["t"] == L.MAX_STEP_NS


def test_custom_runs_apply_and_clamp_overrides():
    sc = L.custom(scenario("clean"), {"hop2": {"ber": 1.0}, "nic": {"drain_gbps": 400, "total_credits": 1}, "llr": {"enabled": 0}})
    assert sc["hop2"]["ber"] == 1e-4 and sc["nic"] == {"drain_gbps": 400.0, "total_credits": 32} and sc["llr"]["enabled"] is False
    assert scenario("clean").get("nic") is None                       # the scenario itself is untouched
    lv = L.Live(sc)
    out = lv.step(800)
    assert lv.cfg["nic_gbps"] == 400 and lv.cfg["llr"]["enabled"] is False
    assert any(e["ev"] == "rx" and e["mac"] == "B" and e["res"] == "bad" for e in out["events"])   # hop 2 is noisy
    import pytest
    with pytest.raises(ValueError):
        L.custom(scenario("clean"), {"sw": {"secret": 1}})
    with pytest.raises(ValueError):
        L.custom(scenario("clean"), {"nic": {"drain_gbps": "fast"}})

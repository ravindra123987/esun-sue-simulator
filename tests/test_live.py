"""The live server (tools/live.py): stepping, captions and commands act on a running simulation."""

from sim.link import LinkSession
from tools import live as L
from tools import make_traces as MT


def scenario(sid):
    return next(s for s in MT.SCENARIOS if s["id"] == sid)


def test_stepping_in_chunks_gives_the_same_events_as_one_run():
    link, llr, cbfc, hooks, _ = MT.setup(scenario("bit-error"))
    one = []
    LinkSession(link, llr, cbfc, hooks=hooks, trace=one).run(500)
    lv = L.Live(scenario("bit-error"))
    got = []
    for until in range(37, 540, 37):
        got += lv.step(min(until, 500))["events"]
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
    lv.cmd("corrupt_frame")
    kinds = [n["kind"] for n in lv.step(400)["notes"]]
    assert kinds[0] == "cmd" and kinds.index("bad") < kinds.index("nack") < kinds.index("replay")

    lv.cmd("egress", 200)
    ev = lv.step(800)["events"]
    eg = [e for e in ev if e["ev"] == "egress"]
    assert eg and all(abs((e["t_end"] - e["t"]) - 1024 / 25) < 1e-6 for e in eg)   # 200 Gb/s = 25 B/ns

    lv.cmd("link_down", 300)
    out = lv.step(1200)
    assert any(f["ev"] == "frame" and f["fate"] == "down" for f in out["events"])
    assert [n["kind"] for n in out["notes"]][:2] == ["down", "up"]


def test_one_request_never_runs_away():
    lv = L.Live(scenario("clean"))
    assert lv.step(1e12)["t"] == L.MAX_STEP_NS

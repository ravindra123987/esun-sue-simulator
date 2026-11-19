"""Packet-viewer data for M5: the five recovery designs on the 4 x 4 fabric, one fault at a time.

A fabric run has 32 cable ends and far too many frames and control blocks to ship one by one, so each
design's run is reduced to time bins (`BIN_NS`): data bytes per cable direction (utilisation), the LLR
state of every port, stores completed and failed per XPU, which port each XPU used towards each peer,
and the recovery events themselves (timeouts, moves, bad marks, restores, PDCs closed, FLUSHes, switch
discards). Captions are written from those events, with the design they happened in.

Used by tools/make_traces.py; the runs are sim/planes.py's, on a smaller workload.
"""

import dataclasses
import math
from collections import defaultdict

from sim import planes as PL

BIN_NS = 1000.0
VIEW_TAIL = 1.3              # the picture runs to this multiple of the last finish time
BYTES = 2 << 20              # per peer: long enough that every fault lands mid-run
MAX_NS = 200_000.0
KEEP = {"frame", "rodl", "txn", "sw_drop", "sw_trim", "sw_cong_drop", "flush", "pkt_tx"}
LABEL = {"sue-t": "SUE-T 1.0", "sue-t+fo": "SUE-T + failover", "metaroce": "MetaRoCE-style", "mrc": "MRC-style", "mrc+llr": "MRC-style + LLR"}
HOW = {"sue-t": "pinned PDC · RODL · LLR", "sue-t+fo": "PDC moves · RODL · LLR", "metaroce": "spray · SACK · no LLR · leave after 3 RTOs",
       "mrc": "spray · SACK · no LLR · leave after 1 RTO, probe back", "mrc+llr": "spray · SACK · LLR · leave after 1 RTO, probe back"}
LLR_RANK = {"ADVANCE": 0, "REPLAY": 1, "INIT": 2, "FLUSH": 3}


def run_design(design, scenario, bytes_per_peer=BYTES, until=MAX_NS, build=None):
    """One run, reduced to bins. Returns (series, events, finished_ns)."""
    f = (build or PL.build)(design, scenario, bytes_per_peer=bytes_per_peer)
    kept = []

    def log(ev, **kw):
        if ev in KEEP:
            kw["ev"], kw["t"] = ev, f.sim.now
            kept.append(kw)
    f.sim.trace = kept                     # endpoints and wires log only when a trace is set ...
    f.sim.log = log                        # ... and only what the planes picture needs is kept
    n, P = f.n, f.P
    nb = int(until // BIN_NS) + 1
    llr = defaultdict(lambda: [0] * nb)    # mac name -> worst LLR state per bin

    def sample():
        b = int(f.sim.now // BIN_NS)
        if b < nb:
            for name, m in f.macs.items():
                r = LLR_RANK.get(m.state, 0) if m.llr.enabled else 0
                if r > llr[name][b]:
                    llr[name][b] = r
        f.sim.after(BIN_NS / 4, sample)
    f.sim.after(0.0, sample)
    f.run(until)
    fin = f.workload.finished
    end = min(until, (fin or until) + 5_000)
    nb = int(end // BIN_NS) + 1
    up = [[[0] * nb for _ in range(P)] for _ in range(n)]       # XPU i -> switch p: bytes per bin
    dn = [[[0] * nb for _ in range(P)] for _ in range(n)]       # switch p -> XPU i
    done = [[0] * nb for _ in range(n)]
    failed = [[0] * nb for _ in range(n)]
    port = [[[-1] * nb for _ in range(n)] for _ in range(n)]    # [src][dst] -> port used most in the bin
    pcount = defaultdict(lambda: [0] * P)
    events = []
    for e in kept:
        t = e["t"]
        b = int(t // BIN_NS)
        if b >= nb:
            continue
        ev = e["ev"]
        if ev == "frame" and e.get("kind") == "data":
            w = e["dir"]
            if w.startswith("n"):                                 # n{i}p{p}>s{p}
                i, p = int(w[1:w.index("p")]), int(w[w.index("p") + 1:w.index(">")])
                up[i][p][b] += e["size"] + 20
            else:                                                 # s{p}>n{i}p{p}
                p, i = int(w[1:w.index(">")]), int(w[w.index(">") + 2:w.rindex("p")])
                dn[i][p][b] += e["size"] + 20
        elif ev == "txn":
            (done if e["ok"] else failed)[e["xpu"]][b] += 1
        elif ev == "pkt_tx" and e.get("kind") == "req":
            pcount[(e["xpu"], e["dst"], b)][e["port"]] += 1
        elif ev == "rodl" and e["what"] in ("timeout", "move", "bad", "restore", "fatal"):
            events.append({"t": round(t / 1000, 3), "what": e["what"], "xpu": e["xpu"], "peer": e["peer"],
                           **{k: e[k] for k in ("port", "frm", "to", "why", "n") if k in e}})
        elif ev == "flush":
            events.append({"t": round(t / 1000, 3), "what": "flush", "mac": e["mac"], "n": len(e.get("seqs", []))})
        elif ev in ("sw_drop", "sw_trim", "sw_cong_drop"):
            events.append({"t": round(t / 1000, 3), "what": ev, "plane": e["plane"], "port": e["port"]})
    for (i, j, b), c in pcount.items():
        port[i][j][b] = max(range(P), key=lambda q: c[q])
    cap = 100.0 * BIN_NS                                          # 800G = 100 B/ns
    pct = lambda arr: [min(100, round(100 * x / cap)) for x in arr]  # noqa: E731
    llr_bins = {name: v[:nb] for name, v in llr.items() if any(v[:nb])}
    series = {"up": [[pct(up[i][p]) for p in range(P)] for i in range(n)],
              "dn": [[pct(dn[i][p]) for p in range(P)] for i in range(n)],
              "done": done, "failed": failed, "port": port, "llr": llr_bins, "total": f.workload.total, "bins": nb}
    return series, events, fin


def wires_down(design, scenario):
    """Which cables the fault takes down, and when (from the scenario's hook)."""
    f = PL.build(design, scenario, bytes_per_peer=1024)
    out = []
    for name, w in f.wires.items():
        for a, b in w.cfg.down:
            out.append({"wire": name, "a": round(a / 1000, 3), "b": None if b == float("inf") else round(b / 1000, 3)})
    return out


def captions(design, events, fin, n_total):
    lab = LABEL.get(design, design)
    notes, said = [], set()

    def note(t, kind, text):
        notes.append({"t": t, "at": design, "kind": kind, "text": f"{lab}: {text}"})
    for e in events:
        w, t = e["what"], e["t"]
        if w == "timeout" and ("to", e["xpu"]) not in said:
            said.add(("to", e["xpu"]))
            note(t, "rtimer", f"XPU {e['xpu']}'s transport timer expires for XPU {e['peer']}: packets sent before the fault are "
                              "still unacknowledged.")
        elif w == "move":
            note(t, "move", f"XPU {e['xpu']} moves its PDC to XPU {e['peer']} from port {e['frm']} to port {e['to']} ({e['why']}).")
        elif w == "bad" and ("bad", e["xpu"], e["peer"], e["port"]) not in said:
            said.add(("bad", e["xpu"], e["peer"], e["port"]))
            note(t, "bad", f"XPU {e['xpu']} marks plane {e['port']} bad towards XPU {e['peer']} after a timeout on it, and sprays "
                           "over the others.")
        elif w == "restore":
            note(t, "up", f"XPU {e['xpu']} takes plane {e['port']} back into use towards XPU {e['peer']}.")
        elif w == "fatal":
            note(t, "fatal", f"XPU {e['xpu']} gives up its PDC to XPU {e['peer']} after repeated timeouts: {e.get('n', 0)} stores fail, "
                             "and the next packet re-establishes it on the same pinned port.")
        elif w == "flush" and ("flush", e["mac"]) not in said:
            said.add(("flush", e["mac"]))
            note(t, "flush", f"LLR at port {e['mac']} gives up (FLUSH): {e['n']} frame(s) thrown away; only the transport can "
                             "recover them now.")
        elif w == "sw_drop" and ("swd", e["plane"], e["port"]) not in said:
            said.add(("swd", e["plane"], e["port"]))
            note(t, "drop", f"switch {e['plane']} discards frames for its port {e['port']}, whose cable is down.")
        elif w == "sw_trim" and ("trim", e["plane"]) not in said:
            said.add(("trim", e["plane"]))
            note(t, "trim", f"switch {e['plane']}'s queue to port {e['port']} is full: frames are trimmed to their headers.")
    if fin is not None:
        note(round(fin / 1000, 3), "done", f"all {n_total} stores done at {fin / 1000:.1f} µs.")
    return notes


def build_fault(fault, designs=None, title=None, summary="", watch="", scenario_id=None, build=None, bytes_per_peer=BYTES):
    designs = designs or list(PL.DESIGNS)
    out, notes, dur = {}, [], 0.0
    for d in designs:
        series, events, fin = run_design(d, fault, bytes_per_peer=bytes_per_peer, build=build)
        out[d] = {"label": LABEL.get(d, d), "how": HOW.get(d, ""), "series": series, "events": events,
                  "finished_us": round(fin / 1000, 2) if fin else None}
        notes += captions(d, events, fin, series["total"])
        dur = max(dur, series["bins"] * BIN_NS / 1000)
    down = wires_down(designs[0], fault) if fault in PL.SCENARIOS else []
    for w in down:
        notes.append({"t": w["a"], "at": "fab", "kind": "down", "text": f"Cable {w['wire']} goes down" + ("." if w["b"] is None else f" until {w['b']} µs.")})
        if w["b"] is not None and w["b"] < dur:
            notes.append({"t": w["b"], "at": "fab", "kind": "up", "text": f"Cable {w['wire']} is back up."})
    notes = _merge_cable_notes(notes)
    # The picture ends shortly after the last design that finishes. A design that never finishes (pinned on a
    # dead plane) would otherwise stretch the time axis several times over; its full-run numbers stay in `result`.
    fins = [v["finished_us"] for v in out.values() if v["finished_us"]]
    view = min(dur, float(math.ceil(max(fins) * VIEW_TAIL))) if fins else dur
    if view < dur:
        for d, v in out.items():
            if v["finished_us"] is None or v["finished_us"] > view:
                failed, done = sum(map(sum, v["series"]["failed"])), sum(map(sum, v["series"]["done"]))
                notes.append({"t": view, "at": d, "kind": "fail", "text": f"{LABEL.get(d, d)} is not done when the others are: over the full run "
                              f"({dur:.0f} µs) it completes {done} of {v['series']['total']} stores and {failed} fail."})
        notes = [x for x in notes if x["t"] <= view]
    notes.sort(key=lambda x: (x["t"], x["at"]))
    return {"id": scenario_id or f"planes-{fault}", "title": title or fault, "summary": summary, "watch": watch,
            "cfg": {"kind": "planes", "time_unit": "µs", "sim_ns": round(view, 3), "full_us": round(dur, 3), "speed_mult": 0.1, "no_flow": True,
                    "n": PL.N, "p": PL.P, "bin_us": BIN_NS / 1000, "fault": fault, "down": down,
                    "hops": [{"down": []}, {"down": []}]},
            "result": {d: {"finished_us": v["finished_us"], "done": sum(map(sum, v["series"]["done"])),
                           "failed": sum(map(sum, v["series"]["failed"])), "total": v["series"]["total"]} for d, v in out.items()},
            "events": [], "notes": notes, "extra": {"designs": out, "order": designs}}


def _merge_cable_notes(notes):
    """Eight cables of one plane going down at the same moment: one caption, not eight."""
    out, groups = [], defaultdict(list)
    for x in notes:
        if x["at"] == "fab":
            groups[(x["t"], x["kind"])].append(x)
        else:
            out.append(x)
    for (t, kind), xs in groups.items():
        if len(xs) == 1:
            out.append(xs[0])
            continue
        planes = sorted({x["text"].split(">")[0][-1] if x["text"].startswith("Cable s") else x["text"].split("p")[1][0] for x in xs})
        word = "go down" if kind == "down" else "are back up"
        out.append({"t": t, "at": "fab", "kind": kind, "text": f"All {len(xs)} cables of plane {', '.join(planes)} {word}."})
    return out


# the T5 reorder case (M3, docs/where-should-retry-live.md): spraying over two planes of unequal delay
def build_reorder():
    from sim.fabric import Fabric
    from sim.model import LinkCfg, LLRCfg
    from sim.suet import SUETCfg
    from sim.workloads import AllToAll

    def make(design, scenario, bytes_per_peer=BYTES):
        order = "rodl" if design == "rodl-spray" else "rud"

        def slow(f):
            for name, w in f.wires.items():
                if "p1" in name:
                    w.cfg = dataclasses.replace(w.cfg, cable_m=20)
        return Fabric(n=PL.N, ports=2, link=LinkCfg(), llr=LLRCfg(), suet=SUETCfg(path="spray", order=order, rto_ns=20_000, xpu_gbps=1600.0),
                      workload=AllToAll(PL.N, bytes_per_peer=bytes_per_peer), hooks=slow)
    LABEL.update({"rodl-spray": "spray, in order (RODL)", "rud-spray": "spray, out of order (SACK)"})
    HOW.update({"rodl-spray": "every packet on any plane · Go-Back-N on a gap", "rud-spray": "every packet on any plane · SACK, no reorder penalty"})
    return build_fault("reorder", designs=["rodl-spray", "rud-spray"], build=make, bytes_per_peer=1 << 20)

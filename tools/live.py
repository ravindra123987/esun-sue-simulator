"""Run the link simulator live and drive the packet viewer from it.

    .venv/bin/python tools/live.py          # then open http://127.0.0.1:8765/

The server serves docs/ and runs one simulator session per browser tab. The
page asks it to advance simulated time a little ahead of what it is showing
(POST /live/step) and draws the events that come back, so every packet on
screen is one the simulator has just produced. Commands (POST /live/cmd)
change the running simulation: corrupt the next frame, lose the next NACK,
take either cable down, change how fast XPU B can write into HBM.

A run can also start from a scenario with settings overridden (POST /live/new with
"cfg"): the viewer's custom-run form sends per-hop BER and cable length, LLR settings
and the two buffers. LIMITS below clamps every value.

Standard library only; listens on 127.0.0.1.
"""

import argparse
import json
import sys
import threading
import time
import uuid
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sim.model import CtlOS, Frame          # noqa: E402
from sim.path import PathSession            # noqa: E402
from sim.trace import Annotator             # noqa: E402
from tools.make_traces import SCENARIOS, setup  # noqa: E402

DOCS = ROOT / "docs"
MAX_STEP_NS = 5_000.0       # one request never advances the simulation further than this
IDLE_S = 600                # sessions nobody has asked about for this long are dropped

# settings a custom run may override: section -> field -> (min, max) or bool
LIMITS = {
    "hop1": {"ber": (0.0, 1e-4), "cable_m": (0.5, 50.0)},
    "hop2": {"ber": (0.0, 1e-4), "cable_m": (0.5, 50.0)},
    "llr": {"enabled": bool, "replay_timer_ns": (100.0, 20_000.0), "replay_ct_max": (1, 255)},
    "sw": {"total_credits": (32, 4096)},
    "nic": {"total_credits": (32, 4096), "drain_gbps": (50.0, 800.0)},
}


def custom(sc: dict, over: dict | None) -> dict:
    """A copy of scenario `sc` with the user's overrides applied, each one clamped to LIMITS."""
    if not over:
        return sc
    if not isinstance(over, dict):
        raise ValueError("cfg must be an object")
    out = dict(sc)
    for section, fields in over.items():
        if section not in LIMITS or not isinstance(fields, dict):
            raise ValueError(f"unknown setting {section!r}")
        part = dict(out.get(section, {}))
        for k, v in fields.items():
            lim = LIMITS[section].get(k)
            if lim is None:
                raise ValueError(f"unknown setting {section}.{k}")
            if lim is bool:
                part[k] = bool(v)
            else:
                lo, hi = lim
                x = type(lo)(v)                      # int fields stay int; a bad string raises ValueError
                part[k] = max(lo, min(hi, x))
        out[section] = part
    return out


def _once(pred):
    """A corruption hook that fires for the first object matching pred."""
    state = {"done": False}

    def hook(obj):
        if not state["done"] and pred(obj):
            state["done"] = True
            return True
        return None
    return hook


def _chain(old, new):
    if old is None:
        return new

    def hook(obj):
        r = new(obj)
        return r if r is not None else old(obj)
    return hook


class Live:
    """One running simulation and the events not yet sent to the browser."""

    def __init__(self, sc):
        kw, cfg = setup(sc)
        cfg["sim_ns"] = None
        self.cfg = cfg
        self.trace = []
        self.s = PathSession(trace=self.trace, **kw)
        self.ann = Annotator(cfg)                # shares cfg, so commands that change it reach the captions
        self.pending = [n for i, h in enumerate(cfg["hops"]) for a, b in h["down"]
                        for n in self.ann.link_down(i + 1, a, b)]
        self.lock = threading.Lock()
        self.seen = time.time()

    @property
    def now(self):
        return self.s.sim.now

    def step(self, until):
        with self.lock:
            self.seen = time.time()
            until = min(float(until), self.now + MAX_STEP_NS)
            if until > self.now:
                self.s.run(until)
            events = list(self.trace)
            self.trace.clear()                  # the MACs keep appending to this same list
            notes, self.pending = self.pending, []
            for e in events:
                notes.extend(self.ann.feed(e))
            return {"t": round(self.now, 3), "events": events, "notes": notes}

    def cmd(self, name, arg=None):
        """arg: {"hop": 1 | 2, "ns": outage length, "gbps": XPU B's HBM write rate}."""
        arg = arg if isinstance(arg, dict) else {}
        hop = 2 if arg.get("hop") == 2 else 1
        with self.lock:
            self.seen = time.time()
            t, s = self.now, self.s
            if name == "corrupt_frame":
                w = s.wires["a2s" if hop == 1 else "s2b"]
                w.corrupt_hook = _chain(w.corrupt_hook, _once(
                    lambda o: isinstance(o, Frame) and o.kind == "data" and o.tx_count == 1))
                who = "XPU A's NIC" if hop == 1 else "switch port 7"
                text = f"You corrupt the next new data frame {who} sends on hop {hop}."
            elif name == "lose_nack":
                w = s.wires["s2a" if hop == 1 else "b2s"]
                w.corrupt_hook = _chain(w.corrupt_hook, _once(
                    lambda o: isinstance(o, CtlOS) and o.kind == "LLR_NACK"))
                text = f"You arrange for the next NACK on hop {hop} to be lost on the cable."
            elif name == "link_down":
                dur = max(10.0, min(float(arg.get("ns") or 300), 20_000.0))
                s.links[hop - 1].down.append((t, t + dur))
                self.cfg["hops"][hop - 1]["down"].append([round(t, 3), round(t + dur, 3)])
                for n in self.ann.link_down(hop, t, t + dur):
                    self.pending.append(n)
                return {"cfg": self.cfg}
            elif name == "hbm":
                g = max(50.0, min(float(arg.get("gbps") or 800), 800.0))
                s.nic.drain_gbps = g
                self.cfg["nic_gbps"] = g
                text = f"You set XPU B's HBM write rate to {g:g} Gb/s."
            else:
                raise ValueError(f"unknown command {name!r}")
            self.pending.append({"t": round(t, 3), "at": "cmd", "kind": "cmd", "text": text})
            return {"cfg": self.cfg}


SESSIONS: dict[str, Live] = {}
SLOCK = threading.Lock()


def _gc():
    cut = time.time() - IDLE_S
    with SLOCK:
        for k in [k for k, v in SESSIONS.items() if v.seen < cut]:
            del SESSIONS[k]


class Handler(SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):         # keep the terminal quiet
        pass

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def _json(self, obj, code=200):
        body = json.dumps(obj, separators=(",", ":")).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self.send_response(302)
            self.send_header("Location", "/viz/?live")
            self.end_headers()
            return
        if self.path == "/live/hello":
            return self._json({"ok": True, "scenarios": [
                {k: sc[k] for k in ("id", "title", "summary", "watch")} for sc in SCENARIOS],
                "limits": {s: {k: (None if v is bool else list(v)) for k, v in f.items()} for s, f in LIMITS.items()}})
        super().do_GET()

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
            req = json.loads(self.rfile.read(n) or b"{}")
            if self.path == "/live/new":
                _gc()
                sc = next((x for x in SCENARIOS if x["id"] == req.get("scenario")), SCENARIOS[0])
                live = Live(custom(sc, req.get("cfg")))
                sid = uuid.uuid4().hex
                with SLOCK:
                    SESSIONS[sid] = live
                return self._json({"id": sid, "scenario": sc["id"], "cfg": live.cfg})
            live = SESSIONS.get(req.get("id", ""))
            if live is None:
                return self._json({"error": "no such session (expired?)"}, 404)
            if self.path == "/live/step":
                return self._json(live.step(req.get("until", 0)))
            if self.path == "/live/cmd":
                return self._json(live.cmd(req.get("cmd"), req.get("arg")))
            return self._json({"error": "not found"}, 404)
        except (ValueError, TypeError, KeyError) as e:
            return self._json({"error": str(e)}, 400)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--port", type=int, default=8765)
    args = ap.parse_args(argv)
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), partial(Handler, directory=str(DOCS)))
    print(f"live simulator: http://127.0.0.1:{args.port}/   (Ctrl-C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

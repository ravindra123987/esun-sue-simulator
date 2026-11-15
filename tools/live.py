"""Run the link simulator live and drive the packet viewer from it.

    .venv/bin/python tools/live.py          # then open http://127.0.0.1:8765/

The server serves docs/ and runs one simulator session per browser tab. The
page asks it to advance simulated time a little ahead of what it is showing
(POST /live/step) and draws the events that come back, so every packet on
screen is one the simulator has just produced. Commands (POST /live/cmd)
change the running simulation: corrupt the next frame, lose the next NACK,
take the link down, change the switch's egress rate.

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

from sim.link import LinkSession            # noqa: E402
from sim.model import CtlOS, Frame          # noqa: E402
from sim.trace import Annotator             # noqa: E402
from tools.make_traces import SCENARIOS, setup  # noqa: E402

DOCS = ROOT / "docs"
MAX_STEP_NS = 5_000.0       # one request never advances the simulation further than this
IDLE_S = 600                # sessions nobody has asked about for this long are dropped


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
        link, llr, cbfc, hooks, cfg = setup(sc)
        cfg["sim_ns"] = None
        self.cfg = cfg
        self.trace = []
        self.s = LinkSession(link, llr, cbfc, hooks=hooks, trace=self.trace)
        self.ann = Annotator()
        self.pending = [n for a, b in link.down for n in self.ann.link_down(a, b)]
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
        with self.lock:
            self.seen = time.time()
            t, s = self.now, self.s
            if name == "corrupt_frame":
                s.a2b.corrupt_hook = _chain(s.a2b.corrupt_hook, _once(
                    lambda o: isinstance(o, Frame) and o.kind == "data" and o.tx_count == 1))
                text = "You corrupt the next new data frame the NIC sends."
            elif name == "lose_nack":
                s.b2a.corrupt_hook = _chain(s.b2a.corrupt_hook, _once(
                    lambda o: isinstance(o, CtlOS) and o.kind == "LLR_NACK"))
                text = "You arrange for the switch port's next NACK to be lost on the wire."
            elif name == "link_down":
                dur = max(10.0, min(float(arg or 300), 20_000.0))
                s.link.down.append((t, t + dur))
                self.cfg["down"].append([round(t, 3), round(t + dur, 3)])
                self.pending.extend(self.ann.link_down(t, t + dur))
                return {"notes": [], "cfg": self.cfg}
            elif name == "egress":
                g = max(50.0, min(float(arg or 800), 800.0))
                s.cbfc.drain_gbps = g
                self.cfg["cbfc"]["drain_gbps"] = g
                text = f"You set the switch's egress port to {g:g} Gb/s."
            else:
                raise ValueError(f"unknown command {name!r}")
            self.pending.append({"t": round(t, 3), "kind": "cmd", "text": text})
            return {"notes": [], "cfg": self.cfg}


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
                {k: sc[k] for k in ("id", "title", "summary", "watch")} for sc in SCENARIOS]})
        super().do_GET()

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
            req = json.loads(self.rfile.read(n) or b"{}")
            if self.path == "/live/new":
                _gc()
                sc = next((x for x in SCENARIOS if x["id"] == req.get("scenario")), SCENARIOS[0])
                live = Live(sc)
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

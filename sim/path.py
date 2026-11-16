"""Two hops through one switch: XPU A's NIC -> switch port 1 -> port 7 -> XPU B's NIC.

Each hop is a full-duplex link with its own LLR and CBFC, built from the same Mac as
sim/link.py:

    A  (XPU A NIC, sender)  --hop 1-->  S1 (switch port 1, receiver)
    S7 (switch port 7, sender)  --hop 2-->  B  (XPU B NIC, receiver)

The switch stores and forwards with zero pipeline latency. A frame that LLR accepts on
port 1 waits in port 1's ingress buffer (the buffer whose credits port 1 gives XPU A)
until port 7 can send it: port 7's LLR window must be open and XPU B must have given it
credits. Port 1 frees the buffer space, and so returns XPU A's credits, when port 7 starts
sending the frame. XPU B's NIC writes its receive buffer into HBM at `nic.drain_gbps`.
So a slow XPU B fills its NIC buffer, port 7 runs out of credits, port 1's buffer fills
and XPU A runs out of credits: backpressure moves back one hop at a time and nothing is
dropped.
"""

from dataclasses import dataclass, field

from .engine import Sim
from .link import Backlog
from .mac import Mac
from .model import CBFCCfg, Frame, LinkCfg, LLRCfg, Wire

NAMES = {"A": "XPU A's NIC", "S1": "Switch port 1", "S7": "Switch port 7", "B": "XPU B's NIC"}
# (sender, receiver, forward wire, reverse wire) for hop 1 and hop 2
HOPS = (("A", "S1", "a2s", "s2a"), ("S7", "B", "s2b", "b2s"))


class SwitchQueue:
    """Port 7's view of port 1's ingress buffer: the oldest frame, as a fresh frame for hop 2."""

    def __init__(self, port):
        self.port = port
        self._of = self._head = None

    def peek(self, now):
        if not self.port.rxbuf:
            return None
        src = self.port.rxbuf[0]
        if self._of is not src:
            self._of = src
            self._head = Frame(src.fid, src.size, src.vc, src.lossless, born=src.born)
        return self._head

    def pop(self):
        fr = self._head
        self._of = self._head = None
        self.port.release_head()
        return fr


@dataclass
class PathResult:
    sim_ns: float
    delivered: int
    goodput_gbps: float
    in_order: bool
    duplicates: int
    lost: int
    lat_p50_ns: float
    lat_p99_ns: float
    macs: dict = field(default_factory=dict)        # name -> Mac stats
    wires: dict = field(default_factory=dict)


class PathSession:
    """Two hops that can be stepped (tools/live.py) or run to the end (run_path)."""

    def __init__(self, hop1: LinkCfg = None, hop2: LinkCfg = None, llr: LLRCfg = None,
                 sw: CBFCCfg = None, nic: CBFCCfg = None, frame_size=1024, hooks=None,
                 trace: list | None = None):
        self.links = (hop1 or LinkCfg(), hop2 or LinkCfg(seed=2))
        self.llr = llr or LLRCfg()
        self.sw, self.nic = sw or CBFCCfg(), nic or CBFCCfg()     # hop 1 / hop 2 receiver buffers
        sim = self.sim = Sim()
        sim.trace = trace
        l1, l2 = self.links
        self.wires = {n: Wire(sim, l, n) for n, l in (("a2s", l1), ("s2a", l1), ("s2b", l2), ("b2s", l2))}
        w = self.wires
        self.got = []

        def sink(fr, now):
            self.got.append((fr.fid, now - fr.born, fr.size, now))
            if sim.trace is not None:
                sim.log("deliver", fid=fr.fid, lat=round(now - fr.born, 3))

        self.A = Mac(sim, "A", l1, self.llr, self.sw, w["a2s"], source=Backlog(frame_size))
        self.S1 = Mac(sim, "S1", l1, self.llr, self.sw, w["s2a"])
        self.S7 = Mac(sim, "S7", l2, self.llr, self.nic, w["s2b"], source=SwitchQueue(self.S1))
        self.B = Mac(sim, "B", l2, self.llr, self.nic, w["b2s"], sink=sink)
        self.S1.forward = self.S7
        w["a2s"].peer, w["s2a"].peer = self.S1, self.A
        w["s2b"].peer, w["b2s"].peer = self.B, self.S7
        self.macs = {"A": self.A, "S1": self.S1, "S7": self.S7, "B": self.B}
        if hooks:
            hooks(sim, self.macs, self.wires)
        if trace is not None:
            def snap():
                for m in self.macs.values():
                    m.snap_if_changed()
            sim.after_event = snap
            snap()
        for m in self.macs.values():
            m.start()
        if trace is not None:
            sim.after_event()

    def run(self, until: float):
        self.sim.run(until)

    def result(self, warmup_ns=2_000.0) -> PathResult:
        got, sim_ns = self.got, self.sim.now
        fids = [g[0] for g in got]
        window = [g for g in got if g[3] >= warmup_ns]
        span = sim_ns - warmup_ns
        lat = sorted(g[1] for g in got) or [0.0]
        lost = set().union(*(m.lost_fids for m in self.macs.values())) - set(fids)
        return PathResult(
            sim_ns=sim_ns, delivered=len(got),
            goodput_gbps=sum(g[2] for g in window) * 8 / span if span > 0 else 0.0,
            in_order=all(x < y for x, y in zip(fids, fids[1:])), duplicates=len(fids) - len(set(fids)),
            lost=len(lost), lat_p50_ns=lat[len(lat) // 2], lat_p99_ns=lat[min(len(lat) - 1, int(len(lat) * 0.99))],
            macs={k: dict(m.stats) for k, m in self.macs.items()},
            wires={k: dict(v.stats) for k, v in self.wires.items()})


def run_path(sim_ns=20_000.0, warmup_ns=2_000.0, **kw) -> PathResult:
    s = PathSession(**kw)
    s.run(sim_ns)
    return s.result(warmup_ns)

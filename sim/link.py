"""A sender and a receiver MAC joined by a full-duplex link, plus traffic and metrics.

Data flows A -> B. B's transmit direction carries only CtlOS (LLR ACK/NACK,
CF_Update), which is what a one-way flow looks like on a real link.
"""

from dataclasses import dataclass, field

from .engine import Sim
from .mac import Mac
from .model import CBFCCfg, Frame, LinkCfg, LLRCfg, Wire


class Backlog:
    """An always-full queue of fixed-size frames on one lossless VC."""

    def __init__(self, size=1024, vc=0, lossless=True):
        self.size, self.vc, self.lossless = size, vc, lossless
        self.n = 0
        self._head = None

    def peek(self, now):
        if self._head is None:
            self.n += 1
            self._head = Frame(self.n, self.size, self.vc, self.lossless, born=now)
        return self._head

    def pop(self):
        fr, self._head = self._head, None
        return fr


@dataclass
class Result:
    sim_ns: float
    delivered: int
    delivered_bytes: int
    goodput_gbps: float
    in_order: bool
    duplicates: int
    lost: int
    lat_p50_ns: float
    lat_p99_ns: float
    a: dict = field(default_factory=dict)       # sender MAC stats
    b: dict = field(default_factory=dict)       # receiver MAC stats
    wire: dict = field(default_factory=dict)


class LinkSession:
    """One link that can be advanced a step at a time (tools/live.py) or run to the end (run_link)."""

    def __init__(self, link: LinkCfg = None, llr: LLRCfg = None, cbfc: CBFCCfg = None, frame_size=1024,
                 hooks=None, trace: list | None = None):
        self.link, self.llr, self.cbfc = link or LinkCfg(), llr or LLRCfg(), cbfc or CBFCCfg()
        sim = self.sim = Sim()
        sim.trace = trace
        self.a2b, self.b2a = Wire(sim, self.link, "a2b"), Wire(sim, self.link, "b2a")
        self.got = []

        def sink(fr, now):
            self.got.append((fr.fid, now - fr.born, fr.size, now))
            if sim.trace is not None:
                sim.log("deliver", fid=fr.fid, lat=round(now - fr.born, 3))

        self.A = Mac(sim, "A", self.link, self.llr, self.cbfc, self.a2b, source=Backlog(frame_size))
        self.B = Mac(sim, "B", self.link, self.llr, self.cbfc, self.b2a, sink=sink)
        self.a2b.peer, self.b2a.peer = self.B, self.A
        if hooks:
            hooks(sim, self.A, self.B, self.a2b, self.b2a)
        if trace is not None:
            def snap():
                self.A.snap_if_changed()
                self.B.snap_if_changed()
            sim.after_event = snap
            snap()
        self.A.start()
        self.B.start()
        if trace is not None:
            sim.after_event()                   # state after the first frame is queued at t = 0

    def run(self, until: float):
        self.sim.run(until)

    def result(self, warmup_ns=2_000.0) -> Result:
        got, A, B, sim_ns = self.got, self.A, self.B, self.sim.now
        fids = [g[0] for g in got]
        in_order = all(x < y for x, y in zip(fids, fids[1:]))
        window = [g for g in got if g[3] >= warmup_ns]
        span = sim_ns - warmup_ns
        lat = sorted(g[1] for g in got) or [0.0]
        # FLUSH can discard frames the receiver already has (only their ACKs were lost)
        lost = (set(A.lost_fids) | set(B.lost_fids)) - set(fids)
        return Result(
            sim_ns=sim_ns, delivered=len(got), delivered_bytes=sum(g[2] for g in got),
            goodput_gbps=sum(g[2] for g in window) * 8 / span if span > 0 else 0.0,
            in_order=in_order, duplicates=len(fids) - len(set(fids)), lost=len(lost),
            lat_p50_ns=lat[len(lat) // 2], lat_p99_ns=lat[min(len(lat) - 1, int(len(lat) * 0.99))],
            a=dict(A.stats), b=dict(B.stats), wire={"a2b": dict(self.a2b.stats), "b2a": dict(self.b2a.stats)})


def run_link(link: LinkCfg = None, llr: LLRCfg = None, cbfc: CBFCCfg = None, frame_size=1024,
             sim_ns=20_000.0, warmup_ns=2_000.0, hooks=None, trace: list | None = None) -> Result:
    """Run one link. Pass an empty list as `trace` to record every event (sim/trace.py)."""
    s = LinkSession(link, llr, cbfc, frame_size, hooks, trace)
    s.run(sim_ns)
    return s.result(warmup_ns)


def link_rtt_ns(link: LinkCfg, llr: LLRCfg) -> float:
    """Time from sending a frame's last bit to receiving its ACK, roughly:
    two propagation delays plus the wait for the next CtlOS slot."""
    return 2 * link.prop_ns + llr.ctlos_spacing / link.rate

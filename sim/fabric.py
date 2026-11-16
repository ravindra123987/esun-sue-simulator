"""N XPUs, each with P ports, one switch per port plane (SUE-T §5: single hop, Figure 2).

Every link is the M2 link (sim/mac.py): LLR and CBFC per cable end, one lossless VC per
traffic class. XPU i's port p is cabled to port i of switch p. A switch stores and forwards
with virtual output queueing: egress port e takes the oldest frame addressed to it from any
ingress buffer, after `pipeline_ns` (RM104 App A budgets < 250 ns). Ingress buffers are the
ones XPUs hold credits for, so a slow XPU backs up the switch and then the senders, as on
the two-hop path (sim/path.py), but now across N ports.
"""

import dataclasses
import itertools
import statistics
from dataclasses import dataclass, field

from .engine import Sim
from .mac import Mac
from .model import CBFCCfg, Frame, LinkCfg, LLRCfg, Wire
from .suet import Endpoint, PortTx, SUETCfg


class Switch:
    def __init__(self, sim, plane, n, pipeline_ns):
        self.sim, self.plane, self.n, self.pipeline_ns = sim, plane, n, pipeline_ns
        self.ports: list[Mac] = [None] * n       # port i: receives from XPU i, sends to XPU i

    def arrived(self, port, fr):
        e = self.ports[fr.dst]
        if self.pipeline_ns > 0:
            self.sim.after(self.pipeline_ns, e.kick)
        else:
            e.kick()


class Ingress:
    """`forward` hook of an ingress MAC: tell the switch which frame just landed in its buffer."""

    def __init__(self, sw, port):
        self.sw, self.port = sw, port

    def kick(self):
        self.sw.arrived(self.port, self.sw.ports[self.port].rxbuf[-1])


class Egress:
    """Source of egress port e: the oldest buffered frame addressed to e, as a fresh frame for its hop."""

    def __init__(self, sw, e):
        self.sw, self.e = sw, e
        self._src = self._from = self._head = None

    def peek(self, now):
        if self._head is not None:
            return self._head
        best = None
        for m in self.sw.ports:
            for fr in m.rxbuf:
                if fr.dst == self.e and fr.kind == "data" and now - fr.t_rx >= self.sw.pipeline_ns - 1e-9:
                    if best is None or fr.t_rx < best[1].t_rx:
                        best = (m, fr)
                    break                                        # a buffer is in arrival order
        if best is None:
            return None
        self._from, self._src = best
        src = self._src
        self._head = Frame(src.fid, src.size, src.vc, src.lossless, born=src.born, dst=src.dst, pkt=src.pkt)
        return self._head

    def pop(self):
        fr, self._head = self._head, None
        self._from.release(self._src)
        self._from = self._src = None
        return fr


@dataclass
class FabricResult:
    sim_ns: float
    done: int
    failed: int
    finished_ns: float | None           # when the workload completed, if it did
    lat_p50_ns: float
    lat_p99_ns: float
    lat_max_ns: float
    payload_bytes: int
    wire_bytes: int                     # every frame the endpoints sent, preamble and IPG included
    efficiency: float                   # payload / wire
    pack_avg: float                     # CMD_PDUs per request packet
    pack_hist: dict
    ep: dict = field(default_factory=dict)      # summed endpoint stats
    mac: dict = field(default_factory=dict)     # summed MAC stats, NIC side and switch side


class Fabric:
    def __init__(self, n=4, ports=1, link: LinkCfg = None, llr: LLRCfg = None, nic: CBFCCfg = None,
                 sw: CBFCCfg = None, suet: SUETCfg = None, pipeline_ns=0.0, workload=None,
                 trace: list | None = None, hooks=None):
        self.n, self.P = n, ports
        self.cfg = suet or SUETCfg()
        self.link, self.llr = link or LinkCfg(), llr or LLRCfg()
        tcs = self.cfg.tcs
        self.nic = dataclasses.replace(nic or CBFCCfg(), vcs=tcs)
        self.sw = dataclasses.replace(sw or CBFCCfg(), vcs=tcs)
        sim = self.sim = Sim()
        sim.trace = trace
        self.fids = itertools.count(1)
        self.workload = workload
        self.eps = [Endpoint(sim, i, self.cfg, ports, self.fids, workload) for i in range(n)]
        self.switches = [Switch(sim, p, n, pipeline_ns) for p in range(ports)]
        self.macs: dict[str, Mac] = {}
        self.wires: dict[str, Wire] = {}
        for p, swp in enumerate(self.switches):
            for i, ep in enumerate(self.eps):
                up, dn = Wire(sim, self.link, f"n{i}p{p}>s{p}"), Wire(sim, self.link, f"s{p}>n{i}p{p}")
                nm = Mac(sim, f"N{i}.{p}", self.link, self.llr, self.nic, up, source=PortTx(ep, p), sink=ep.on_frame,
                         cl_credits=self.sw.total_credits)
                sm = Mac(sim, f"S{p}.{i}", self.link, self.llr, self.sw, dn, source=Egress(swp, i),
                         cl_credits=self.nic.total_credits)
                sm.forward = Ingress(swp, i)
                up.peer, dn.peer = sm, nm
                ep.macs[p] = nm
                swp.ports[i] = sm
                self.macs[nm.name], self.macs[sm.name] = nm, sm
                self.wires[up.name], self.wires[dn.name] = up, dn
        if hooks:
            hooks(self)
        if workload is not None:
            workload.attach(self)
        if trace is not None:
            def snap():
                for m in self.macs.values():
                    m.snap_if_changed()
            sim.after_event = snap
        for m in self.macs.values():
            m.start()
        for ep in self.eps:
            ep.kick_xpu()
        if trace is not None:
            sim.after_event()                   # state at t = 0, before the first event

    def run(self, until: float, stop_when_done=True, step=500.0):
        """Advance to `until`, or until the workload says it is finished."""
        while self.sim.now < until:
            if stop_when_done and self.workload is not None and self.workload.done():
                break
            self.sim.run(min(until, self.sim.now + step))

    def result(self) -> FabricResult:
        lat = sorted(x for ep in self.eps for x in ep.lat) or [0.0]
        ep = {k: sum(e.stats[k] for e in self.eps) for k in self.eps[0].stats}
        hist = {}
        for e in self.eps:
            for k, v in e.pack_hist.items():
                hist[k] = hist.get(k, 0) + v
        npk = sum(hist.values())
        mac = {}
        for side, pred in (("nic", lambda n: n.startswith("N")), ("sw", lambda n: n.startswith("S"))):
            ms = [m for n, m in self.macs.items() if pred(n)]
            mac[side] = {k: sum(m.stats[k] for m in ms) for k in ms[0].stats}
        payload = ep["tx_payload"]
        return FabricResult(
            sim_ns=self.sim.now, done=ep["done"], failed=ep["failed"],
            finished_ns=self.workload.finished if self.workload is not None else None,
            lat_p50_ns=statistics.median(lat), lat_p99_ns=lat[min(len(lat) - 1, int(len(lat) * 0.99))], lat_max_ns=lat[-1],
            payload_bytes=payload, wire_bytes=ep["tx_wire"], efficiency=payload / ep["tx_wire"] if ep["tx_wire"] else 0.0,
            pack_avg=sum(k * v for k, v in hist.items()) / npk if npk else 0.0, pack_hist=dict(sorted(hist.items())),
            ep=ep, mac=mac)

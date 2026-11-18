"""M5: the same multi-plane fabric, five recovery designs, one set of faults (docs/where-should-retry-live.md).

Designs are SUE-T endpoint configurations (sim/suet.py) plus whether the links run LLR:

    sue-t        SUE-T 1.0 as specified: PDC pinned to its port, RODL Go-Back-N, LLR on every link.
                 The spec leaves failover to future work (§7.5).
    sue-t+fo     The "integrated failover" §7.5 sketches: the PDC moves to another port when its NIC sees
                 its own link down, or after one RTO (with LLR on, an RTO already means the link gave up).
    metaroce     MetaRoCE's shape: traffic spread over the planes, out-of-order delivery with SACK, no LLR;
                 a port is abandoned after 3 timeouts and retried after a long timer (spec §4.8, §7.5).
    mrc          MRC's shape: every packet on any good plane, SACK, no LLR; one timeout marks the plane bad
                 for that peer, probes bring it back (MRC + SRv6 paper).
    mrc+llr      MRC's transport over links that also retry: the retry lives in both places.

Faults act on plane 1 unless stated: a whole plane dying, a short plane outage, one remote link (switch 1 to
XPU 2) dying, bit errors on every plane-1 cable, and a plane whose switch buffers are too small (credits).
"""

import dataclasses

from .fabric import Fabric
from .model import CBFCCfg, LinkCfg, LLRCfg
from .suet import SUETCfg
from .workloads import AllToAll

INF = float("inf")
N, P = 4, 4
FAULT_AT = 5_000.0

# rto: transport retransmission timer. With LLR on it must exceed LLR's worst case (2 µs x 9 = 18 µs, M3 T4);
# with LLR off only the fabric round trip and queueing bound it.
DESIGNS = {
    "sue-t":    dict(llr=True,  suet=dict(path="pin", order="rodl", rto_ns=20_000, max_rtos=8)),
    "sue-t+fo": dict(llr=True,  suet=dict(path="failover", order="rodl", rto_ns=20_000, rtos_before_move=1)),
    "metaroce": dict(llr=False, suet=dict(path="spray", order="rud", rto_ns=10_000, rtos_before_move=3,
                                          restore="timer", probe_ns=500_000)),
    "mrc":      dict(llr=False, suet=dict(path="spray", order="rud", rto_ns=10_000, rtos_before_move=1,
                                          restore="probe", probe_ns=20_000)),
    "mrc+llr":  dict(llr=True,  suet=dict(path="spray", order="rud", rto_ns=20_000, rtos_before_move=1,
                                          restore="probe", probe_ns=20_000)),
}


def _down(f, names, t0, t1):
    for n in names:
        w = f.wires[n]
        w.cfg = dataclasses.replace(w.cfg, down=list(w.cfg.down) + [(t0, t1)])


def plane_wires(plane, n=N):
    return [f"n{i}p{plane}>s{plane}" for i in range(n)] + [f"s{plane}>n{i}p{plane}" for i in range(n)]


SCENARIOS = {
    "clean":       dict(desc="no fault"),
    "plane-kill":  dict(desc="plane 1 dies at 5 µs and stays down",
                        hook=lambda f: _down(f, plane_wires(1), FAULT_AT, INF)),
    "plane-flap":  dict(desc="plane 1 down from 5 to 15 µs",
                        hook=lambda f: _down(f, plane_wires(1), FAULT_AT, FAULT_AT + 10_000)),
    "remote-link": dict(desc="the link from switch 1 to XPU 2 dies at 5 µs (senders cannot see it)",
                        hook=lambda f: _down(f, ["s1>n2p1"], FAULT_AT, INF)),
    "plane-ber":   dict(desc="bit errors (1e-6) on every plane-1 cable",
                        hook=lambda f: [setattr(f.wires[n], "cfg", dataclasses.replace(f.wires[n].cfg, ber=1e-6))
                                        for n in plane_wires(1)]),
    "plane-credits": dict(desc="plane 1's switch holds only 4 KB per ingress port (64 credits): a slow plane",
                          sw_credits_plane1=64),
}


def build(design, scenario, bytes_per_peer=1 << 20, seed=1, trace=None, suet_over=None):
    d, sc = DESIGNS[design], SCENARIOS[scenario]
    cfg = SUETCfg(xpu_gbps=3200.0, seed=seed, **{**d["suet"], **(suet_over or {})})
    hooks = sc.get("hook")
    if "sw_credits_plane1" in sc:
        small = sc["sw_credits_plane1"]

        def hooks(f, small=small):
            for i in range(N):
                m, nic = f.macs[f"S1.{i}"], f.macs[f"N{i}.1"]
                m.cbfc = dataclasses.replace(m.cbfc, total_credits=small)
                nic.cl = {vc: small for vc in nic.cl}             # what XPU i may send into switch 1
    return Fabric(n=N, ports=P, link=LinkCfg(seed=seed), llr=LLRCfg(enabled=d["llr"]), suet=cfg,
                  workload=AllToAll(N, bytes_per_peer=bytes_per_peer, seed=seed), hooks=hooks, trace=trace)


def run(design, scenario, until=400_000.0, **kw):
    f = build(design, scenario, **kw)
    f.run(until)
    r = f.result()
    wl = f.workload
    return f, r, wl

"""User-space switch: N ports on veths, each a full LLR + CBFC link end, forwarding by destination.

Forwarding is a table lookup on the inner frame: a UFH_16 frame's 16-bit destination container
(the XPU id, UEC Fig 3-120) or an ESUN/Ethernet frame's MAC DA (the lab gives XPU i the MAC
02:a0:00:00:00:ii). Frames wait in the ingress port's lossless buffer, which is the credit pool
the sender sees; the egress port takes the oldest frame destined to it from any ingress buffer
(virtual output queueing), when its own LLR window and the next hop's credits allow. Store and
forward, no pipeline latency.

    ip netns exec sw0 python -m emu.switch --ports 4 --out /tmp/sw.json [--ber p1=1e-5] [--drop-cf p1=0.5] [--no-llr]
"""

import argparse
import json
import os
import signal
import struct
import time

from . import shim as S
from .port import Loop, Port, PortCfg, Timers, raw_socket


def xpu_mac(i: int) -> bytes:
    return b"\x02\xa0\x00\x00\x00" + bytes([i])


def sw_mac(i: int) -> bytes:
    return b"\x02\x5f\x00\x00\x00" + bytes([i])


def dst_port_of(inner: bytes) -> int:
    """UFH_16: dst_addr (12 bits of bytes 4-5); ESUN / Ethernet: last byte of the DA (lab convention)."""
    if len(inner) >= 16 and inner[12:14] == b"\xe7\x90" and (inner[0] & 0x4E) == 0x42:
        return struct.unpack("!H", inner[4:6])[0] & 0xFFF
    if len(inner) >= 14 and inner[:5] == b"\x02\xa0\x00\x00\x00":
        return inner[5]
    return -1


class Egress:
    """What port `e` transmits next: the oldest buffered frame on any ingress port that is addressed to it."""

    def __init__(self, sw, e):
        self.sw, self.e = sw, e
        self._cand = None

    def peek(self):
        best, src = None, None
        for p in self.sw.ports:
            for fr in p.rxbuf:
                if fr.dst_port == self.e and (best is None or fr.t_rx < best.t_rx):
                    best, src = fr, p
                    break                          # rxbuf is in arrival order
        self._cand = (best, src)
        return best

    def pop(self):
        fr, src = self._cand
        src.release(fr)
        self.sw.stats["forwarded"] += 1
        return fr


class Switch:
    def __init__(self, n, cfgs, send, log=None, nic_credits=None):
        self.timers = Timers()
        self.ports = []
        self.stats = {"forwarded": 0, "no_route": 0}
        self.log = log
        for i in range(n):
            p = Port(f"p{i}", cfgs[i], self.timers, send(i), sw_mac(i), xpu_mac(i), source=Egress(self, i),
                     forward=True, classify=self._classify, cl_credits=nic_credits, log=log)
            self.ports.append(p)

    def _classify(self, fr):
        fr.dst_port = dst_port_of(fr.inner)
        if not 0 <= fr.dst_port < len(self.ports):
            self.stats["no_route"] += 1
            fr.dst_port = -1
            if self.log:
                self.log("sw", "no_route", {"size": fr.size})

    def on_wire(self, i, raw):
        self.ports[i].on_wire(raw)           # the loop kicks every port once per pass

    def kick_all(self):
        for p in self.ports:
            p.kick()

    def start(self):
        for p in self.ports:
            p.start()

    def result(self):
        return {"switch": dict(self.stats), "ports": {p.name: dict(p.stats) for p in self.ports}}


def parse_per_port(spec, n, cast=float):
    out = {i: 0.0 for i in range(n)}
    for item in (spec or "").split(","):
        if item:
            k, v = item.split("=")
            out[int(k.lstrip("p"))] = cast(v)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ports", type=int, required=True)
    ap.add_argument("--ifname", default="sw0-p{i}")
    ap.add_argument("--out", required=True)
    ap.add_argument("--ber", default="", help="per port, e.g. p1=1e-5,p2=1e-6 (corruption of what the port sends)")
    ap.add_argument("--drop-cf", default="", help="per port, e.g. p1=0.5 (fraction of received CF_Updates dropped)")
    ap.add_argument("--no-llr", action="store_true")
    ap.add_argument("--no-cbfc", action="store_true")
    ap.add_argument("--credits", type=int, default=1024, help="ingress buffer per VC, in 64 B credits")
    ap.add_argument("--nic-credits", type=int, default=1024, help="the NICs' receive buffer we may send into")
    ap.add_argument("--replay-timer", type=float, default=0.05)
    ap.add_argument("--replay-ct-max", type=int, default=8)
    ap.add_argument("--log", default="")
    a = ap.parse_args(argv)

    bers, drops = parse_per_port(a.ber, a.ports), parse_per_port(a.drop_cf, a.ports)
    cfgs = [PortCfg(llr=not a.no_llr, cbfc=not a.no_cbfc, total_credits=a.credits, ber=bers[i], drop_cf=drops[i],
                    replay_timer_s=a.replay_timer, replay_ct_max=a.replay_ct_max, seed=100 + i) for i in range(a.ports)]
    socks = [raw_socket(a.ifname.format(i=i)) for i in range(a.ports)]
    events = []
    log = (lambda who, ev, kw: events.append({"t": round(time.monotonic() - T0, 6), "at": who, "ev": ev, **kw})) if a.log else None
    sw = Switch(a.ports, cfgs, lambda i: socks[i].send, log=log, nic_credits=a.nic_credits)
    loop = Loop(sw.timers)
    loop.ports = sw.ports
    for i, s in enumerate(socks):
        loop.add(s, lambda raw, i=i: sw.on_wire(i, raw))
    T0 = time.monotonic()

    def stop(*_):
        loop.stop = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    sw.start()
    loop.run()
    res = sw.result()
    res["uptime_s"] = round(time.monotonic() - T0, 3)
    with open(a.out, "w") as f:
        json.dump(res, f, indent=1)
    if a.log:
        with open(a.log, "w") as f:
            for e in events:
                f.write(json.dumps(e) + "\n")
    os._exit(0)


if __name__ == "__main__":
    main()

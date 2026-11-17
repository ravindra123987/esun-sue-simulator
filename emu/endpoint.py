"""A SUE-T endpoint as a user-space process on one veth (SUE-T Base 1.0.0 §6-§7, UEC §3.5.7.3).

What it does, on real frames built by sue/frame.py:
  - one queue per destination XPU; stores of `size` bytes issued round robin over the peers,
    held back by a transmit buffer of `tx_buf` bytes (the XPU interface hand-over is instant)
  - work-conserving packing: up to `max_pack` CMD_PDUs or `max_payload` bytes per packet
  - one RODL PDC per peer over UFH_16: syn on the first packet, hidden PSN in the UET CRC, a window
    of `window` packets, Go-Back-N on a NACK or on the RTO; or no retransmission (SUE-lite), where a
    loss fails everything in flight and the next packet re-establishes the PDC with syn
  - operational ACKs: the receiver "executes" a store at once, holds the ACK for `ack_hold` in case a
    request going the other way can carry it (rev_cack_psn_lsb in the UFH_16 header), else sends a
    bare ACK packet on the response VC; a gap is NACKed once with a NACK packet
  - the receiver finds a syn=0 packet's PSN the way the dissector does: expected first, then a window
    around it, by recomputing the UET CRC

Loads, delivery ACKs and ESUN framing are not here yet (the switch forwards ESUN frames by DA).

    ip netns exec xpu0 python -m emu.endpoint --xpu 0 --n 4 --out /tmp/xpu0.json [--bytes-per-peer 32768] ...
"""

import argparse
import json
import os
import signal
import statistics
import time
from collections import deque

from scapy.packet import Raw

from sue import consts as C
from sue import crc as K
from sue.frame import PDC, Req, _pad_to_min, pack_requests, ufh16_rodl_header
from sue.layers import UFH16Ack, UFH16RODL, is_ufh16

from .port import Loop, Port, PortCfg, Timers, TxFrame, raw_socket
from .switch import sw_mac, xpu_mac

PSN_SEARCH = 64


class Txn:
    __slots__ = ("id", "dst", "address", "data", "t_issue", "t_done", "ok", "psn")

    def __init__(self, id, dst, address, data, t_issue):
        self.id, self.dst, self.address, self.data, self.t_issue = id, dst, address, data, t_issue
        self.t_done, self.ok, self.psn = -1.0, None, -1


class Pkt:
    __slots__ = ("psn", "pdus", "ses", "syn", "tx_count", "t_tx")

    def __init__(self, psn, pdus, ses, syn):
        self.psn, self.pdus, self.ses, self.syn, self.tx_count, self.t_tx = psn, pdus, ses, syn, 0, -1.0


class Pdc:
    """Both directions of one PDC with a peer: what we send to it and what we receive from it."""

    def __init__(self, peer, start_psn):
        self.peer = peer
        # transmit
        self.tx_psn = start_psn
        self.acked = start_psn - 1          # highest cumulatively acknowledged PSN
        self.unacked: deque[Pkt] = deque()
        self.retx_q: deque[Pkt] = deque()
        self.syn = True
        self.rto_tok, self.rto_on = 0, False
        # receive
        self.start = None
        self.expect = None
        self.cack = None                    # highest in-order PSN executed (operational ACK)
        self.nack_sent = False
        self.ack_dirty, self.ack_due = False, None


class Endpoint:
    def __init__(self, xpu, n, size=256, bytes_per_peer=32768, senders=None, retx=True, window=64, rto_s=1.0,
                 ack_hold_s=0.002, max_pack=8, max_payload=2048, tx_buf=65536, timers=None, log=None, now=time.monotonic):
        self.id, self.n, self.size, self.now, self.log = xpu, n, size, now, log
        self.retx, self.window, self.rto_s, self.ack_hold_s = retx, window, rto_s, ack_hold_s
        self.max_pack, self.max_payload, self.tx_buf = max_pack, max_payload, tx_buf
        self.timers = timers or Timers()
        self.port: Port | None = None
        self.peers = [p for p in range(n) if p != xpu]
        self.sending = senders is None or xpu in senders
        per_peer = bytes_per_peer // size if self.sending else 0
        self.remaining = {p: per_peer for p in self.peers}
        self.total = per_peer * len(self.peers)
        self.rr = 0
        self.next_id = 0
        self.q = {p: deque() for p in self.peers}
        self.queued = 0
        self.pdcs = {p: Pdc(p, 1000 * (xpu + 1)) for p in self.peers}
        self.ctl_q: deque[TxFrame] = deque()
        self.retx_ready: deque[Pdc] = deque()
        self._plan = None
        self.lat = []
        self.stats = {k: 0 for k in ("tx_pkts", "tx_payload", "rx_pkts", "rx_payload", "acks_tx", "acks_rx", "nacks_tx", "nacks_rx",
                                     "retx_pkts", "rtos", "fatal", "dup_rx", "gap_drops", "done", "failed", "rx_bad_crc",
                                     "rx_unknown_psn", "piggybacked")}
        self.pack_hist = {}
        self.t0 = self.now()
        self.t_finished = None
        self.address = {p: (xpu << 32) for p in self.peers}

    # ------------------------------------------------------------ XPU side
    def _log(self, ev, **kw):
        if self.log is not None:
            self.log(f"xpu{self.id}", ev, kw)

    def issue(self):
        """Hand stores to the transmit queues until the transmit buffer is full."""
        while self.queued < self.tx_buf and any(self.remaining.values()):
            for _ in range(len(self.peers)):
                p = self.peers[self.rr]
                self.rr = (self.rr + 1) % len(self.peers)
                if self.remaining[p]:
                    break
            self.remaining[p] -= 1
            self.next_id += 1
            data = bytes([(self.id * 37 + self.next_id) & 0xFF]) * self.size
            t = Txn(self.next_id, p, self.address[p], data, self.now())
            self.address[p] += self.size
            self.q[p].append(t)
            self.queued += self.size
            self._log("txn_in", id=t.id, dst=p, size=self.size)

    # ------------------------------------------------------------ transmit side: the port's source
    def peek(self):
        if self.ctl_q:
            self._plan = ("ctl", self.ctl_q[0])
            return self.ctl_q[0]
        for _ in range(len(self.retx_ready)):
            p = self.retx_ready[0]
            if not p.retx_q:
                self.retx_ready.popleft()
                continue
            pkt = p.retx_q[0]
            fr = TxFrame(self._req_bytes(p, pkt, retx=True), vc=0, meta=pkt)
            self._plan = ("retx", p, pkt, fr)
            return fr
        best = None
        for p in self.peers:
            q, pdc = self.q[p], self.pdcs[p]
            if not q or len(pdc.unacked) >= self.window or pdc.retx_q:
                continue
            if best is None or q[0].t_issue < best[0][0].t_issue:
                best = (q, pdc)
        if best is None:
            self._plan = None
            return None
        q, pdc = best
        pdus, pay = [], 0
        for t in q:
            if pdus and (len(pdus) >= self.max_pack or pay + len(t.data) > self.max_payload):
                break
            pdus.append(t)
            pay += len(t.data)
        msgs = pack_requests([Req(opcode=C.OP_WRITE, address=t.address, data=t.data) for t in pdus])
        pkt = Pkt(pdc.tx_psn, pdus, b"".join(bytes(m) for m in msgs), pdc.syn)
        fr = TxFrame(self._req_bytes(pdc, pkt, retx=False), vc=0, meta=pkt)
        self._plan = ("req", pdc, pkt, fr)
        return fr

    def pop(self):
        kind = self._plan[0]
        now = self.now()
        if kind == "ctl":
            fr = self.ctl_q.popleft()
            self._plan = None
            return fr
        if kind == "retx":
            _, p, pkt, fr = self._plan
            p.retx_q.popleft()
            if not p.retx_q:
                self.retx_ready.popleft()
            pkt.tx_count += 1
            self.stats["retx_pkts"] += 1
            self._piggyback(p)
            self._log("pkt_tx", dst=p.peer, psn=pkt.psn, n=len(pkt.pdus), retx=True, size=fr.size)
            self._plan = None
            return fr
        _, p, pkt, fr = self._plan
        for t in pkt.pdus:
            self.q[p.peer].popleft()
            t.psn = pkt.psn
        self.queued -= sum(len(t.data) for t in pkt.pdus)
        p.tx_psn += 1
        p.syn = False
        p.unacked.append(pkt)
        pkt.tx_count += 1
        pkt.t_tx = now
        self.stats["tx_pkts"] += 1
        self.stats["tx_payload"] += sum(len(t.data) for t in pkt.pdus)
        self.pack_hist[len(pkt.pdus)] = self.pack_hist.get(len(pkt.pdus), 0) + 1
        self._piggyback(p)
        if not p.rto_on:
            self._start_rto(p)
        self._log("pkt_tx", dst=p.peer, psn=pkt.psn, n=len(pkt.pdus), retx=False, syn=pkt.syn, size=fr.size)
        self._plan = None
        self.issue()
        return fr

    def _piggyback(self, p):
        if p.ack_dirty:
            self.stats["piggybacked"] += 1
            p.ack_dirty, p.ack_due = False, None

    def _rev_cack(self, p):
        return 0 if p.cack is None else p.cack & 0xFFF

    def _req_bytes(self, p, pkt, retx):
        pdc = PDC(dst=p.peer, src=self.id, spdcid=p.peer, dpdcid=self.id, psn=pkt.psn, dscp=0,
                  rev_cack_psn_lsb=self._rev_cack(p))
        hdr = ufh16_rodl_header(pdc, C.NH_REQUEST_LCL, syn=1 if pkt.syn else 0, retx=1 if retx else 0)
        unpadded = bytes(hdr) + pkt.ses
        body = _pad_to_min(unpadded)
        return body + K.crc_bytes(K.ufh16_crc(body, pkt.psn, payload_end=len(unpadded)))

    def _ack_bytes(self, p, ack_psn, nack=False):
        cack = p.cack if p.cack is not None else ack_psn - 1
        off = ((ack_psn - cack + (1 << 31)) % (1 << 32)) - (1 << 31)
        hdr = UFH16Ack(type=C.PDS_TYPE_NACK if nack else C.PDS_TYPE_ACK, next_hdr=C.NH_NONE,
                       dpdcid_hi=self.id >> 4, dpdcid_lo=self.id & 0xF, dst_rsv=p.peer >> 12, dst_addr=p.peer & 0xFFF,
                       dscp=1, spdcid=p.peer, src_entropy=self.id >> 12, src_addr=self.id & 0xFFF,
                       ack_psn_offset_raw=off & 0xFFFF, cack_psn=cack & 0xFFFFFFFF)
        body = _pad_to_min(bytes(hdr))
        return body + K.crc_bytes(K.ufh16_crc(body, None))

    def _send_ctl(self, p, ack_psn, nack=False):
        self.stats["nacks_tx" if nack else "acks_tx"] += 1
        self._log("pkt_tx", dst=p.peer, kind="nack" if nack else "ack", psn=ack_psn, cack=p.cack)
        self.ctl_q.append(TxFrame(self._ack_bytes(p, ack_psn, nack), vc=1))
        if self.port:
            self.port.kick()

    # ------------------------------------------------------------ RODL transmit side
    def _start_rto(self, p):
        p.rto_tok += 1
        p.rto_on = True
        self.timers.after(self.rto_s, self._rto, p, p.rto_tok)

    def _stop_rto(self, p):
        p.rto_tok += 1
        p.rto_on = False

    def _rto(self, p, tok):
        if tok != p.rto_tok:
            return
        p.rto_on = False
        if not p.unacked:
            return
        self.stats["rtos"] += 1
        self._log("rodl", peer=p.peer, what="timeout", psn=p.unacked[0].psn)
        self._go_back(p, p.unacked[0].psn)

    def _go_back(self, p, psn):
        if not self.retx:
            return self._fatal(p)
        if p.retx_q:
            return
        for pkt in p.unacked:
            if pkt.psn >= psn:
                p.retx_q.append(pkt)
        if p.retx_q:
            self._log("rodl", peer=p.peer, what="go_back", psn=p.retx_q[0].psn, n=len(p.retx_q))
            self.retx_ready.append(p)
            self._start_rto(p)
            if self.port:
                self.port.kick()

    def _fatal(self, p):
        self.stats["fatal"] += 1
        self._log("rodl", peer=p.peer, what="fatal", n=sum(len(pkt.pdus) for pkt in p.unacked))
        for pkt in p.unacked:
            for t in pkt.pdus:
                self._complete(t, False)
        p.unacked.clear()
        p.retx_q.clear()
        p.syn = True
        self._stop_rto(p)
        if self.port:
            self.port.kick()

    def _on_ack(self, p, cack, nack_psn=None):
        if cack is not None and cack > p.acked:
            while p.unacked and p.unacked[0].psn <= cack:
                pkt = p.unacked.popleft()
                for t in pkt.pdus:
                    self._complete(t, True)
            while p.retx_q and p.retx_q[0].psn <= cack:
                p.retx_q.popleft()
            p.acked = cack
            self._stop_rto(p)
            if p.unacked:
                self._start_rto(p)
        if nack_psn is not None:
            self.stats["nacks_rx"] += 1
            self._go_back(p, nack_psn)
        if self.port:
            self.port.kick()

    def _full_cack(self, p, lsb):
        """rev_cack_psn_lsb carries 12 bits: the value in (acked, tx_psn) with those low bits, if any."""
        c = (p.acked & ~0xFFF) | lsb
        if c <= p.acked:
            c += 0x1000
        return c if c < p.tx_psn else None

    # ------------------------------------------------------------ receive side: the port's sink
    def on_deliver(self, fr: TxFrame):
        inner = fr.inner
        if not is_ufh16(inner) or inner[12:14] != b"\xe7\x90":
            return
        ptype = inner[1] >> 3
        body, wire = inner[:-C.UET_CRC_LEN], int.from_bytes(inner[-C.UET_CRC_LEN:], C.CRC_BYTE_ORDER)
        if ptype in (C.PDS_TYPE_ACK, C.PDS_TYPE_NACK):
            if K.ufh16_crc(body, None) != wire:
                self.stats["rx_bad_crc"] += 1
                return
            h = UFH16Ack(body)
            p = self.pdcs.get(h.src)
            if p is None:
                return
            nack = ptype == C.PDS_TYPE_NACK
            if not nack:
                self.stats["acks_rx"] += 1
            self._log("pkt_rx", src=h.src, kind="nack" if nack else "ack", cack=h.cack_psn, psn=h.ack_psn)
            self._on_ack(p, h.cack_psn, h.ack_psn if nack else None)
            return
        if ptype != C.PDS_TYPE_RODL:
            return
        h = UFH16RODL(body)
        p = self.pdcs.get(h.src)
        if p is None:
            return
        tail = h.lastlayer()
        end = len(body) - (len(tail) if isinstance(tail, Raw) else 0)
        reg = K.crc32c(self._masked(body))
        if h.syn:
            psn = h.explicit_psn
            if K.crc32c((psn & 0xFFFFFFFF).to_bytes(4, C.PSN_BYTE_ORDER), reg) != wire:
                self.stats["rx_bad_crc"] += 1
                return
        else:
            if p.expect is None:
                self.stats["rx_unknown_psn"] += 1       # the syn packet never arrived: nothing to check against
                return
            psn = self._find_psn(reg, wire, p.expect, h.retx)
            if psn is None:
                self.stats["rx_bad_crc"] += 1
                return
            cack = self._full_cack(p, h.rev_cack_psn_lsb)
            if cack is not None:
                self._on_ack(p, cack)
        self.stats["rx_pkts"] += 1
        if h.syn and psn != p.start:
            p.start = p.expect = psn
            p.cack, p.nack_sent = psn - 1, False
        d = psn - p.expect
        if d == 0:
            p.expect += 1
            p.nack_sent = False
            n = self._execute(h)
            p.cack = psn
            self._log("pkt_rx", src=h.src, res="accept", psn=psn, n=n)
            self._mark_ack(p)
        elif d < 0:
            self.stats["dup_rx"] += 1
            self._log("pkt_rx", src=h.src, res="dup", psn=psn)
            self._mark_ack(p)
        else:
            self.stats["gap_drops"] += 1
            self._log("pkt_rx", src=h.src, res="gap", psn=psn, expect=p.expect)
            if not p.nack_sent:
                p.nack_sent = True
                self._send_ctl(p, p.expect, nack=True)

    @staticmethod
    def _masked(body):
        m = bytearray(body)
        m[C.UFH16_TC_BYTE] = 0
        return bytes(m)

    @staticmethod
    def _find_psn(reg, wire, expect, retx):
        order = [0] + [d for k in range(1, PSN_SEARCH + 1) for d in ((-k, k) if retx else (k, -k))]
        for d in order:
            psn = expect + d
            if psn >= 0 and K.crc32c((psn & 0xFFFFFFFF).to_bytes(4, C.PSN_BYTE_ORDER), reg) == wire:
                return psn
        return None

    def _execute(self, h):
        """The XPU executes the packed stores at once (operational ACK). Returns the CMD_PDU count."""
        n, layer = 0, h.payload
        while layer is not None and not isinstance(layer, Raw) and layer.name != "NoPayload":
            if hasattr(layer, "request_length"):
                n += 1
                self.stats["rx_payload"] += len(getattr(layer, "data", b"") or b"")
            layer = layer.payload if layer.payload else None
        return n

    def _mark_ack(self, p):
        p.ack_dirty = True
        if p.ack_due is None:
            p.ack_due = self.now() + self.ack_hold_s
            self.timers.at(p.ack_due, self._ack_timer, p, p.ack_due)

    def _ack_timer(self, p, due):
        if p.ack_dirty and p.ack_due == due:
            p.ack_dirty, p.ack_due = False, None
            self._send_ctl(p, p.cack)

    def _complete(self, t, ok):
        if t.t_done >= 0:
            return
        t.t_done, t.ok = self.now(), ok
        self.stats["done" if ok else "failed"] += 1
        if ok:
            self.lat.append(t.t_done - t.t_issue)
        self._log("txn", id=t.id, dst=t.dst, ok=ok, lat_ms=round(1000 * (t.t_done - t.t_issue), 3))
        if self.stats["done"] + self.stats["failed"] == self.total and self.t_finished is None:
            self.t_finished = self.now()
            self._log("finished", s=round(self.t_finished - self.t0, 4))

    @property
    def finished(self):
        return self.t_finished is not None or self.total == 0

    def result(self):
        lat = sorted(self.lat)
        pct = lambda q: round(1000 * lat[min(len(lat) - 1, int(q * len(lat)))], 3) if lat else None  # noqa: E731
        r = dict(self.stats)
        r.update(xpu=self.id, total=self.total, pack_hist=self.pack_hist,
                 pack_avg=round(sum(k * v for k, v in self.pack_hist.items()) / max(1, sum(self.pack_hist.values())), 2),
                 finished_s=round(self.t_finished - self.t0, 4) if self.t_finished else None,
                 lat_p50_ms=pct(0.5), lat_p99_ms=pct(0.99), lat_max_ms=round(1000 * lat[-1], 3) if lat else None,
                 lat_mean_ms=round(1000 * statistics.mean(lat), 3) if lat else None,
                 pdcs={p: {"tx_psn": d.tx_psn, "acked": d.acked, "unacked": len(d.unacked), "expect": d.expect, "cack": d.cack}
                       for p, d in self.pdcs.items()})
        if self.port is not None:
            r["port"] = dict(self.port.stats)
            r["port_state"] = self.port.snapshot()
        return r


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--xpu", type=int, required=True)
    ap.add_argument("--n", type=int, required=True)
    ap.add_argument("--ifname", default="eth0")
    ap.add_argument("--out", required=True)
    ap.add_argument("--bytes-per-peer", type=int, default=32768)
    ap.add_argument("--size", type=int, default=256)
    ap.add_argument("--senders", default="", help="comma list of XPUs that send; default all")
    ap.add_argument("--no-retx", action="store_true", help="SUE-lite: no RODL retransmission")
    ap.add_argument("--window", type=int, default=64)
    ap.add_argument("--rto", type=float, default=1.0, help="RODL timer; must exceed LLR's replay_timer x (replay_ct_max + 1)")
    ap.add_argument("--ack-hold", type=float, default=0.002)
    ap.add_argument("--max-pack", type=int, default=8)
    ap.add_argument("--tx-buf", type=int, default=65536)
    ap.add_argument("--ber", type=float, default=0.0)
    ap.add_argument("--drop-cf", type=float, default=0.0)
    ap.add_argument("--no-llr", action="store_true")
    ap.add_argument("--no-cbfc", action="store_true")
    ap.add_argument("--credits", type=int, default=1024)
    ap.add_argument("--sw-credits", type=int, default=1024)
    ap.add_argument("--replay-timer", type=float, default=0.05)
    ap.add_argument("--replay-ct-max", type=int, default=8)
    ap.add_argument("--stall-at", type=float, default=-1.0, help="fault: stop draining the receive buffer at this time")
    ap.add_argument("--stall", type=float, default=0.0, help="... for this many seconds")
    ap.add_argument("--timeout", type=float, default=60.0)
    ap.add_argument("--log", default="")
    a = ap.parse_args(argv)

    T0 = time.monotonic()
    events = []
    log = (lambda who, ev, kw: events.append({"t": round(time.monotonic() - T0, 6), "at": who, "ev": ev, **kw})) if a.log else None
    senders = [int(x) for x in a.senders.split(",")] if a.senders else None
    timers = Timers()
    ep = Endpoint(a.xpu, a.n, size=a.size, bytes_per_peer=a.bytes_per_peer, senders=senders, retx=not a.no_retx,
                  window=a.window, rto_s=a.rto, ack_hold_s=a.ack_hold, max_pack=a.max_pack, tx_buf=a.tx_buf,
                  timers=timers, log=log)
    cfg = PortCfg(llr=not a.no_llr, cbfc=not a.no_cbfc, total_credits=a.credits, ber=a.ber, drop_cf=a.drop_cf,
                  replay_timer_s=a.replay_timer, replay_ct_max=a.replay_ct_max, seed=1 + a.xpu)
    sock = raw_socket(a.ifname)
    port = Port(f"xpu{a.xpu}", cfg, timers, sock.send, xpu_mac(a.xpu), sw_mac(a.xpu), source=ep, sink=ep.on_deliver,
                cl_credits=a.sw_credits, log=log)
    ep.port = port
    loop = Loop(timers)
    loop.ports = [port]
    loop.add(sock, port.on_wire)              # the loop kicks the port once per pass, in bounded bursts
    if a.stall_at >= 0:
        timers.after(a.stall_at, port.stall, a.stall)

    def stop(*_):
        loop.stop = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    done_marker = a.out + ".done"
    ep.issue()
    port.start()
    marked = False
    deadline = time.monotonic() + a.timeout
    while not loop.stop and time.monotonic() < deadline:
        loop.run_once()
        if not marked and ep.finished:
            marked = True
            with open(done_marker, "w") as f:
                json.dump(ep.result(), f)
    res = ep.result()
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

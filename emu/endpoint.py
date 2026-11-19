"""A SUE-T endpoint as a user-space process on one or more veths (SUE-T Base 1.0.0 §6-§7, UEC §3.5.7.3).

What it does, on real frames built by sue/frame.py:
  - one queue per destination XPU; stores of `size` bytes issued round robin over the peers,
    held back by a transmit buffer of `tx_buf` bytes (the XPU interface hand-over is instant)
  - work-conserving packing: up to `max_pack` CMD_PDUs or `max_payload` bytes per packet
  - one PDC per peer over UFH_16: syn on the first packet, hidden PSN in the UET CRC, a window of
    `window` packets; in order (RODL: Go-Back-N on a NACK or the RTO, or SUE-lite) or out of order
    (`order="rud"`: every new PSN accepted, ACKs name the packet they answer, selective resend)
  - operational ACKs: the receiver "executes" a store at once, holds the ACK for `ack_hold` in case a
    request going the other way can carry it (rev_cack_psn_lsb in the UFH_16 header), else sends a
    bare ACK packet on the response VC; a gap is NACKed once with a NACK packet (RODL)
  - the receiver finds a syn=0 packet's PSN the way the dissector does: expected first, then a window
    around it, by recomputing the UET CRC
  - several ports (one per plane, M5b) and three path policies, as in sim/suet.py: "pin" (the port is
    a function of the peer, §6 step 6), "failover" (the PDC moves when its link's carrier drops or
    after RTOs), "spray" (every packet on any usable port; a port is marked bad after timeouts on it
    and comes back when a probe is answered, or after a timer)

Out of order on the wire (decision E9): UFH_16 has formats for RODL requests and ACKs only, so the
sprayed, out-of-order traffic keeps the RODL frame layout. The ACK names the packet it answers in
ack_psn (signed offset from cack_psn, UEC Table 3-52), which is how a UEC sender learns about a
packet beyond the cumulative point; a syn packet carries psn_offset = PSN - start PSN (Fig 3-120), and
the sender keeps syn set until the first ACK, so a receiver learns the start PSN from whichever packet
overtakes the others. Probes are ACK frames with flag 0x40, answered with flag 0x20 on the same port.

Loads, delivery ACKs and ESUN framing are not here yet (the switch forwards ESUN frames by DA).

    ip netns exec xpu0 python -m emu.endpoint --xpu 0 --n 4 --out /tmp/xpu0.json [--planes 4 --path spray --order rud]
"""

import argparse
import json
import os
import random
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
FLAG_PROBE, FLAG_PROBE_REPLY = 0x40, 0x20


class Txn:
    __slots__ = ("id", "dst", "address", "data", "t_issue", "t_done", "ok", "psn")

    def __init__(self, id, dst, address, data, t_issue):
        self.id, self.dst, self.address, self.data, self.t_issue = id, dst, address, data, t_issue
        self.t_done, self.ok, self.psn = -1.0, None, -1


class Pkt:
    __slots__ = ("psn", "pdus", "ses", "syn", "start", "tx_count", "t_tx", "port")

    def __init__(self, psn, pdus, ses, syn, start):
        self.psn, self.pdus, self.ses, self.syn, self.start = psn, pdus, ses, syn, start
        self.tx_count, self.t_tx, self.port = 0, -1.0, -1


class Pdc:
    """Both directions of one PDC with a peer: what we send to it and what we receive from it."""

    def __init__(self, peer, start_psn):
        self.peer = peer
        # transmit
        self.tx_psn = start_psn
        self.tx_start = start_psn
        self.acked = start_psn - 1          # highest cumulatively acknowledged PSN
        self.unacked: deque[Pkt] = deque()
        self.retx_q: deque[Pkt] = deque()
        self.syn = True
        self.rto_tok, self.rto_on = 0, False
        self.streak = 0                     # RTOs without progress
        self.port = None                    # failover: the port we send on now
        self.port_to = {}                   # spray: consecutive timeouts per port
        self.bad = {}                       # spray: port -> time marked bad
        self.rr_port = peer                 # spray: the port this PDC's next packet takes (rotates, like MRC's EVs)
        # receive
        self.start = None
        self.expect = None
        self.cack = None                    # highest in-order PSN executed (operational ACK)
        self.got = set()                    # RUD: PSNs accepted beyond cack
        self.nack_sent = False
        self.ack_dirty, self.ack_due = False, None
        self.rx_port = None                 # where the peer's last packet arrived: ACKs go back that way


class PortSource:
    """The source a Port pulls frames from: the endpoint, asked for what may leave on this port."""

    def __init__(self, ep, q):
        self.ep, self.q = ep, q

    def peek(self):
        return self.ep.peek(self.q)

    def pop(self):
        return self.ep.pop(self.q)


class Endpoint:
    def __init__(self, xpu, n, size=256, bytes_per_peer=32768, senders=None, retx=True, window=64, rto_s=1.0,
                 ack_hold_s=0.002, max_pack=8, max_payload=2048, tx_buf=65536, timers=None, log=None, now=time.monotonic,
                 planes=1, path="pin", order="rodl", rtos_before_move=1, max_rtos=0, restore="probe", probe_s=0.2,
                 seed=1):
        self.id, self.n, self.size, self.now, self.log = xpu, n, size, now, log
        self.retx, self.window, self.rto_s, self.ack_hold_s = retx, window, rto_s, ack_hold_s
        self.max_pack, self.max_payload, self.tx_buf = max_pack, max_payload, tx_buf
        self.P, self.path, self.order = planes, path, order
        self.rtos_before_move, self.max_rtos, self.restore, self.probe_s = rtos_before_move, max_rtos, restore, probe_s
        self.rng = random.Random(seed * 7919 + xpu)
        self.timers = timers or Timers()
        self.ports: list[Port | None] = [None] * planes
        self.carrier = [True] * planes      # what our NIC sees of each link (emu: /sys/class/net/ethN/carrier)
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
        self.ctl_q: deque = deque()         # (port or None, TxFrame): ACKs, NACKs, probes
        self.retx_ready: deque[Pdc] = deque()
        self._plan = {}
        self.lat = []
        self.stats = {k: 0 for k in ("tx_pkts", "tx_payload", "rx_pkts", "rx_payload", "acks_tx", "acks_rx", "nacks_tx", "nacks_rx",
                                     "retx_pkts", "rtos", "fatal", "dup_rx", "gap_drops", "done", "failed", "rx_bad_crc",
                                     "rx_unknown_psn", "piggybacked", "moves", "bad_marks", "restores", "probes")}
        self.pack_hist = {}
        self.port_pkts = [0] * planes
        self.t0 = self.now()
        self.t_finished = None
        self.address = {p: (xpu << 32) for p in self.peers}

    # ------------------------------------------------------------ ports
    @property
    def port(self):
        return self.ports[0]

    @port.setter
    def port(self, p):
        self.ports[0] = p

    def _kick(self):
        for p in self.ports:
            if p is not None:
                p.kick()

    def set_carrier(self, q, up):
        if self.carrier[q] == up:
            return
        self.carrier[q] = up
        self._log("carrier", port=q, up=up)
        if not up and self.path == "failover":
            for p in self.pdcs.values():
                if self._tx_port(p) == q:
                    self._move(p, "carrier down")
        self._kick()

    def _home(self, peer, ack=False):
        return (self.id + peer + (1 if ack else 0)) % self.P

    def _tx_port(self, p):
        if p.port is None:
            p.port = self._home(p.peer)
        return p.port

    def _move(self, p, why):
        others = [q for q in range(self.P) if q != p.port and self.carrier[q]]
        if not others:
            return
        load = {q: sum(1 for x in self.pdcs.values() if x is not p and x.port == q) for q in others}
        low = min(load.values())
        old, p.port = p.port, self.rng.choice([q for q in others if load[q] == low])
        p.streak = 0
        self.stats["moves"] += 1
        self._log("rodl", peer=p.peer, what="move", frm=old, to=p.port, why=why)
        if p.unacked and self.retx and not p.retx_q:         # what left on the old port is presumed lost
            if self.order == "rud":
                p.retx_q.extend(x for x in p.unacked if x.port == old)
                if p.retx_q and p not in self.retx_ready:
                    self.retx_ready.append(p)
            else:
                self._go_back(p, p.unacked[0].psn)

    def _usable(self, p, q):
        if not self.carrier[q]:
            return False
        if q not in p.bad:
            return True
        return all(x in p.bad or not self.carrier[x] for x in range(self.P))

    def _serves(self, q, p):
        if self.path == "pin":
            return q == self._home(p.peer)
        if self.path == "failover":
            return q == self._tx_port(p)
        # spray: rotate over the usable ports (the emulator has no line rate, so "first port with room"
        # would mean "always the first port")
        for k in range(self.P):
            c = (p.rr_port + k) % self.P
            if self._usable(p, c):
                return q == c
        return False

    def _ack_port(self, p):
        if self.path == "pin":
            return self._home(p.peer, ack=True)
        if p.rx_port is not None and self.carrier[p.rx_port]:
            return p.rx_port
        return self._tx_port(p) if self.path == "failover" else None

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

    # ------------------------------------------------------------ transmit side: the ports' source
    def peek(self, q=0):
        for k, (cq, fr) in enumerate(self.ctl_q):
            if cq is None or cq == q:
                self._plan[q] = ("ctl", k, fr)
                return fr
        for _ in range(len(self.retx_ready)):
            p = self.retx_ready[0]
            if not p.retx_q:
                self.retx_ready.popleft()
                continue
            if not self._serves(q, p):
                self.retx_ready.rotate(-1)
                continue
            pkt = p.retx_q[0]
            fr = TxFrame(self._req_bytes(p, pkt, retx=True), vc=0, meta=pkt)
            self._plan[q] = ("retx", p, pkt, fr)
            return fr
        best = None
        for peer in self.peers:
            qu, pdc = self.q[peer], self.pdcs[peer]
            # the window bounds the PSN span in flight (from the oldest unacknowledged PSN), not the count:
            # with SACK a hole would otherwise let the PSN run beyond what the receiver can recover
            if not qu or pdc.tx_psn - (pdc.acked + 1) >= self.window or pdc.retx_q or not self._serves(q, pdc):
                continue
            if best is None or qu[0].t_issue < best[0][0].t_issue:
                best = (qu, pdc)
        if best is None:
            self._plan.pop(q, None)
            return None
        qu, pdc = best
        pdus, pay = [], 0
        for t in qu:
            if pdus and (len(pdus) >= self.max_pack or pay + len(t.data) > self.max_payload):
                break
            pdus.append(t)
            pay += len(t.data)
        msgs = pack_requests([Req(opcode=C.OP_WRITE, address=t.address, data=t.data) for t in pdus])
        pkt = Pkt(pdc.tx_psn, pdus, b"".join(bytes(m) for m in msgs), pdc.syn, pdc.tx_start)
        fr = TxFrame(self._req_bytes(pdc, pkt, retx=False), vc=0, meta=pkt)
        self._plan[q] = ("req", pdc, pkt, fr)
        return fr

    def pop(self, q=0):
        plan = self._plan.pop(q)
        kind = plan[0]
        now = self.now()
        if kind == "ctl":
            _, k, fr = plan
            del self.ctl_q[k]
            return fr
        _, p, pkt, fr = plan
        pkt.port = q
        pkt.t_tx = now
        pkt.tx_count += 1
        self.port_pkts[q] += 1
        p.rr_port = (q + 1) % self.P
        if kind == "retx":
            p.retx_q.popleft()
            if not p.retx_q and self.retx_ready and self.retx_ready[0] is p:
                self.retx_ready.popleft()
            self.stats["retx_pkts"] += 1
            self._piggyback(p)
            self._log("pkt_tx", dst=p.peer, psn=pkt.psn, n=len(pkt.pdus), retx=True, size=fr.size, port=q)
            if not p.rto_on:
                self._arm(p)
            return fr
        for t in pkt.pdus:
            self.q[p.peer].popleft()
            t.psn = pkt.psn
        self.queued -= sum(len(t.data) for t in pkt.pdus)
        p.tx_psn += 1
        if self.order != "rud":
            p.syn = False                                    # RUD: syn on every packet until the first ACK
        p.unacked.append(pkt)
        self.stats["tx_pkts"] += 1
        self.stats["tx_payload"] += sum(len(t.data) for t in pkt.pdus)
        self.pack_hist[len(pkt.pdus)] = self.pack_hist.get(len(pkt.pdus), 0) + 1
        self._piggyback(p)
        if not p.rto_on:
            self._arm(p)
        self._log("pkt_tx", dst=p.peer, psn=pkt.psn, n=len(pkt.pdus), retx=False, syn=pkt.syn, size=fr.size, port=q)
        self.issue()
        return fr

    def _piggyback(self, p):
        if p.ack_dirty and self.order != "rud":
            self.stats["piggybacked"] += 1
            p.ack_dirty, p.ack_due = False, None

    def _rev_cack(self, p):
        return 0 if p.cack is None else p.cack & 0xFFF

    def _req_bytes(self, p, pkt, retx):
        pdc = PDC(dst=p.peer, src=self.id, spdcid=p.peer, dpdcid=self.id, psn=pkt.psn, dscp=0,
                  rev_cack_psn_lsb=self._rev_cack(p) if self.order != "rud" else 0,
                  extra={"psn_offset": (pkt.psn - pkt.start) & 0x3FF})
        hdr = ufh16_rodl_header(pdc, C.NH_REQUEST_LCL, syn=1 if pkt.syn else 0, retx=1 if retx else 0)
        unpadded = bytes(hdr) + pkt.ses
        body = _pad_to_min(unpadded)
        return body + K.crc_bytes(K.ufh16_crc(body, pkt.psn, payload_end=len(unpadded)))

    def _ack_bytes(self, p, ack_psn, nack=False, flags=0):
        cack = p.cack if p.cack is not None else ack_psn - 1
        off = ((ack_psn - cack + (1 << 31)) % (1 << 32)) - (1 << 31)
        hdr = UFH16Ack(type=C.PDS_TYPE_NACK if nack else C.PDS_TYPE_ACK, next_hdr=C.NH_NONE, flags=flags,
                       dpdcid_hi=self.id >> 4, dpdcid_lo=self.id & 0xF, dst_rsv=p.peer >> 12, dst_addr=p.peer & 0xFFF,
                       dscp=1, spdcid=p.peer, src_entropy=self.id >> 12, src_addr=self.id & 0xFFF,
                       ack_psn_offset_raw=off & 0xFFFF, cack_psn=cack & 0xFFFFFFFF)
        body = _pad_to_min(bytes(hdr))
        return body + K.crc_bytes(K.ufh16_crc(body, None))

    def _send_ctl(self, p, ack_psn, nack=False, flags=0, port="ack"):
        if flags & FLAG_PROBE:
            kind = "probe"
        elif flags & FLAG_PROBE_REPLY:
            kind = "probe_reply"
        else:
            kind = "nack" if nack else "ack"
            self.stats["nacks_tx" if nack else "acks_tx"] += 1
        q = self._ack_port(p) if port == "ack" else port
        self._log("pkt_tx", dst=p.peer, kind=kind, psn=ack_psn, cack=p.cack, port=q)
        self.ctl_q.append((q, TxFrame(self._ack_bytes(p, ack_psn, nack, flags), vc=1)))
        self._kick()

    # ------------------------------------------------------------ RODL / RUD transmit side
    def _arm(self, p):
        p.rto_tok += 1
        p.rto_on = True
        if self.order == "rud" and p.unacked:
            waiting = [x.t_tx for x in p.unacked if x not in p.retx_q]
            t = (min(waiting) if waiting else self.now()) + self.rto_s
            self.timers.at(max(t, self.now() + 0.001), self._rto, p, p.rto_tok)
        else:
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
        now = self.now()
        if self.order == "rud":
            lost = [x for x in p.unacked if now - x.t_tx >= self.rto_s - 1e-6 and x not in p.retx_q]
            if not lost:
                self._arm(p)
                return
        else:
            lost = [p.unacked[0]]
        self.stats["rtos"] += 1
        p.streak += 1
        self._log("rodl", peer=p.peer, what="timeout", psn=lost[0].psn, n=len(lost))
        if self.max_rtos and p.streak >= self.max_rtos:
            return self._fatal(p)
        if self.path == "failover" and p.streak >= self.rtos_before_move:
            self._move(p, f"{p.streak} RTO")
        elif self.path == "spray":
            for q in sorted(set(x.port for x in lost)):
                k = p.port_to[q] = p.port_to.get(q, 0) + 1
                if k >= self.rtos_before_move and q not in p.bad:
                    p.bad[q] = now
                    self.stats["bad_marks"] += 1
                    self._log("rodl", peer=p.peer, what="bad", port=q)
                    if self.restore != "never":
                        self.timers.after(self.probe_s, self._restore_tick, p, q, now)
        if self.order == "rud":
            if not self.retx:
                return self._fatal(p)
            p.retx_q.extend(sorted(lost, key=lambda x: x.psn))
            if p not in self.retx_ready:
                self.retx_ready.append(p)
            self._arm(p)
            self._kick()
            return
        self._go_back(p, p.unacked[0].psn)

    def _restore_tick(self, p, q, since):
        if p.bad.get(q) != since:
            return
        if self.restore == "timer":
            self._restore(p, q)
            return
        self.stats["probes"] += 1
        self._send_ctl(p, p.tx_psn, flags=FLAG_PROBE, port=q)
        self.timers.after(self.probe_s, self._restore_tick, p, q, since)

    def _restore(self, p, q):
        if p.bad.pop(q, None) is not None:
            p.port_to[q] = 0
            self.stats["restores"] += 1
            self._log("rodl", peer=p.peer, what="restore", port=q)
            self._kick()

    def _go_back(self, p, psn):
        if not self.retx:
            return self._fatal(p)
        if p.retx_q:
            self._arm(p)
            return
        for pkt in p.unacked:
            if pkt.psn >= psn:
                p.retx_q.append(pkt)
        if p.retx_q:
            self._log("rodl", peer=p.peer, what="go_back", psn=p.retx_q[0].psn, n=len(p.retx_q))
            self.retx_ready.append(p)
            self._arm(p)
            self._kick()

    def _fatal(self, p):
        self.stats["fatal"] += 1
        self._log("rodl", peer=p.peer, what="fatal", n=sum(len(pkt.pdus) for pkt in p.unacked))
        for pkt in p.unacked:
            for t in pkt.pdus:
                self._complete(t, False)
        p.unacked.clear()
        p.retx_q.clear()
        p.syn = True
        p.tx_start = p.tx_psn
        p.streak = 0
        self._stop_rto(p)
        self._kick()

    def _on_ack(self, p, cack, nack_psn=None, sel=None):
        moved = False
        if cack is not None and cack > p.acked:
            while p.unacked and p.unacked[0].psn <= cack:
                self._acked(p, p.unacked.popleft())
                moved = True
            p.acked = cack
        if sel is not None and sel > p.acked:                # RUD: the ACK names a packet beyond cack
            for x in list(p.unacked):
                if x.psn == sel:
                    p.unacked.remove(x)
                    self._acked(p, x)
                    moved = True
                    break
        if moved:
            p.retx_q = deque(x for x in p.retx_q if x in p.unacked)
            p.streak = 0
            p.syn = False if self.order == "rud" else p.syn
            self._stop_rto(p)
            if p.unacked:
                self._arm(p)
        if nack_psn is not None:
            self.stats["nacks_rx"] += 1
            self._go_back(p, nack_psn)
        self._kick()

    def _acked(self, p, pkt):
        if pkt.port >= 0:
            p.port_to[pkt.port] = 0
        for t in pkt.pdus:
            self._complete(t, True)

    def _full_cack(self, p, lsb):
        """rev_cack_psn_lsb carries 12 bits: the value in (acked, tx_psn) with those low bits, if any."""
        c = (p.acked & ~0xFFF) | lsb
        if c <= p.acked:
            c += 0x1000
        return c if c < p.tx_psn else None

    # ------------------------------------------------------------ receive side: the ports' sink
    def deliver_from(self, q):
        return lambda fr: self.on_deliver(fr, q)

    def on_deliver(self, fr: TxFrame, q=0):
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
            if h.flags & FLAG_PROBE:
                self._send_ctl(p, h.ack_psn, flags=FLAG_PROBE_REPLY, port=q)
                return
            if h.flags & FLAG_PROBE_REPLY:
                self._restore(p, q)
                return
            nack = ptype == C.PDS_TYPE_NACK
            if not nack:
                self.stats["acks_rx"] += 1
            self._log("pkt_rx", src=h.src, kind="nack" if nack else "ack", cack=h.cack_psn, psn=h.ack_psn, port=q)
            sel = h.ack_psn if (self.order == "rud" and not nack and h.ack_psn != h.cack_psn) else None
            self._on_ack(p, h.cack_psn, h.ack_psn if nack else None, sel)
            return
        if ptype != C.PDS_TYPE_RODL:
            return
        h = UFH16RODL(body)
        p = self.pdcs.get(h.src)
        if p is None:
            return
        reg = K.crc32c(self._masked(body))
        if h.syn:
            psn = h.explicit_psn
            if K.crc32c((psn & 0xFFFFFFFF).to_bytes(4, C.PSN_BYTE_ORDER), reg) != wire:
                self.stats["rx_bad_crc"] += 1
                return
            start = psn - h.psn_offset
        else:
            if p.expect is None:
                self.stats["rx_unknown_psn"] += 1       # the syn packet never arrived: nothing to check against
                return
            psn = self._find_psn(reg, wire, p.expect, h.retx)
            if psn is None:
                self.stats["rx_bad_crc"] += 1
                return
            start = None
            if self.order != "rud":
                cack = self._full_cack(p, h.rev_cack_psn_lsb)
                if cack is not None:
                    self._on_ack(p, cack)
        self.stats["rx_pkts"] += 1
        p.rx_port = q
        if self.order == "rud":
            return self._rx_rud(p, h, psn, start, q)
        if h.syn and psn != p.start:
            p.start = p.expect = psn
            p.cack, p.nack_sent = psn - 1, False
        d = psn - p.expect
        if d == 0:
            p.expect += 1
            p.nack_sent = False
            n = self._execute(h)
            p.cack = psn
            self._log("pkt_rx", src=h.src, res="accept", psn=psn, n=n, port=q)
            self._mark_ack(p)
        elif d < 0:
            self.stats["dup_rx"] += 1
            self._log("pkt_rx", src=h.src, res="dup", psn=psn, port=q)
            self._mark_ack(p)
        else:
            self.stats["gap_drops"] += 1
            self._log("pkt_rx", src=h.src, res="gap", psn=psn, expect=p.expect, port=q)
            if not p.nack_sent:
                p.nack_sent = True
                self._send_ctl(p, p.expect, nack=True)

    def _reply_port(self, q):
        """MRC answers on the path the packet came in on, so an ACK's loss is blamed on that path only."""
        return q if self.carrier[q] else "ack"

    def _rx_rud(self, p, h, psn, start, q=0):
        if start is not None and start != p.start:           # (re)established: learn the base from psn_offset
            p.start, p.cack, p.expect = start, start - 1, start
            p.got.clear()
        if psn <= p.cack or psn in p.got:
            self.stats["dup_rx"] += 1
            self._log("pkt_rx", src=h.src, res="dup", psn=psn)
            self._send_ctl(p, psn, port=self._reply_port(q))
            return
        n = self._execute(h)
        p.got.add(psn)
        while p.cack + 1 in p.got:
            p.cack += 1
            p.got.discard(p.cack)
        p.expect = p.cack + 1
        self._log("pkt_rx", src=h.src, res="accept", psn=psn, n=n)
        if psn == p.cack and not p.got:
            self._mark_ack(p)                                # in order: coalesce
        else:
            self._send_ctl(p, psn, port=self._reply_port(q))   # beyond a hole: name it at once, on its own path

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
        r.update(xpu=self.id, total=self.total, pack_hist=self.pack_hist, port_pkts=self.port_pkts,
                 pack_avg=round(sum(k * v for k, v in self.pack_hist.items()) / max(1, sum(self.pack_hist.values())), 2),
                 finished_s=round(self.t_finished - self.t0, 4) if self.t_finished else None,
                 lat_p50_ms=pct(0.5), lat_p99_ms=pct(0.99), lat_max_ms=round(1000 * lat[-1], 3) if lat else None,
                 lat_mean_ms=round(1000 * statistics.mean(lat), 3) if lat else None,
                 pdcs={p: {"tx_psn": d.tx_psn, "acked": d.acked, "unacked": len(d.unacked), "expect": d.expect, "cack": d.cack,
                           "port": d.port, "bad": sorted(d.bad)} for p, d in self.pdcs.items()})
        live = [p for p in self.ports if p is not None]
        if live:
            r["port"] = {k: sum(p.stats[k] for p in live) for k in live[0].stats}
            r["port_state"] = live[0].snapshot()
            r["ports"] = [dict(p.stats) for p in live]
        return r


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--xpu", type=int, required=True)
    ap.add_argument("--n", type=int, required=True)
    ap.add_argument("--planes", type=int, default=1)
    ap.add_argument("--ifname", default="eth{p}")
    ap.add_argument("--out", required=True)
    ap.add_argument("--bytes-per-peer", type=int, default=32768)
    ap.add_argument("--size", type=int, default=256)
    ap.add_argument("--senders", default="", help="comma list of XPUs that send; default all")
    ap.add_argument("--no-retx", action="store_true", help="SUE-lite: no RODL retransmission")
    ap.add_argument("--path", default="pin", choices=("pin", "failover", "spray"))
    ap.add_argument("--order", default="rodl", choices=("rodl", "rud"))
    ap.add_argument("--rtos-before-move", type=int, default=1)
    ap.add_argument("--max-rtos", type=int, default=0)
    ap.add_argument("--restore", default="probe", choices=("probe", "timer", "never"))
    ap.add_argument("--probe", type=float, default=0.2)
    ap.add_argument("--window", type=int, default=64)
    ap.add_argument("--rto", type=float, default=1.0, help="RODL timer; must exceed LLR's replay_timer x (replay_ct_max + 1)")
    ap.add_argument("--ack-hold", type=float, default=0.002)
    ap.add_argument("--max-pack", type=int, default=8)
    ap.add_argument("--tx-buf", type=int, default=65536)
    ap.add_argument("--ber", type=float, default=0.0, help="on every port, or see --ber-port")
    ap.add_argument("--ber-port", type=int, default=-1, help="apply --ber only to this port (plane)")
    ap.add_argument("--drop-cf", type=float, default=0.0)
    ap.add_argument("--no-llr", action="store_true")
    ap.add_argument("--no-cbfc", action="store_true")
    ap.add_argument("--credits", type=int, default=1024)
    ap.add_argument("--sw-credits", type=int, default=1024)
    ap.add_argument("--replay-timer", type=float, default=0.05)
    ap.add_argument("--replay-ct-max", type=int, default=8)
    ap.add_argument("--carrier-poll", type=float, default=0.005, help="how often the NIC's link state is read")
    ap.add_argument("--stall-at", type=float, default=-1.0, help="fault: stop draining the receive buffer at this time")
    ap.add_argument("--stall", type=float, default=0.0, help="... for this many seconds")
    ap.add_argument("--timeout", type=float, default=60.0)
    ap.add_argument("--log", default="")
    ap.add_argument("--go-file", default="", help="wait for this file before sending (the lab starts all XPUs together)")
    a = ap.parse_args(argv)

    T0 = time.monotonic()
    events = []
    log = (lambda who, ev, kw: events.append({"t": round(time.monotonic() - T0, 6), "at": who, "ev": ev, **kw})) if a.log else None
    senders = [int(x) for x in a.senders.split(",")] if a.senders else None
    timers = Timers()
    ep = Endpoint(a.xpu, a.n, size=a.size, bytes_per_peer=a.bytes_per_peer, senders=senders, retx=not a.no_retx,
                  window=a.window, rto_s=a.rto, ack_hold_s=a.ack_hold, max_pack=a.max_pack, tx_buf=a.tx_buf,
                  timers=timers, log=log, planes=a.planes, path=a.path, order=a.order, rtos_before_move=a.rtos_before_move,
                  max_rtos=a.max_rtos, restore=a.restore, probe_s=a.probe, seed=1 + a.xpu)
    loop = Loop(timers)
    names = []
    for q in range(a.planes):
        ber = a.ber if a.ber_port in (-1, q) else 0.0
        cfg = PortCfg(llr=not a.no_llr, cbfc=not a.no_cbfc, total_credits=a.credits, ber=ber, drop_cf=a.drop_cf,
                      replay_timer_s=a.replay_timer, replay_ct_max=a.replay_ct_max, seed=1 + a.xpu + 101 * q)
        name = a.ifname.format(p=q)
        names.append(name)
        sock = raw_socket(name)
        port = Port(f"xpu{a.xpu}" if a.planes == 1 else f"xpu{a.xpu}.{q}", cfg, timers, sock.send, xpu_mac(a.xpu),
                    sw_mac(a.xpu), source=PortSource(ep, q), sink=ep.deliver_from(q), cl_credits=a.sw_credits, log=log)
        ep.ports[q] = port
        loop.add(sock, port.on_wire)
    loop.ports = list(ep.ports)
    if a.stall_at >= 0:
        timers.after(a.stall_at, ep.ports[0].stall, a.stall)

    def poll_carrier():
        for q, name in enumerate(names):
            try:
                with open(f"/sys/class/net/{name}/carrier") as f:
                    up = f.read().strip() == "1"
            except OSError:
                up = False
            ep.set_carrier(q, up)
        timers.after(a.carrier_poll, poll_carrier)
    if a.planes > 1:
        timers.after(a.carrier_poll, poll_carrier)

    def stop(*_):
        loop.stop = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    done_marker = a.out + ".done"
    if a.go_file:                                         # every XPU's sockets are open before anyone sends
        with open(a.out + ".ready", "w") as f:
            f.write("1")
        wait_until = time.monotonic() + 30
        while not os.path.exists(a.go_file) and time.monotonic() < wait_until:
            time.sleep(0.005)
    T0 = time.monotonic()
    ep.t0 = ep.now()
    ep.issue()
    for port in ep.ports:
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

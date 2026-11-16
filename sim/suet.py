"""A SUE-T endpoint (SUE-T Base 1.0.0 §6–§7) on top of the M2 link model.

What it models, with the spec step it comes from (§7, Figure 3):
  2–3  CMD_PDUs enter a transmit buffer queued per {dstXPU, TC}; the XPU command interface
       has its own rate, so queues build when it is faster than the ports (§7.3).
  4–5  A work-conserving scheduler: round robin between TCs, arrival order inside a TC. It
       never waits to pack; it packs whatever the chosen queue holds, up to 16 CMD_PDUs
       and the payload caps (§7.3, §7.4). Headers are counted by sim/wire.py.
  6    One RODL PDC per {dstXPU, TC} (§7.5.1): PSNs, a hold buffer, Go-Back-N on NACK or
       timeout (UEC §3.5.7.2–3), or no retransmission at all (SUE-lite: loss closes the PDC,
       §7.5, §7.8). The reverse direction's ACK state rides in the request header; a
       dedicated ACK packet goes out only when no reverse packet carries it in time.
       Ports: fixed per {dstXPU, TC} (§6 step 6) or chosen per packed group (§7.6).
  10   The target checks the expected PSN; a gap gets one NACK and everything after it is
       dropped until the expected PSN arrives.
  ACK modes (§7.1): Delivery ACK = the packet was delivered; the XPU-level response comes
       back later as a command on the response TC. Operational ACK = the XPU has processed
       every CMD_PDU in the packet; a store needs nothing more, a load's data comes back as
       SES responses in an ACK packet.
"""

from collections import Counter, deque
from dataclasses import dataclass, field

from . import wire
from .model import Frame

INF = float("inf")


@dataclass
class SUETCfg:
    ack_mode: str = "operational"   # "delivery" | "operational" (§7.1)
    retx: bool = True               # Go-Back-N retransmission; False = SUE-lite, a loss closes the PDC (§7.8)
    stack: str = "ufh16"            # header stack: "ufh16" | "esun" | "udp" (§8.3, sim/wire.py)
    max_pack: int = 16              # CMD_PDUs per packet (§7.3)
    max_payload: int = 2048         # sum of store payloads per packet (§7.3: 2K, 4K or 8K)
    max_resp_payload: int = 2048    # sum of load payloads per packet
    ehl: int = 0                    # extension header (AxUSER): 0, 1 = 4 B, 2 = 8 B, 3 = 16 B (§8.4.2.2)
    resp_cmd: int = 16              # delivery mode: bytes of the XPU-level response command (§7.1.2)
    tcs: int = 2                    # traffic classes; requests on even TCs, responses and ACKs on odd (§7.3)
    window: int = 64                # RODL packets a PDC may have unacknowledged (hold buffer, §7.2.2)
    rto_ns: float = 20000.0         # PDC retransmission timer: 10x the < 2 µs RTT target (Table 1), and longer
                                    # than LLR's worst case (replay_timer x retries), or RODL retransmits
                                    # what the link is still repairing (docs/experiments/suet-endpoint.md, T4)
    ack_hold_ns: float = 100.0      # wait for a reverse packet to carry the ACK before sending a bare one
    lb: str = "pdc"                 # port choice: "pdc" (fixed per {dstXPU, TC}) | "group" (per packed group, §7.6)
    xpu_gbps: float = 1600.0        # XPU → SUE-T command interface rate (§7.3: may exceed the port rate)
    tx_buf: int = 65536             # transmit buffer, bytes of payload queued before the XPU is held back
    rx_ns: float = 50.0             # unpack and hand to the XPU NOC (RM104 App A: bridge < 100 ns both ways)
    xpu_ns: float = 100.0           # the target XPU's time to execute a command and respond


@dataclass
class Txn:
    """One XPU transaction (a CMD_PDU on the wire). In delivery mode the XPU-level response is a
    second Txn of kind "resp" that refers back to the request."""
    id: int
    src: int
    dst: int
    op: str                         # "store" | "load"
    size: int = 256
    tc: int = 0
    kind: str = "req"               # "req" | "resp"
    ref: "Txn | None" = None
    t_issue: float = 0.0            # accepted from the XPU
    t_enq: float = 0.0              # entered its {dstXPU, TC} queue
    t_tx: float = -1.0              # first left a port
    t_done: float = -1.0            # completed at the issuing XPU (or failed)
    ok: bool = True
    psn: int = -1

    def payload(self) -> int:       # bytes of data this PDU carries
        return self.size if (self.op == "store") == (self.kind == "req") else 0

    def resp_payload(self) -> int:  # bytes its response will carry (operational-mode data ACK)
        return self.size if self.op == "load" and self.kind == "req" else 0


@dataclass
class Pkt:
    """One RODL packet: a request (packed CMD_PDUs, PSN, piggybacked ACK state) or a PDS ACK."""
    src: int
    dst: int
    tc: int                         # traffic class it travels on
    ptc: int                        # traffic class of the PDC it belongs to (ACKs travel on the response TC)
    kind: str                       # "req" | "ack"
    psn: int = -1
    pdus: list = field(default_factory=list)
    cack: int = -1                  # cumulative ACK for the reverse direction
    nack: int = -1                  # expected PSN, when the reverse direction saw a gap
    syn: bool = False               # (re)establishes the PDC: the receiver takes this PSN as expected
    size: int = 0                   # frame bytes, DA to FCS
    data: list = field(default_factory=list)   # ACK with data: [(psn, [load Txn, ...]), ...]
    tx: int = 0
    t_tx: float = 0.0


class Pdc:
    """Both directions of one Packet Delivery Context with a peer, on one TC."""

    def __init__(self, peer, tc):
        self.peer, self.tc = peer, tc
        # transmit (UEC §3.5.8: next PSN, hold buffer, timer)
        self.tx_psn = 0
        self.unacked: deque[Pkt] = deque()
        self.retx_q: deque[Pkt] = deque()
        self.syn = True
        self.rto_tok, self.rto_on = 0, False
        # receive
        self.start = None               # PSN the peer established this PDC with (None: not yet)
        self.expect = 0
        self.nack_sent = False
        self.cack = -1                  # highest PSN we can acknowledge, in order
        self.nack = -1
        self.ack_dirty, self.ack_due = False, INF
        self.done = set()               # operational: PSNs the XPU finished, not yet contiguous
        self.resp_data: deque = deque() # operational: (psn, [load Txn]) waiting for a data ACK packet


class PortTx:
    """What a NIC MAC pulls frames from (sim/mac.py source interface)."""

    def __init__(self, ep, port):
        self.ep, self.port, self._head = ep, port, None

    def peek(self, now):
        if self._head is None:
            self._head = self.ep.next_frame(self.port, now)
        return self._head

    def pop(self):
        fr, self._head = self._head, None
        return fr


class Endpoint:
    def __init__(self, sim, xpu: int, cfg: SUETCfg, ports: int, fids, workload=None):
        self.sim, self.id, self.cfg, self.P, self.fids = sim, xpu, cfg, ports, fids
        self.workload = workload
        self.macs = [None] * ports
        self.q: dict[tuple, deque] = {}
        self.pdcs: dict[tuple, Pdc] = {}
        self.ack_ready: dict[Pdc, None] = {}        # PDCs with an ACK to send, in the order they became due
        self.retx_ready: deque[Pdc] = deque()
        self.rr = 0
        self.queued = 0                     # payload bytes in the transmit buffer
        self.xpu_busy = False
        self.pack_hist = Counter()
        self.lat: list[float] = []
        self.stats = {k: 0 for k in (
            "tx_pkts", "tx_wire", "tx_payload", "rx_pkts", "acks_tx", "acks_rx", "nacks_tx", "nacks_rx",
            "retx_pkts", "rtos", "fatal", "dup_rx", "gap_drops", "done", "failed", "xpu_stalls")}

    # ------------------------------------------------------------ helpers
    def _log(self, ev, **kw):
        if self.sim.trace is not None:
            self.sim.log(ev, xpu=self.id, **kw)

    def pdc(self, peer, tc) -> Pdc:
        p = self.pdcs.get((peer, tc))
        if p is None:
            p = self.pdcs[(peer, tc)] = Pdc(peer, tc)
        return p

    def port_of(self, dst, tc):
        """§6 step 6: the port is a function of {dstXPU, TC}; None under per-group balancing (§7.6).
        Our own id goes into the hash too, or every XPU would reach a given destination over the same
        plane and that destination would receive on one port only."""
        return None if self.cfg.lb == "group" else (self.id + dst + tc) % self.P

    def _kick(self, port):
        for m in (self.macs if port is None else [self.macs[port]]):
            if m is not None:
                m.kick()

    def _serves(self, port, dst, tc):
        p = self.port_of(dst, tc)
        return p is None or p == port

    # ------------------------------------------------------------ XPU command interface (§8.2)
    def kick_xpu(self):
        if self.xpu_busy or self.workload is None:
            return
        if self.queued >= self.cfg.tx_buf:
            self.stats["xpu_stalls"] += 1   # per-TC flow control toward the XPU (§7.3), counted once per hold
            return
        t = self.workload.next_txn(self.id, self.sim.now)
        if t is None:
            return
        self.xpu_busy = True
        self.sim.after((t.payload() + 16) / (self.cfg.xpu_gbps / 8.0), self._xpu_in, t)   # command + data words

    def _xpu_in(self, t: Txn):
        self.xpu_busy = False
        self.enqueue(t)
        self.kick_xpu()

    def enqueue(self, t: Txn):
        t.t_enq = self.sim.now
        key = (t.dst, t.tc)
        q = self.q.get(key)
        if q is None:
            q = self.q[key] = deque()
        q.append(t)
        self.queued += t.payload()
        self._kick(self.port_of(t.dst, t.tc))

    # ------------------------------------------------------------ transmit scheduler (§7 steps 4–6)
    def next_frame(self, port, now):
        pkt = self._next_ack(port, now) or self._next_retx(port) or self._next_req(port, now)
        if pkt is None:
            return None
        pkt.tx += 1
        pkt.t_tx = now
        self.stats["tx_pkts"] += 1
        self.stats["tx_wire"] += wire.on_wire(pkt.size)
        fr = Frame(next(self.fids), pkt.size, vc=pkt.tc, dst=pkt.dst, pkt=pkt, born=now)
        self._log("pkt_tx", fid=fr.fid, kind=pkt.kind, dst=pkt.dst, tc=pkt.tc, psn=pkt.psn, n=len(pkt.pdus),
                  cack=pkt.cack, nack=pkt.nack, retx=pkt.tx > 1, size=pkt.size, port=port,
                  pdus=[t.id for t in pkt.pdus], data=sum(len(d[1]) for d in pkt.data))
        return fr

    def _next_ack(self, port, now):
        for p in list(self.ack_ready):
            rtc = p.tc | 1                                  # ACKs travel on the response class
            if not self._serves(port, p.peer, rtc):
                continue
            pkt = Pkt(self.id, p.peer, rtc, p.tc, "ack", cack=p.cack, nack=p.nack)
            sizes, cap = [], self.cfg.max_resp_payload
            while p.resp_data and sum(sizes) + sum(t.size for t in p.resp_data[0][1]) <= cap:
                psn, loads = p.resp_data.popleft()
                pkt.data.append((psn, loads))
                sizes += [t.size for t in loads]
            pkt.size = wire.packet_bytes(self.cfg.stack, "ack", wire.ses_responses(sizes, self.cfg.ehl))
            self.stats["nacks_tx" if p.nack >= 0 else "acks_tx"] += 1
            self.stats["tx_payload"] += sum(sizes)
            p.nack, p.ack_dirty, p.ack_due = -1, False, INF
            self.ack_ready.pop(p)
            if p.resp_data:
                self.ack_ready[p] = None                    # more data to return: back of the queue
            return pkt
        return None

    def _next_retx(self, port):
        for _ in range(len(self.retx_ready)):
            p = self.retx_ready.popleft()
            if not p.retx_q:
                continue
            if not self._serves(port, p.peer, p.tc):
                self.retx_ready.append(p)
                continue
            pkt = p.retx_q.popleft()
            pkt.cack, pkt.nack = p.cack, p.nack             # carry the latest ACK state
            p.nack, p.ack_dirty, p.ack_due = -1, False, INF
            if not p.resp_data:
                self.ack_ready.pop(p, None)
            if p.retx_q:
                self.retx_ready.append(p)
            self.stats["retx_pkts"] += 1
            return pkt
        return None

    def _next_req(self, port, now):
        c = self.cfg
        for k in range(c.tcs):
            tc = (self.rr + k) % c.tcs
            best = None
            for (dst, qtc), q in self.q.items():
                if qtc != tc or not q or not self._serves(port, dst, tc):
                    continue
                p = self.pdc(dst, tc)
                if len(p.unacked) >= c.window or p.retx_q:
                    continue                                 # window full, or replaying: keep order
                if best is None or q[0].t_enq < best[1][0].t_enq:
                    best = ((dst, tc), q, p)
            if best is None:
                continue
            (dst, tc), q, p = best
            self.rr = (tc + 1) % c.tcs
            pdus, pay, rpay, ses = [], 0, 0, 0
            while q and len(pdus) < c.max_pack:
                t = q[0]
                pl, rl = t.payload(), t.resp_payload()
                if pdus and (pay + pl > c.max_payload or rpay + rl > c.max_resp_payload):
                    break
                q.popleft()
                hdr = c.resp_cmd if t.kind == "resp" else wire.req_hdr_bytes(len(pdus), c.ehl)
                ses += hdr + wire.pad4(pl)
                pdus.append(t)
                pay += pl
                rpay += rl
            pkt = Pkt(self.id, dst, tc, tc, "req", psn=p.tx_psn, pdus=pdus, cack=p.cack, nack=p.nack, syn=p.syn,
                      size=wire.packet_bytes(c.stack, "req", ses))
            p.tx_psn += 1
            p.syn = False
            p.unacked.append(pkt)
            p.nack, p.ack_dirty, p.ack_due = -1, False, INF
            if not p.resp_data:
                self.ack_ready.pop(p, None)
            for t in pdus:
                t.psn = pkt.psn
                if t.t_tx < 0:
                    t.t_tx = now
            self.queued -= pay
            self.pack_hist[len(pdus)] += 1
            self.stats["tx_payload"] += pay
            if not p.rto_on:
                self._start_rto(p)
            self.kick_xpu()
            return pkt
        return None

    # ------------------------------------------------------------ RODL transmit side
    def _start_rto(self, p):
        p.rto_tok += 1
        p.rto_on = True
        self.sim.after(self.cfg.rto_ns, self._rto, p, p.rto_tok)

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
        self._log("rodl", peer=p.peer, tc=p.tc, what="timeout", psn=p.unacked[0].psn)
        self._go_back(p, p.unacked[0].psn)

    def _go_back(self, p, psn):
        """Go-Back-N: resend everything from `psn` (UEC §3.5.7.2), or give up the PDC (SUE-lite)."""
        if not self.cfg.retx:
            return self._fatal(p)
        if p.retx_q:
            return                                           # a replay is already queued
        for pkt in p.unacked:
            if pkt.psn >= psn:
                p.retx_q.append(pkt)
        if p.retx_q:
            self._log("rodl", peer=p.peer, tc=p.tc, what="go_back", psn=p.retx_q[0].psn, n=len(p.retx_q))
            self.retx_ready.append(p)
            self._start_rto(p)
            self._kick(self.port_of(p.peer, p.tc))

    def _fatal(self, p):
        self.stats["fatal"] += 1
        n = sum(len(pkt.pdus) for pkt in p.unacked)
        self._log("rodl", peer=p.peer, tc=p.tc, what="fatal", n=n)
        for pkt in p.unacked:
            for t in pkt.pdus:
                self._complete(t.ref if t.kind == "resp" else t, False)
        p.unacked.clear()
        p.retx_q.clear()
        p.syn = True                                         # the next packet re-establishes the PDC
        self._stop_rto(p)
        self._kick(self.port_of(p.peer, p.tc))

    def _on_ack(self, p, cack, nack):
        if cack >= 0:
            moved = False
            while p.unacked and p.unacked[0].psn <= cack:
                pkt = p.unacked.popleft()
                moved = True
                if self.cfg.ack_mode == "operational":
                    for t in pkt.pdus:
                        if t.op == "store":
                            self._complete(t, True)          # loads complete when their data ACK arrives
            while p.retx_q and p.retx_q[0].psn <= cack:
                p.retx_q.popleft()
            if moved:
                self._stop_rto(p)
                if p.unacked:
                    self._start_rto(p)
                self._kick(self.port_of(p.peer, p.tc))      # the window may have opened
        if nack >= 0:
            self.stats["nacks_rx"] += 1
            self._go_back(p, nack)

    # ------------------------------------------------------------ receive side (§7 steps 9–11)
    def on_frame(self, fr: Frame, now):
        pkt = fr.pkt
        p = self.pdc(pkt.src, pkt.ptc)
        self._on_ack(p, pkt.cack, pkt.nack)
        if pkt.kind == "ack":
            self.stats["acks_rx"] += 1
            for psn, loads in pkt.data:
                for t in loads:
                    self._complete(t, True)
            self._log("pkt_rx", fid=fr.fid, res="ack", src=pkt.src)
            return
        self.stats["rx_pkts"] += 1
        if pkt.syn and pkt.psn != p.start:
            # a new PDC (first packet, or re-established after a fatal error): take its PSN as expected.
            # A retransmitted first packet carries syn too; with the same start PSN it is a duplicate below.
            p.start = p.expect = pkt.psn
            p.cack, p.nack_sent = pkt.psn - 1, False
            p.done.clear()
        d = pkt.psn - p.expect
        if d == 0:
            p.expect += 1
            p.nack_sent = False
            if self.cfg.ack_mode == "delivery":
                p.cack = pkt.psn
                self._mark_ack(p)
            self._log("pkt_rx", fid=fr.fid, res="accept", src=pkt.src, psn=pkt.psn)
            self.sim.after(self.cfg.rx_ns, self._to_xpu, p, pkt)
        elif d < 0:
            self.stats["dup_rx"] += 1
            self._log("pkt_rx", fid=fr.fid, res="dup", src=pkt.src, psn=pkt.psn)
            self._mark_ack(p)
        else:
            self.stats["gap_drops"] += 1
            self._log("pkt_rx", fid=fr.fid, res="gap", src=pkt.src, psn=pkt.psn, expect=p.expect)
            if not p.nack_sent:
                p.nack_sent, p.nack = True, p.expect
                self._ack_now(p)

    def _to_xpu(self, p, pkt):
        for t in pkt.pdus:
            if t.kind == "resp":
                self._complete(t.ref, True)                  # delivery mode: the response command arrived
            elif self.workload is not None:
                self.workload.on_receive(self.id, t, self.sim.now)
        if any(t.kind == "req" for t in pkt.pdus):
            self.sim.after(self.cfg.xpu_ns, self._xpu_done, p, pkt)

    def _xpu_done(self, p, pkt):
        now = self.sim.now
        if self.cfg.ack_mode == "delivery":
            for t in pkt.pdus:
                if t.kind == "req":
                    self.enqueue(Txn(next(self.fids), self.id, pkt.src, t.op, t.size, t.tc | 1, "resp", t, t_issue=now))
            return
        p.done.add(pkt.psn)
        while p.cack + 1 in p.done:
            p.cack += 1
            p.done.remove(p.cack)
        loads = [t for t in pkt.pdus if t.op == "load" and t.kind == "req"]
        if loads:
            p.resp_data.append((pkt.psn, loads))
            self._ack_now(p)
        else:
            self._mark_ack(p)

    def _mark_ack(self, p):
        p.ack_dirty = True
        if p.ack_due == INF:
            p.ack_due = self.sim.now + self.cfg.ack_hold_ns
            self.sim.at(p.ack_due, self._ack_timer, p, p.ack_due)

    def _ack_timer(self, p, due):
        if p.ack_dirty and p.ack_due == due:
            self._ack_now(p)

    def _ack_now(self, p):
        if p not in self.ack_ready:
            self.ack_ready[p] = None
        self._kick(self.port_of(p.peer, p.tc | 1))

    def _complete(self, t: Txn, ok: bool):
        if t.t_done >= 0:
            return
        t.t_done, t.ok = self.sim.now, ok
        self.stats["done" if ok else "failed"] += 1
        if ok:
            self.lat.append(t.t_done - t.t_issue)
        self._log("txn", id=t.id, dst=t.dst, op=t.op, ok=ok, lat=round(t.t_done - t.t_issue, 1))
        if self.workload is not None:
            self.workload.on_done(t, self.sim.now)

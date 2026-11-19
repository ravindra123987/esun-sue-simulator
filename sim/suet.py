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
    # ---- multi-plane recovery (M5, docs/where-should-retry-live.md). SUE-T 1.0 leaves failover to future
    # work (§7.5), so "pin" is the spec; the others are what an implementation, MetaRoCE or MRC would add.
    path: str = "pin"               # "pin": port fixed per {dstXPU, TC} (§6 step 6), never moves
                                    # "failover": the PDC moves to another port (local link down, or RTOs)
                                    # "spray": every packet may take any usable port (MRC EVs, MetaRoCE flows)
    order: str = "rodl"             # "rodl": in order, Go-Back-N | "rud": out of order, SACK, selective resend
    rtos_before_move: int = 1       # failover: RTOs without progress before the PDC moves;
                                    # spray: timeouts on a port before that port is marked bad
    move_to: str = "least"          # failover target: "least" loaded port | "random" (MetaRoCE §7.5.4)
    max_rtos: int = 0               # RTOs without progress before the PDC is declared dead (fatal); 0 = never
    restore: str = "probe"          # spray: how a bad port comes back: "probe" (MRC) | "timer" (MetaRoCE) | "never"
    probe_ns: float = 20000.0       # probe / restore interval for bad ports
    detect_ns: float = 1000.0       # an endpoint sees its own link down after this long (PCS link fault)
    seed: int = 1


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
    sack: frozenset = frozenset()   # RUD: PSNs beyond cack already executed (selective ACK)
    start: int = -1                 # with syn: the PDC's start PSN (UFH_16 carries it as psn_offset, UEC §3.5.8)
    nacks: frozenset = frozenset()  # RUD: PSNs whose packets arrived trimmed: resend these now
    port: int = -1                  # the port (plane) it last left on


class Pdc:
    """Both directions of one Packet Delivery Context with a peer, on one TC."""

    def __init__(self, peer, tc):
        self.peer, self.tc = peer, tc
        # transmit (UEC §3.5.8: next PSN, hold buffer, timer)
        self.tx_psn = 0
        self.unacked: deque[Pkt] = deque()
        self.retx_q: deque[Pkt] = deque()
        self.syn = True
        self.tx_start = 0               # PSN the current establishment started at
        self.rto_tok, self.rto_on = 0, False
        # receive
        self.start = None               # PSN the peer established this PDC with (None: not yet)
        self.expect = 0
        self.nack_sent = False
        self.cack = -1                  # highest PSN we can acknowledge, in order
        self.nack = -1
        self.ack_dirty, self.ack_due = False, INF
        self.done = set()               # operational: PSNs the XPU finished, not yet contiguous (RUD: the SACK set)
        self.resp_data: deque = deque() # operational: (psn, [load Txn]) waiting for a data ACK packet
        # multi-plane state (M5)
        self.port = None                # failover: the port this PDC sends on now
        self.rx_port = None             # the port the peer's last packet arrived on: ACKs go back that way
        self.streak = 0                 # RTOs without progress
        self.port_to = {}               # spray: consecutive timeouts per port
        self.bad = {}                   # spray: port -> when it was marked bad
        self.got = set()                # RUD receive: PSNs accepted beyond cack
        self.trim_nacks = set()         # RUD receive: trimmed PSNs to NACK


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
        self.rng = __import__("random").Random(cfg.seed * 7919 + xpu)
        self.probe_q: deque = deque()       # (port, Pkt): probes and probe answers (spray, restore="probe")
        if cfg.order == "rud" and cfg.ack_mode != "operational":
            raise ValueError("RUD is modelled with operational ACKs only")
        self.queued = 0                     # payload bytes in the transmit buffer
        self.xpu_busy = False
        self.pack_hist = Counter()
        self.lat: list[float] = []
        self.stats = {k: 0 for k in (
            "tx_pkts", "tx_wire", "tx_payload", "rx_pkts", "acks_tx", "acks_rx", "nacks_tx", "nacks_rx",
            "retx_pkts", "rtos", "fatal", "dup_rx", "gap_drops", "done", "failed", "xpu_stalls",
            "moves", "bad_marks", "restores", "probes", "trims_rx", "trim_resends")}

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
        if self.cfg.lb == "group" or self.cfg.path != "pin":
            return None
        return (self.id + dst + tc) % self.P

    def _kick(self, port):
        for m in (self.macs if port is None else [self.macs[port]]):
            if m is not None:
                m.kick()

    def local_up(self, port) -> bool:
        """Our own link on `port` as the NIC sees it: down once a down interval has lasted detect_ns."""
        m = self.macs[port]
        if m is None:
            return True
        now = self.sim.now
        return not any(a + self.cfg.detect_ns <= now < b for a, b in m.wire.cfg.down)

    def _tx_port(self, p):
        """failover: the PDC's current port; it leaves a port whose link it sees down."""
        if p.port is None:
            p.port = (self.id + p.peer + p.tc) % self.P
            for q in self.pdcs.values():                     # every PDC's home port is known before any move
                if q.port is None:
                    q.port = (self.id + q.peer + q.tc) % self.P
        if not self.local_up(p.port):
            self._move(p, "local link down")
        return p.port

    def _move(self, p, why):
        others = [q for q in range(self.P) if q != p.port and self.local_up(q)]
        if not others:
            return
        if self.cfg.move_to == "least":                      # the port carrying the fewest of our PDCs
            load = {q: sum(1 for x in self.pdcs.values() if x is not p and x.port == q) for q in others}
            low = min(load.values())
            others = [q for q in others if load[q] == low]
        old, p.port = p.port, self.rng.choice(others)
        p.streak = 0
        self.stats["moves"] += 1
        self._log("rodl", peer=p.peer, tc=p.tc, what="move", frm=old, to=p.port, why=why)
        if p.unacked and self.cfg.retx:                      # what left on the old port is presumed lost
            if self.cfg.order == "rud":
                gone = [x for x in p.unacked if x.port == old and x not in p.retx_q]
                if gone:
                    p.retx_q.extend(gone)
                    if p not in self.retx_ready:
                        self.retx_ready.append(p)
            elif not p.retx_q:
                self._go_back(p, p.unacked[0].psn)

    def _usable(self, p, port):
        if not self.local_up(port):
            return False
        if port not in p.bad:
            return True
        return all(q in p.bad or not self.local_up(q) for q in range(self.P))   # nothing better: use it anyway

    def _serves(self, port, p, ack=False):
        c = self.cfg
        if c.path == "pin":
            q = self.port_of(p.peer, (p.tc | 1) if ack else p.tc)
            return q is None or q == port
        if ack:     # back the way the peer's data came (MRC answers on the EV; MetaRoCE spec §8.1.3)
            want = p.rx_port if p.rx_port is not None and self.local_up(p.rx_port) else None
            if want is None:
                want = self._tx_port(p) if c.path == "failover" else None
            return (want is None and self.local_up(port)) or want == port
        if c.path == "failover":
            return port == self._tx_port(p)
        return self._usable(p, port)

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
        self._log("txn_in", id=t.id, dst=t.dst, op=t.op, size=t.size, tc=t.tc, kind=t.kind,
                  ref=t.ref.id if t.ref is not None else None)
        key = (t.dst, t.tc)
        q = self.q.get(key)
        if q is None:
            q = self.q[key] = deque()
        q.append(t)
        self.queued += t.payload()
        self._kick(self.port_of(t.dst, t.tc))

    # ------------------------------------------------------------ transmit scheduler (§7 steps 4–6)
    def next_frame(self, port, now):
        pkt = (self._next_probe(port) or self._next_ack(port, now) or self._next_retx(port)
               or self._next_req(port, now))
        if pkt is None:
            return None
        pkt.tx += 1
        pkt.t_tx = now
        pkt.port = port
        self.stats["tx_pkts"] += 1
        self.stats["tx_wire"] += wire.on_wire(pkt.size)
        fr = Frame(next(self.fids), pkt.size, vc=pkt.tc, dst=pkt.dst, pkt=pkt, born=now)
        self._log("pkt_tx", fid=fr.fid, kind=pkt.kind, dst=pkt.dst, tc=pkt.tc, psn=pkt.psn, n=len(pkt.pdus),
                  cack=pkt.cack, nack=pkt.nack, retx=pkt.tx > 1, size=pkt.size, port=port,
                  pdus=[t.id for t in pkt.pdus], data=sum(len(d[1]) for d in pkt.data),
                  pay=sum(t.payload() for t in pkt.pdus) + sum(t.size for _, L in pkt.data for t in L))
        return fr

    def _next_probe(self, port):
        for k, (q, pkt) in enumerate(self.probe_q):
            if q == port:
                del self.probe_q[k]
                return pkt
        return None

    def _next_ack(self, port, now):
        for p in list(self.ack_ready):
            rtc = p.tc | 1                                  # ACKs travel on the response class
            if not self._serves(port, p, ack=True):
                continue
            pkt = Pkt(self.id, p.peer, rtc, p.tc, "ack", cack=p.cack, nack=p.nack,
                      sack=frozenset(p.done) if self.cfg.order == "rud" else frozenset(), nacks=self._take_nacks(p))
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
            if not self._serves(port, p):
                self.retx_ready.append(p)
                continue
            pkt = p.retx_q.popleft()
            pkt.cack, pkt.nack = p.cack, p.nack             # carry the latest ACK state
            if self.cfg.order == "rud":
                pkt.sack = frozenset(p.done)
                pkt.nacks = self._take_nacks(p)
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
                if qtc != tc or not q:
                    continue
                p = self.pdc(dst, tc)
                if not self._serves(port, p):
                    continue
                oldest = p.unacked[0].psn if p.unacked else p.tx_psn
                if p.tx_psn - oldest >= c.window or p.retx_q:
                    continue                                 # window (PSN span from the oldest unacked) full, or replaying
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
                      size=wire.packet_bytes(c.stack, "req", ses),
                      sack=frozenset(p.done) if c.order == "rud" else frozenset(), start=p.tx_start,
                      nacks=self._take_nacks(p))
            p.tx_psn += 1
            if c.order != "rud":
                p.syn = False                                # RUD: syn on every packet until the first ACK
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

    def _arm_oldest(self, p):
        p.rto_tok += 1
        p.rto_on = True
        t = min(x.t_tx for x in p.unacked) + self.cfg.rto_ns
        self.sim.at(max(self.sim.now + 1.0, t), self._rto, p, p.rto_tok)

    def _stop_rto(self, p):
        p.rto_tok += 1
        p.rto_on = False

    def _rto(self, p, tok):
        if tok != p.rto_tok:
            return
        p.rto_on = False
        if not p.unacked:
            return
        c, now = self.cfg, self.sim.now
        if c.order == "rud":
            queued = set(id(x) for x in p.retx_q)
            lost = [x for x in p.unacked if now - x.t_tx >= c.rto_ns - 1e-6 and id(x) not in queued]
            if not lost:
                waiting = [x.t_tx for x in p.unacked if id(x) not in queued]
                p.rto_tok += 1
                p.rto_on = True                              # all overdue packets already wait for a port
                t = min(waiting) + c.rto_ns if waiting else now + c.rto_ns
                self.sim.at(max(now + 1.0, t), self._rto, p, p.rto_tok)
                return
        else:
            lost = [p.unacked[0]]
        self.stats["rtos"] += 1
        p.streak += 1
        self._log("rodl", peer=p.peer, tc=p.tc, what="timeout", psn=lost[0].psn, n=len(lost))
        if c.max_rtos and p.streak >= c.max_rtos:
            return self._fatal(p)
        if c.path == "failover" and p.streak >= c.rtos_before_move:
            self._move(p, f"{p.streak} RTO")
        elif c.path == "spray":
            for port in sorted(set(x.port for x in lost)):
                n = p.port_to[port] = p.port_to.get(port, 0) + 1
                if n >= c.rtos_before_move and port not in p.bad:
                    p.bad[port] = now
                    self.stats["bad_marks"] += 1
                    self._log("rodl", peer=p.peer, tc=p.tc, what="bad", port=port)
                    self._schedule_restore(p, port)
        if c.order == "rud":
            if not c.retx:
                return self._fatal(p)
            for x in sorted(lost, key=lambda x: x.psn):
                p.retx_q.append(x)
            if p not in self.retx_ready:
                self.retx_ready.append(p)
            self._start_rto(p)
            self._kick(None)
            return
        self._go_back(p, p.unacked[0].psn)

    # ------------------------------------------------------------ bad ports come back (spray)
    def _schedule_restore(self, p, port):
        if self.cfg.restore == "never":
            return
        self.sim.after(self.cfg.probe_ns, self._restore_tick, p, port, p.bad[port])

    def _restore_tick(self, p, port, since):
        if p.bad.get(port) != since:
            return
        if self.cfg.restore == "timer":
            self._restore(p, port)
            return
        self.stats["probes"] += 1
        self.probe_q.append((port, Pkt(self.id, p.peer, p.tc | 1, p.tc, "probe", size=64)))
        self._kick(port)
        self.sim.after(self.cfg.probe_ns, self._restore_tick, p, port, since)

    def _restore(self, p, port):
        if p.bad.pop(port, None) is not None:
            p.port_to[port] = 0
            self.stats["restores"] += 1
            self._log("rodl", peer=p.peer, tc=p.tc, what="restore", port=port)
            self._kick(None)

    def _go_back(self, p, psn):
        """Go-Back-N: resend everything from `psn` (UEC §3.5.7.2), or give up the PDC (SUE-lite)."""
        if not self.cfg.retx:
            return self._fatal(p)
        if p.retx_q:
            self._start_rto(p)                               # a replay is already queued: keep timing it
            return
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
        p.tx_start = p.tx_psn
        self._stop_rto(p)
        self._kick(self.port_of(p.peer, p.tc))

    @staticmethod
    def _take_nacks(p):
        if not p.trim_nacks:
            return frozenset()
        n = frozenset(p.trim_nacks)
        p.trim_nacks.clear()
        return n

    def _on_ack(self, p, cack, nack, sack=frozenset(), nacks=frozenset()):
        if nacks:                                            # trimmed: congestion, not a path failure
            queued = set(id(x) for x in p.retx_q)
            for x in p.unacked:
                if x.psn in nacks and id(x) not in queued:
                    p.retx_q.append(x)
                    self.stats["trim_resends"] += 1
            if p.retx_q and p not in self.retx_ready:
                self.retx_ready.append(p)
            self._kick(None)
        if cack >= 0 or sack:
            moved = False
            while p.unacked and p.unacked[0].psn <= cack:
                pkt = p.unacked.popleft()
                moved = True
                self._acked(p, pkt)
            if sack and p.unacked:
                keep = deque()
                for pkt in p.unacked:
                    if pkt.psn in sack:
                        moved = True
                        self._acked(p, pkt)
                    else:
                        keep.append(pkt)
                p.unacked = keep
            if p.retx_q:
                p.retx_q = deque(x for x in p.retx_q if x.psn > cack and x.psn not in sack)
            if moved:
                p.streak = 0
                p.syn = False                                # established: the peer has acknowledged
                self._stop_rto(p)
                if p.unacked:
                    if self.cfg.order == "rud":
                        self._arm_oldest(p)                  # a hole stays visible while others complete
                    else:
                        self._start_rto(p)
                self._kick(self.port_of(p.peer, p.tc))      # the window may have opened
        if nack >= 0:
            self.stats["nacks_rx"] += 1
            self._go_back(p, nack)

    def _acked(self, p, pkt):
        if pkt.port >= 0:
            p.port_to[pkt.port] = 0
        if self.cfg.ack_mode == "operational":
            for t in pkt.pdus:
                if t.op == "store":
                    self._complete(t, True)              # loads complete when their data ACK arrives

    # ------------------------------------------------------------ receive side (§7 steps 9–11)
    def on_frame(self, fr: Frame, now):
        pkt = fr.pkt
        p = self.pdc(pkt.src, pkt.ptc)
        if pkt.kind == "probe":                              # answer on the port it came in on
            self.probe_q.append((pkt.port, Pkt(self.id, pkt.src, pkt.tc, pkt.ptc, "probe_ack", size=64, port=pkt.port)))
            self._kick(pkt.port)
            return
        if pkt.kind == "probe_ack":
            self._restore(p, pkt.port)
            return
        p.rx_port = pkt.port
        self._on_ack(p, pkt.cack, pkt.nack, pkt.sack, pkt.nacks)
        if fr.trimmed:                                       # only the headers arrived: NACK it at once
            if pkt.kind == "req" and pkt.psn > p.cack and pkt.psn not in p.got:
                self.stats["trims_rx"] += 1
                p.trim_nacks.add(pkt.psn)
                self._log("pkt_rx", fid=fr.fid, res="trimmed", src=pkt.src, psn=pkt.psn)
                self._ack_now(p)
            return
        if pkt.kind == "ack":
            self.stats["acks_rx"] += 1
            for psn, loads in pkt.data:
                for t in loads:
                    self._complete(t, True)
            self._log("pkt_rx", fid=fr.fid, res="ack", src=pkt.src, cack=pkt.cack, nack=pkt.nack)
            return
        self.stats["rx_pkts"] += 1
        if self.cfg.order == "rud":
            return self._rx_rud(p, pkt, fr)
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
            self._log("pkt_rx", fid=fr.fid, res="accept", src=pkt.src, psn=pkt.psn, cack=pkt.cack, nack=pkt.nack)
            self.sim.after(self.cfg.rx_ns, self._to_xpu, p, pkt)
        elif d < 0:
            self.stats["dup_rx"] += 1
            self._log("pkt_rx", fid=fr.fid, res="dup", src=pkt.src, psn=pkt.psn, cack=pkt.cack, nack=pkt.nack)
            self._mark_ack(p)
        else:
            self.stats["gap_drops"] += 1
            self._log("pkt_rx", fid=fr.fid, res="gap", src=pkt.src, psn=pkt.psn, expect=p.expect, cack=pkt.cack, nack=pkt.nack)
            if not p.nack_sent:
                p.nack_sent, p.nack = True, p.expect
                self._ack_now(p)

    def _rx_rud(self, p, pkt, fr):
        """Out-of-order delivery: accept every new PSN, execute it, SACK what is beyond the hole."""
        if pkt.syn and pkt.start != p.start:                 # (re)established: its start PSN is the base
            p.start, p.cack = pkt.start, pkt.start - 1
            p.got.clear()
            p.done.clear()
        elif p.start is None:                                # overtook the syn packet: the base is unknown yet
            self.stats["gap_drops"] += 1
            return
        if pkt.psn <= p.cack or pkt.psn in p.got:
            self.stats["dup_rx"] += 1
            self._log("pkt_rx", fid=fr.fid, res="dup", src=pkt.src, psn=pkt.psn, cack=pkt.cack, nack=pkt.nack)
            self._ack_now(p)
            return
        p.got.add(pkt.psn)
        self._log("pkt_rx", fid=fr.fid, res="accept", src=pkt.src, psn=pkt.psn, cack=pkt.cack, nack=pkt.nack)
        self.sim.after(self.cfg.rx_ns, self._to_xpu, p, pkt)

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
            p.got.discard(p.cack)
        if self.cfg.order == "rud" and p.done:
            self._ack_now(p)                                 # a hole: SACK at once
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

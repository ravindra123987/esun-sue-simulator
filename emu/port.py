"""One link end in real time: MAC transmit, LLR (UEC 1.1 §5.1) and CBFC (§5.2) over a packet socket.

The same layering as sim/mac.py, driven by an event loop instead of a discrete-event clock:

    client (SUE-T endpoint, or the switch's forwarding)
    CBFC  : S_VC_CC counted when a lossless frame is first sent; R_VC_CC only for frames LLR
            accepted in order; CF_Update as a CtlOS unit, CC_Update as a 64 B MAC control frame
    LLR   : replay buffer, 20-bit seq in the shim (emu/shim.py), ACK/NACK/INIT/INIT_ECHO as CtlOS units
    wire  : a raw socket on a veth; corruption (BER) and lost credit messages injected here

Differences from a real link, all deliberate: there is no serialisation time, so a sender bursts
until its replay buffer or its credits stop it; CtlOS go out when due rather than in PCS slots
(an LLR_ACK after every `ctlos_bytes` of received data or every `slot_s`, whichever first; a NACK
at once); the INIT handshake runs at start-up as on a real link (sim/mac.py skips it).
"""

import heapq
import random
import select
import socket
import struct
import time
from collections import deque
from dataclasses import dataclass

from . import shim as S

CC_MOD = 1 << 20
CF_MOD = 1 << 15
PACKET_OUTGOING = 4


@dataclass
class PortCfg:
    llr: bool = True
    outstanding_data_max: int = 64 * 1024
    outstanding_seq_max: int = 1024  # the spec allows 4096; a Python receiver wants a shorter burst of small frames
    replay_timer_s: float = 0.05    # ~10x the emulator's "RTT": a Python process answers within a few ms
    replay_ct_max: int = 8
    data_age_s: float = 5.0
    slot_s: float = 0.001           # CtlOS opportunity when the link is quiet
    ctlos_bytes: int = 2048         # an LLR_ACK after this many received bytes (ctlos_target_spacing) ...
    ctlos_frames: int = 8           # ... or this many received frames, whichever first (small frames, slow receiver)
    init_retry_s: float = 0.01      # LLR_INIT repeat interval while waiting for the echo
    burst: int = 8                  # frames per transmit opportunity before the loop reads the socket again
    cbfc: bool = True
    credit_size: int = 64
    total_credits: int = 1024       # our receive buffer, per VC
    vcs: int = 2
    cf_min_s: float = 0.0002
    cf_max_s: float = 0.005
    cc_interval_s: float = 0.02
    ber: float = 0.0                # corruption of what we send: post-FEC bit error rate stand-in
    drop_cf: float = 0.0            # fraction of received CF_Updates to drop (lost credit messages)
    seed: int = 1

    def credits_for(self, size):
        return -(-size // self.credit_size)


class Timers:
    def __init__(self):
        self.h, self.n = [], 0

    def at(self, t, fn, *a):
        self.n += 1
        heapq.heappush(self.h, (t, self.n, fn, a))

    def after(self, dt, fn, *a):
        self.at(time.monotonic() + dt, fn, *a)

    def next_due(self):
        return self.h[0][0] if self.h else None

    def run(self, now=None):
        now = time.monotonic() if now is None else now
        while self.h and self.h[0][0] <= now:
            _, _, fn, a = heapq.heappop(self.h)
            fn(*a)


class TxFrame:
    """A frame the client hands to the port, with the link-layer state it acquires."""
    __slots__ = ("inner", "vc", "kind", "lossless", "dst_port", "seq", "credits", "cc_snapshot",
                 "tx_count", "fid", "t_rx", "meta", "src_port")

    def __init__(self, inner, vc=0, kind="data", lossless=True, dst_port=-1, meta=None):
        self.inner, self.vc, self.kind, self.lossless, self.dst_port, self.meta = inner, vc, kind, lossless, dst_port, meta
        self.seq, self.credits, self.cc_snapshot, self.tx_count, self.fid, self.t_rx, self.src_port = None, 0, None, 0, 0, 0.0, -1

    @property
    def size(self):
        return len(self.inner)


STAT_KEYS = ("tx_frames", "replayed", "nacks_tx", "nacks_rx", "acks_tx", "acks_rx", "inits", "flushes", "flush_lost",
             "rx_bad", "rx_dup", "rx_ooo", "rx_crc_drop", "credit_stalls", "overflow", "cc_tx", "cc_rx", "cc_reclaimed",
             "cc_negative", "cf_tx", "cf_rx", "cf_dropped", "timer_replays", "tx_err", "corrupted", "rx_frames", "rx_bytes", "tx_bytes")


class Port:
    def __init__(self, name, cfg: PortCfg, timers: Timers, send, mac: bytes, peer: bytes,
                 source=None, sink=None, forward=False, classify=None, cl_credits=None, log=None):
        """`send(raw)` puts bytes on the wire. A port with a `source` transmits what it peeks/pops.
        A port with a `sink` delivers accepted frames to it at once; with `forward=True` it keeps
        them in `rxbuf` (credits held) until the switch's egress calls `release()`. `classify(fr)`
        sets `fr.dst_port` for a forwarder. `cl_credits` is the peer's buffer size (what we may send
        into), per VC; it defaults to our own."""
        self.name, self.cfg, self.timers, self.send_raw, self.mac, self.peer = name, cfg, timers, send, mac, peer
        self.source, self.sink, self.forward, self.classify, self.log = source, sink, forward, classify, log
        self.rng = random.Random(cfg.seed * 7919 + sum(name.encode()))
        vcs = range(cfg.vcs)
        # ---- LLR TX (§5.1.5)
        self.state = "INIT" if cfg.llr else "ADVANCE"
        self.tx_seq = 0
        self.init_seq = 0
        self.acked_seq = S.SEQ_MOD - 1
        self.buf: deque[TxFrame] = deque()
        self.out_data = 0
        self.replay_list, self.replay_idx = [], 0
        self.replay_req = False
        self.nack_received = False
        self.replay_ct = 0
        self.rt_token, self.rt_running = 0, False
        self.last_progress = time.monotonic()
        # ---- LLR RX (§5.1.7)
        self.next_rx = 0
        self.ack_state = "SEND_ACKS"
        self.echo_pending = None
        self.rx_since_ack = 0
        self.rx_frames_since_ack = 0
        # ---- CBFC sender
        self.s_cc = {vc: 0 for vc in vcs}
        self.s_cf = {vc: 0 for vc in vcs}
        self.cl = {vc: (cl_credits if cl_credits is not None else cfg.total_credits) for vc in vcs}
        self.cc_pending = False
        # ---- CBFC receiver
        self.r_cc = {vc: 0 for vc in vcs}
        self.r_cf = {vc: 0 for vc in vcs}
        self.rxbuf: deque[TxFrame] = deque()
        self.occ = 0
        self.occv = {vc: 0 for vc in vcs}
        self.cf_dirty, self.last_cf = False, 0.0
        self._cf_turn = False
        self.stalled_until = 0.0
        self.fid = 0
        self.stalled = False
        self.last_init = -1.0
        self.pending = False            # a burst stopped with more to send: the loop must kick again
        self.stats = {k: 0 for k in STAT_KEYS}
        self.lost_fids = []

    # ================================================================ helpers
    def _log(self, ev, **kw):
        if self.log is not None:
            self.log(self.name, ev, kw)

    def start(self):
        now = time.monotonic()
        self.last_cf = now
        self.timers.after(self.cfg.slot_s, self._slot)
        if self.cfg.cbfc and self.source is not None:
            self.timers.after(self.cfg.cc_interval_s, self._cc_timer)
        if self.state == "INIT":
            self.last_init = now
            self._send_ctl(S.T_INIT, self.init_seq)
        self.kick()

    def snapshot(self):
        return dict(llr=self.state, tx_seq=self.tx_seq, acked=self.acked_seq, nbuf=len(self.buf), out_data=self.out_data,
                    replay_ct=self.replay_ct, next_rx=self.next_rx, ack_state=self.ack_state, occ=self.occ,
                    cr_used={vc: (self.s_cc[vc] - self.s_cf[vc]) % CF_MOD for vc in self.cl}, cl=dict(self.cl))

    # ================================================================ transmit
    def _llr_can_accept(self, size):
        c = self.cfg
        if not c.llr:
            return True
        outstanding = S.seq_diff(S.seq_add(self.tx_seq, -1), self.acked_seq)
        return self.state == "ADVANCE" and outstanding < c.outstanding_seq_max and self.out_data < c.outstanding_data_max

    def _credits_ok(self, fr):
        if not (self.cfg.cbfc and fr.lossless):
            return True
        cr = self.cfg.credits_for(fr.size)
        cu = (self.s_cc[fr.vc] - self.s_cf[fr.vc]) % CF_MOD
        if cu + cr > self.cl[fr.vc]:
            if not self.stalled:
                self.stats["credit_stalls"] += 1
                self._log("stall", vc=fr.vc, used=cu, need=cr, cl=self.cl[fr.vc])
            self.stalled = True
            return False
        self.stalled = False
        return True

    def _choose(self):
        c = self.cfg
        if c.llr:
            if self.replay_req and self.state in ("ADVANCE", "REPLAY"):
                if self.state == "REPLAY" and not self.nack_received:
                    self.replay_ct += 1
                self.replay_req = False
                self.state = "REPLAY"
                self.replay_list, self.replay_idx = list(self.buf), 0
                if self.buf:
                    self._log("replay", start=self.buf[0].seq, n=len(self.buf),
                              cause="nack" if self.nack_received else "timer", replay_ct=self.replay_ct)
                self.nack_received = False
            if self.state == "REPLAY":
                while self.replay_idx < len(self.replay_list):
                    fr = self.replay_list[self.replay_idx]
                    self.replay_idx += 1
                    if S.seq_diff(fr.seq, self.acked_seq) > 0:
                        return fr
                self.state = "ADVANCE"
                if not self.nack_received:
                    self.replay_ct += 1
            if self.state in ("INIT", "FLUSH"):
                return None
        if c.cbfc and self.cc_pending and self._llr_can_accept(S.CC_FRAME_LEN):
            self.cc_pending = False
            return TxFrame(S.cc_update_frame(self.mac, self.s_cc), kind="cc_update", lossless=False)
        if self.source is None:
            return None
        fr = self.source.peek()
        if fr is None or not self._llr_can_accept(fr.size) or not self._credits_ok(fr):
            return None
        return self.source.pop()

    def kick(self):
        """Transmit what the link allows, at most `burst` frames; True if more could follow."""
        for _ in range(self.cfg.burst):
            fr = self._choose()
            if fr is None:
                self.pending = False
                return False
            self._send_frame(fr)
        self.pending = True
        return True

    def _send_frame(self, fr: TxFrame):
        c = self.cfg
        first = fr.tx_count == 0
        fr.tx_count += 1
        if first:
            self.fid += 1
            fr.fid = self.fid
            if c.llr:
                fr.seq = self.tx_seq
                self.tx_seq = S.seq_add(self.tx_seq, 1)
                self.buf.append(fr)
                self.out_data += fr.size
            else:
                fr.seq = 0
            if fr.kind == "cc_update":
                fr.cc_snapshot = dict(self.s_cc)
                self.stats["cc_tx"] += 1
            elif c.cbfc and fr.lossless:
                fr.credits = c.credits_for(fr.size)
                self.s_cc[fr.vc] = (self.s_cc[fr.vc] + fr.credits) % CC_MOD
            self.stats["tx_frames"] += 1
            self.stats["tx_bytes"] += fr.size
        else:
            self.stats["replayed"] += 1
        raw = S.wrap_frame(self.peer, self.mac, fr.seq, fr.inner)
        raw = self._corrupt(raw, 14 + S.SHIM_LEN)
        self._log("tx", fid=fr.fid, seq=fr.seq, kind=fr.kind, size=fr.size, replay=not first)
        self._put(raw)
        if c.llr and self.buf and not self.rt_running:
            self._start_timer()

    def _corrupt(self, raw, body_off):
        ber = self.cfg.ber
        if ber <= 0:
            return raw
        nbits = 8 * (len(raw) - body_off)
        if self.rng.random() < 1.0 - (1.0 - ber) ** nbits:
            self.stats["corrupted"] += 1
            b = bytearray(raw)
            i = self.rng.randrange(nbits)
            b[body_off + i // 8] ^= 1 << (i % 8)
            return bytes(b)
        return raw

    def _put(self, raw):
        try:
            self.send_raw(raw)
        except OSError:
            self.stats["tx_err"] += 1         # link down: the frame is lost, LLR will replay it

    # ================================================================ CtlOS
    def _send_ctl(self, mtype, seq, init_data=0):
        raw = S.llr_ctlos(self.peer, self.mac, mtype, seq, init_data)
        if self.cfg.ber > 0 and self.rng.random() < 1.0 - (1.0 - self.cfg.ber) ** 64:
            self.stats["corrupted"] += 1
            return                                  # a corrupted CtlOS block is discarded by the PCS
        self._log("ctl", kind=S.TYPE_NAME[mtype], seq=seq)
        self._put(raw)

    def _slot(self):
        self._ctlos_opportunity()
        self.timers.after(self.cfg.slot_s, self._slot)

    def _cf_due(self):
        if not self.cfg.cbfc:
            return False
        dt = time.monotonic() - self.last_cf
        return (self.cf_dirty and dt >= self.cfg.cf_min_s) or dt >= self.cfg.cf_max_s

    def _ctlos_opportunity(self):
        c = self.cfg
        if c.llr:
            if self.ack_state == "SEND_NACK":
                self.ack_state = "NACK_SENT"
                self.stats["nacks_tx"] += 1
                self._send_ctl(S.T_NACK, S.seq_add(self.next_rx, -1))
                return
            if self.echo_pending is not None:
                s, self.echo_pending = self.echo_pending, None
                self._send_ctl(S.T_INIT_ECHO, s)
                return
            if self.state == "INIT":
                now = time.monotonic()
                if now - self.last_init >= self.cfg.init_retry_s:
                    self.last_init = now
                    self._send_ctl(S.T_INIT, self.init_seq)
                return
        want_ack = c.llr and self.ack_state == "SEND_ACKS"
        if self._cf_due() and (self._cf_turn or not want_ack):
            self._cf_turn = False
            self.cf_dirty, self.last_cf = False, time.monotonic()
            self.stats["cf_tx"] += 1
            self._log("ctl", kind="CF_UPDATE", cf=dict(self.r_cf))
            self._put(S.cf_update(self.peer, self.mac, 0, self.r_cf.get(0, 0), 1, self.r_cf.get(1, 0)))
            return
        self._cf_turn = True
        if want_ack:
            self.stats["acks_tx"] += 1
            self.rx_since_ack, self.rx_frames_since_ack = 0, 0
            self._send_ctl(S.T_ACK, S.seq_add(self.next_rx, -1))

    # ================================================================ LLR TX side
    def _start_timer(self):
        self.rt_token += 1
        self.rt_running = True
        self.timers.after(self.cfg.replay_timer_s, self._timer_fire, self.rt_token)

    def _stop_timer(self):
        self.rt_token += 1
        self.rt_running = False

    def _timer_fire(self, tok):
        if tok != self.rt_token:
            return
        self.rt_running = False
        if not self.buf or self.state not in ("ADVANCE", "REPLAY"):
            return
        c = self.cfg
        if time.monotonic() - self.last_progress >= c.data_age_s or (c.replay_ct_max != 255 and self.replay_ct >= c.replay_ct_max):
            self._log("timer", action="flush", replay_ct=self.replay_ct)
            self._flush()
            return
        self._log("timer", action="replay", replay_ct=self.replay_ct)
        self.stats["timer_replays"] += 1
        self.replay_req = True
        self.kick()

    def _flush(self):
        self.stats["flushes"] += 1
        self._log("flush", seqs=[f.seq for f in self.buf], fids=[f.fid for f in self.buf if f.kind == "data"])
        for fr in self.buf:
            if fr.kind == "data":
                self.stats["flush_lost"] += 1
                self.lost_fids.append(fr.fid)
        self.buf.clear()
        self.out_data = 0
        self.replay_list, self.replay_idx, self.replay_req = [], 0, False
        self.replay_ct = 0
        self._stop_timer()
        self.state = "INIT"
        self.init_seq = self.tx_seq
        self.acked_seq = S.seq_add(self.init_seq, -1)
        self.stats["inits"] += 1
        self.last_init = time.monotonic()
        self._send_ctl(S.T_INIT, self.init_seq)

    def _on_ack(self, seq, nack):
        d = S.seq_diff(seq, self.acked_seq)
        if d > 0 and S.seq_diff(seq, S.seq_add(self.tx_seq, -1)) <= 0:
            while self.buf and S.seq_diff(self.buf[0].seq, seq) <= 0:
                self.out_data -= self.buf.popleft().size
            self.acked_seq = seq
            self.last_progress = time.monotonic()
            self.replay_ct = 0
            self._stop_timer()
            if self.buf and not nack:
                self._start_timer()
        if nack:
            self.stats["nacks_rx"] += 1
            self.nack_received = True
            self._stop_timer()
            if self.state in ("ADVANCE", "REPLAY"):
                self.replay_req = True
        elif d > 0:
            self.nack_received = False
        self.kick()

    # ================================================================ receive
    def on_wire(self, raw: bytes):
        u = S.unwrap(raw)
        if u is None:
            return
        if u.is_frame:
            self._on_frame(u)
        else:
            self._on_ctlos(u)

    def _on_ctlos(self, u: S.Unit):
        if u.mtype in (S.T_ACK, S.T_NACK):
            if u.mtype == S.T_ACK:
                self.stats["acks_rx"] += 1
            if self.cfg.llr:
                self._on_ack(u.seq, u.mtype == S.T_NACK)
        elif u.mtype == S.T_INIT:
            self.next_rx = u.seq
            self.ack_state = "SEND_ACKS"
            self.echo_pending = u.seq
            self._log("init_rx", seq=u.seq)
            self._ctlos_opportunity()
        elif u.mtype == S.T_INIT_ECHO:
            if self.state == "INIT" and u.seq == self.init_seq:
                self.state = "ADVANCE"
                self.last_progress = time.monotonic()
                self._log("init_done", seq=u.seq)
                self.kick()
        elif u.mtype == S.T_CF:
            if self.cfg.drop_cf > 0 and self.rng.random() < self.cfg.drop_cf:
                self.stats["cf_dropped"] += 1
                return
            self.stats["cf_rx"] += 1
            moved = False
            for vc, val in u.cf.items():
                if vc in self.s_cf and (val - self.s_cf[vc]) % CF_MOD:
                    moved = True
                    self.s_cf[vc] = val
            if moved:
                self.kick()

    def _vc_of(self, inner: bytes) -> int:
        """The lossless VC a frame travels on: UFH_16 dscp (byte 7) or the ESUN CoS; 0 otherwise."""
        if len(inner) > 14 and inner[12:14] == b"\xe7\x90":
            return (inner[7] >> 2) % self.cfg.vcs
        if len(inner) > 15 and inner[12:14] == struct.pack("!H", 0x88B5):
            return ((inner[14] >> 2) & 7) % self.cfg.vcs
        return 0

    def _on_frame(self, u: S.Unit):
        inner = u.inner
        kind = "cc_update" if S.is_cc_update(inner) else "data"
        fr = TxFrame(inner, vc=self._vc_of(inner), kind=kind, lossless=(kind == "data"))
        fr.seq = u.seq
        fr.credits = self.cfg.credits_for(fr.size) if fr.lossless else 0
        if kind == "cc_update" and u.crc_ok:
            fr.cc_snapshot = S.parse_cc_update(inner)
        bad = not u.crc_ok
        self.stats["rx_frames"] += 1
        self.stats["rx_bytes"] += fr.size
        verdict = "bad" if bad else ("accept" if not self.cfg.llr else
                                     {0: "accept"}.get(S.seq_diff(fr.seq, self.next_rx), "dup" if S.seq_diff(fr.seq, self.next_rx) < 0 else "ooo"))
        self._log("rx", seq=fr.seq, kind=kind, size=fr.size, res=verdict)
        if not self.cfg.llr:
            if bad:
                self.stats["rx_crc_drop"] += 1
                return
            self._deliver(fr)
            return
        if bad:
            self.stats["rx_bad"] += 1
            if self.ack_state == "SEND_ACKS":
                self.ack_state = "SEND_NACK"
                self._ctlos_opportunity()
            return
        d = S.seq_diff(fr.seq, self.next_rx)
        if d == 0:
            self.next_rx = S.seq_add(self.next_rx, 1)
            self.ack_state = "SEND_ACKS"
            self.rx_since_ack += fr.size
            self.rx_frames_since_ack += 1
            self._deliver(fr)
            if self.rx_since_ack >= self.cfg.ctlos_bytes or self.rx_frames_since_ack >= self.cfg.ctlos_frames:
                self._ctlos_opportunity()
        elif d < 0:
            self.stats["rx_dup"] += 1
        else:
            self.stats["rx_ooo"] += 1
            if self.ack_state == "SEND_ACKS":
                self.ack_state = "SEND_NACK"
                self._ctlos_opportunity()

    # ================================================================ CBFC receiver
    def _deliver(self, fr: TxFrame):
        if fr.kind == "cc_update":
            self._rx_cc(fr)
            return
        if self.classify is not None:
            self.classify(fr)
        if self.cfg.cbfc and fr.lossless:
            self.r_cc[fr.vc] = (self.r_cc[fr.vc] + fr.credits) % CC_MOD
            if self.occv[fr.vc] + fr.credits > self.cfg.total_credits:
                self.stats["overflow"] += 1
                self._log("overflow", occ=self.occ, need=fr.credits)
                return
            self.occ += fr.credits
            self.occv[fr.vc] += fr.credits
            fr.t_rx = time.monotonic()
            self.rxbuf.append(fr)
            self._drain()
        elif self.sink:
            self.sink(fr)

    def _drain(self):
        if self.forward:
            return                                  # the egress port pulls with release()
        if time.monotonic() < self.stalled_until:
            return                                  # stuck receiver: credits stay held
        while self.rxbuf:
            fr = self.rxbuf.popleft()
            self._free(fr)
            if self.sink:
                self.sink(fr)

    def stall(self, seconds):
        """Fault: the client stops taking frames out of the receive buffer for a while."""
        self.stalled_until = time.monotonic() + seconds
        self._log("stall_rx", s=seconds)
        self.timers.after(seconds + 0.001, self._drain)

    def _free(self, fr):
        self.occ -= fr.credits
        self.occv[fr.vc] -= fr.credits
        self.r_cf[fr.vc] = (self.r_cf[fr.vc] + fr.credits) % CF_MOD
        self.cf_dirty = True

    def release(self, fr: TxFrame) -> TxFrame:
        """A switch egress port took this buffered frame (any position: virtual output queueing)."""
        self.rxbuf.remove(fr)
        self._free(fr)
        return fr

    def _rx_cc(self, fr):
        self.stats["cc_rx"] += 1
        for vc, s in (fr.cc_snapshot or {}).items():
            if vc not in self.r_cc:
                continue
            lost = (s - self.r_cc[vc]) % CC_MOD
            if lost >= CC_MOD // 2:
                self.stats["cc_negative"] += 1
            elif lost:
                self.stats["cc_reclaimed"] += lost
                self.r_cf[vc] = (self.r_cf[vc] + lost) % CF_MOD
                self.cf_dirty = True
                self._log("cc_reclaim", vc=vc, credits=lost)
            self.r_cc[vc] = s

    def _cc_timer(self):
        self.cc_pending = True
        self.kick()
        self.timers.after(self.cfg.cc_interval_s, self._cc_timer)


# ==================================================================== sockets and the loop
def raw_socket(ifname: str) -> socket.socket:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    s.bind((ifname, 0))
    s.setblocking(False)
    # net.core.rmem_max caps SO_RCVBUF at ~208 KB, which an LLR replay burst overflows; as root,
    # SO_RCVBUFFORCE (33) goes past the cap. A real link has no queue here to overflow.
    for opt, size in ((33, 64 << 20), (socket.SO_RCVBUF, 4 << 20)):
        try:
            s.setsockopt(socket.SOL_SOCKET, opt, size)
            break
        except OSError:
            continue
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 << 20)
    return s


class Loop:
    """select() over packet sockets plus the shared timer heap."""

    def __init__(self, timers: Timers):
        self.timers = timers
        self.socks = {}
        self.ports = []                 # kicked after every pass, so a bounded burst continues
        self.batch = 32                 # frames read per socket per pass: timers and CtlOS interleave across sockets
        self.stop = False

    def add(self, sock, on_raw):
        self.socks[sock.fileno()] = (sock, on_raw)

    def run_once(self, max_wait=0.05):
        now = time.monotonic()
        self.timers.run(now)
        more = False
        for p in self.ports:
            more = p.kick() or more
        due = self.timers.next_due()
        wait = 0.0 if more else (max_wait if due is None else max(0.0, min(max_wait, due - now)))
        if not self.socks:
            time.sleep(wait)
            return
        r, _, _ = select.select(list(self.socks), [], [], wait)
        for fd in r:
            sock, cb = self.socks[fd]
            for _ in range(self.batch):
                try:
                    data, addr = sock.recvfrom(65535)
                except BlockingIOError:
                    break
                except OSError:
                    break
                if addr[2] == PACKET_OUTGOING:
                    continue                        # our own transmissions echoed by the packet socket
                cb(data)

    def run(self, until=None):
        while not self.stop and (until is None or time.monotonic() < until):
            self.run_once()

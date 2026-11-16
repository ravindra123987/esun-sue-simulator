"""One end of a full-duplex link: MAC transmit, LLR (UEC 1.1 §5.1) and CBFC (§5.2).

Layering, which is what makes the §5.2.9 rules hold:

    client (traffic source / sink)
    CBFC  : counts S_VC_CC when a lossless frame is first sent; R_VC_CC only for
            frames that LLR accepted in order; CF_Update in CtlOS, CC_Update as a frame
    LLR   : replay buffer, sequence numbers in the preamble, ACK/NACK in CtlOS
    wire  : serialisation (here), propagation, corruption, outages (model.Wire)

Simplifications (documented in docs/experiments/llr-cbfc.md):
  - CtlOS go out in fixed slots every `ctlos_spacing` bytes of link time and
    stretch the frame in flight by 8 B; the 256 B "not in the first bytes of a
    frame" rule is ignored.
  - The PCS-status timer is not modelled; link-down shows up as lost frames/CtlOS.
  - Both ends start initialised (no INIT exchange at time 0); INIT is used after FLUSH.
"""

from collections import deque

from .model import CTLOS_BYTES, PREAMBLE_IPG, SEQ_MOD, CtlOS, Frame, seq_add, seq_diff

CC_MOD = 1 << 20     # S_VC_CC / R_VC_CC width (Table 5-18)
CF_MOD = 1 << 15     # S_VC_CF / R_VC_CF width


class Mac:
    def __init__(self, sim, name, link, llr, cbfc, wire_out, source=None, sink=None, cl_credits=None):
        """`cbfc` describes this end's receive buffer. `cl_credits` is the peer's buffer (what we may
        send into); it defaults to the same size, as on the symmetric links of sim/link.py and sim/path.py."""
        self.sim, self.name, self.link, self.llr, self.cbfc = sim, name, link, llr, cbfc
        self.wire = wire_out
        self.source, self.sink = source, sink
        vcs = range(cbfc.vcs)
        self.rate = link.rate
        # ---- transmit
        self.busy, self.cur, self.tx_end = False, None, 0.0
        # ---- LLR TX (§5.1.5)
        self.state = "ADVANCE"          # ADVANCE | REPLAY | INIT | FLUSH
        self.tx_seq = 0
        self.acked_seq = SEQ_MOD - 1    # all ones (Table 5-10)
        self.buf: deque[Frame] = deque()
        self.out_data = 0
        self.replay_list, self.replay_idx = [], 0
        self.replay_req = False         # enter / restart REPLAY at the next transmit opportunity
        self.nack_received = False
        self.replay_ct = 0
        self.rt_token, self.rt_running = 0, False
        self.last_progress = 0.0
        self.init_seq = 0
        # ---- LLR RX (§5.1.7) for frames arriving from the peer
        self.next_rx = 0
        self.ack_state = "SEND_ACKS"    # SEND_ACKS | SEND_NACK | NACK_SENT
        self.echo_pending = None
        # ---- CBFC sender (credits for frames we send)
        self.s_cc = {vc: 0 for vc in vcs}
        self.s_cf = {vc: 0 for vc in vcs}
        self.cl = {vc: cl_credits if cl_credits is not None else cbfc.total_credits for vc in vcs}
        self.cc_pending = False
        # ---- CBFC receiver (frames from the peer)
        self.r_cc = {vc: 0 for vc in vcs}
        self.r_cf = {vc: 0 for vc in vcs}
        self.rxbuf: deque[Frame] = deque()
        self.occ = 0                    # credits held, all VCs
        self.occv = {vc: 0 for vc in vcs}
        self.draining = False
        self.cf_dirty, self.last_cf = False, -1e18
        self._cf_turn = False
        self.fid = 0
        self.stats = {k: 0 for k in (
            "tx_frames", "replayed", "nacks_tx", "nacks_rx", "acks_tx", "flushes", "flush_lost",
            "rx_bad", "rx_dup", "rx_ooo", "rx_crc_drop", "credit_stalls", "overflow",
            "cc_tx", "cc_rx", "cc_reclaimed", "cc_negative", "cf_tx", "timer_replays")}
        self.lost_fids = []
        self.stalled = False            # waiting for credits (tracing only)
        self.forward = None             # switch: the egress Mac that pulls from rxbuf (sim/path.py)
        self._last_snap = None

    # ================================================================ tracing
    def _log(self, ev, **kw):
        if self.sim.trace is not None:
            self.sim.log(ev, mac=self.name, **kw)

    def snapshot(self) -> dict:
        """The state the visualiser draws (docs/viz). A sender (it has a source) reports LLR transmit
        and its credits; a receiver (a sink or a forwarder, or no source at all) reports LLR receive and
        its buffer; a MAC that is both reports both. The replay buffer is contiguous in seq, so its
        first seq and length describe it."""
        s = {}
        if self.source is not None:
            s.update(llr=self.state, tx_seq=self.tx_seq, acked=self.acked_seq,
                     buf0=self.buf[0].seq if self.buf else None, nbuf=len(self.buf),
                     replay_ct=self.replay_ct, timer=self.rt_running,
                     cr_used=sum((self.s_cc[v] - self.s_cf[v]) % CF_MOD for v in self.cl), cl=sum(self.cl.values()),
                     stalled=self.stalled)
        if self.source is None or self.sink is not None or self.forward is not None:
            s.update(next_rx=self.next_rx, ack_state=self.ack_state, occ=self.occ)
        return s

    def snap_if_changed(self):
        s = self.snapshot()
        if s != self._last_snap:
            self._last_snap = s
            self.sim.log("mac", mac=self.name, **s)

    # ================================================================ start
    def start(self):
        self.sim.after(self.llr.ctlos_spacing / self.rate, self._slot)
        if self.cbfc.enabled and self.source is not None:
            self.sim.after(self.cbfc.cc_interval_ns, self._cc_timer)
        self.kick()

    def kick(self):
        if not self.busy:
            self._pull()

    # ================================================================ transmit
    def _llr_can_accept(self, size):
        L = self.llr
        if not L.enabled:
            return True
        outstanding = seq_diff(seq_add(self.tx_seq, -1), self.acked_seq)
        return (self.state == "ADVANCE" and outstanding < L.outstanding_seq_max
                and self.out_data < L.outstanding_data_max)

    def _credits_ok(self, fr):
        if not (self.cbfc.enabled and fr.lossless):
            return True
        cr = self.cbfc.credits_for(fr.size)
        cu = (self.s_cc[fr.vc] - self.s_cf[fr.vc]) % CF_MOD
        if cu + cr > self.cl[fr.vc]:
            self.stats["credit_stalls"] += 1
            self.stalled = True
            return False
        self.stalled = False
        return True

    def _choose(self):
        if self.llr.enabled:
            if self.replay_req and self.state in ("ADVANCE", "REPLAY"):
                if self.state == "REPLAY" and not self.nack_received:
                    self.replay_ct += 1              # a restarted replay exits REPLAY too
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
                    if seq_diff(fr.seq, self.acked_seq) > 0:      # not yet acknowledged
                        return fr
                self.state = "ADVANCE"                             # replay_done
                if not self.nack_received:
                    self.replay_ct += 1
            if self.state in ("INIT", "FLUSH"):
                return None                                        # llr_*_behavior = BLOCK
        if self.cbfc.enabled and self.cc_pending and self._llr_can_accept(64):
            self.cc_pending = False                                # rule 9: never during a replay
            self.fid += 1
            return Frame(self.fid, 64, lossless=False, kind="cc_update", born=self.sim.now)
        if self.source is None:
            return None
        fr = self.source.peek(self.sim.now)
        if fr is None or not self._llr_can_accept(fr.size) or not self._credits_ok(fr):
            return None
        return self.source.pop()

    def _pull(self):
        fr = self._choose()
        if fr is None:
            return
        first = fr.tx_count == 0
        fr.tx_count += 1
        if first:
            fr.llr_eligible = self.llr.enabled
            if fr.llr_eligible:
                fr.seq = self.tx_seq
                self.tx_seq = seq_add(self.tx_seq, 1)
                self.buf.append(fr)
                self.out_data += fr.size
            if fr.kind == "cc_update":
                # all credits of frames sent before this one, none after (§5.2.5.6.4)
                fr.cc_snapshot = dict(self.s_cc)
                self.stats["cc_tx"] += 1
            elif self.cbfc.enabled and fr.lossless:
                fr.credits = self.cbfc.credits_for(fr.size)
                self.s_cc[fr.vc] = (self.s_cc[fr.vc] + fr.credits) % CC_MOD
            self.stats["tx_frames"] += 1
        else:
            self.stats["replayed"] += 1
            if self.cbfc.count_replays and fr.kind == "data" and fr.lossless:   # breaks rule 1
                self.s_cc[fr.vc] = (self.s_cc[fr.vc] + fr.credits) % CC_MOD
        self.busy, self.cur = True, fr
        fr.t_start = self.sim.now
        self.tx_end = self.sim.now + (fr.size + PREAMBLE_IPG) / self.rate
        self.sim.at(self.tx_end, self._tx_done)

    def _tx_done(self):
        if self.sim.now < self.tx_end - 1e-9:        # stretched by CtlOS insertion
            self.sim.at(self.tx_end, self._tx_done)
            return
        fr, self.cur, self.busy = self.cur, None, False
        self.wire.send_frame(fr, self.sim.now)
        if fr.llr_eligible and self.buf and not self.rt_running:
            self._start_timer()
        self._pull()

    # ================================================================ CtlOS slots
    def _slot(self):
        c = self._pick_ctlos()
        if c is not None:
            dt = CTLOS_BYTES / self.rate
            if self.busy:
                self.tx_end += dt
            self.wire.send_ctlos(c, self.sim.now + dt)
        self.sim.after(self.llr.ctlos_spacing / self.rate, self._slot)

    def _cf_due(self):
        if not self.cbfc.enabled:
            return False
        dt = self.sim.now - self.last_cf
        return (self.cf_dirty and dt >= self.cbfc.cf_min_ns) or dt >= self.cbfc.cf_max_ns

    def _pick_ctlos(self):
        L = self.llr
        if L.enabled:
            if self.ack_state == "SEND_NACK":
                self.ack_state = "NACK_SENT"
                self.stats["nacks_tx"] += 1
                return CtlOS("LLR_NACK", seq_add(self.next_rx, -1))
            if self.echo_pending is not None:
                s, self.echo_pending = self.echo_pending, None
                return CtlOS("LLR_INIT_ECHO", s)
            if self.state == "INIT":
                return CtlOS("LLR_INIT", self.init_seq)
        want_ack = L.enabled and self.ack_state == "SEND_ACKS"
        if self._cf_due() and (self._cf_turn or not want_ack):
            self._cf_turn = False
            self.cf_dirty, self.last_cf = False, self.sim.now
            self.stats["cf_tx"] += 1
            return CtlOS("CF_UPDATE", cf=dict(self.r_cf))
        self._cf_turn = True
        if want_ack:
            self.stats["acks_tx"] += 1
            return CtlOS("LLR_ACK", seq_add(self.next_rx, -1))
        return None

    # ================================================================ LLR TX side
    def _start_timer(self):
        self.rt_token += 1
        self.rt_running = True
        self.sim.after(self.llr.replay_timer_ns, self._timer_fire, self.rt_token)

    def _stop_timer(self):
        self.rt_token += 1
        self.rt_running = False

    def _timer_fire(self, tok):
        if tok != self.rt_token:
            return
        self.rt_running = False
        if not self.buf or self.state not in ("ADVANCE", "REPLAY"):
            return
        L = self.llr
        if (self.sim.now - self.last_progress >= L.data_age_ns
                or (L.replay_ct_max != 255 and self.replay_ct >= L.replay_ct_max)):
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
        if self.llr.re_init:
            self.state = "INIT"
            self.init_seq = self.tx_seq
            self.acked_seq = seq_add(self.init_seq, -1)
        else:
            self.state = "FLUSH"

    def _on_ack(self, seq, nack):
        d = seq_diff(seq, self.acked_seq)
        if d > 0 and seq_diff(seq, seq_add(self.tx_seq, -1)) <= 0:
            while self.buf and seq_diff(self.buf[0].seq, seq) <= 0:
                self.out_data -= self.buf.popleft().size
            self.acked_seq = seq
            self.last_progress = self.sim.now
            self.replay_ct = 0
            self._stop_timer()
            if self.buf and not nack:
                self._start_timer()
        if nack:
            self.stats["nacks_rx"] += 1
            self.nack_received = True
            self._stop_timer()                    # held at zero until the replay starts
            if self.state in ("ADVANCE", "REPLAY"):
                self.replay_req = True
        elif d > 0:
            self.nack_received = False
        self.kick()

    # ================================================================ receive
    def on_ctlos(self, c: CtlOS):
        if c.kind in ("LLR_ACK", "LLR_NACK"):
            if self.llr.enabled:
                self._on_ack(c.seq, c.kind == "LLR_NACK")
        elif c.kind == "LLR_INIT":
            self.next_rx = c.seq
            self.ack_state = "SEND_ACKS"
            self.echo_pending = c.seq
        elif c.kind == "LLR_INIT_ECHO":
            if self.state == "INIT" and c.seq == self.init_seq:
                self.state = "ADVANCE"
                self.last_progress = self.sim.now
                self.kick()
        elif c.kind == "CF_UPDATE":                # still applied in the discard window (rule 4)
            moved = False
            for vc, val in c.cf.items():
                if (val - self.s_cf[vc]) % CF_MOD:
                    moved = True
                self.s_cf[vc] = val
            if moved:
                self.kick()

    def on_frame(self, fr: Frame, bad: bool):
        if fr.kind == "cc_update" and self.cbfc.cc_bypass_llr and not bad:
            self._rx_cc(fr)                        # breaks rule 3: ignores the LLR verdict
        if self.sim.trace is not None:
            self._log("rx", fid=fr.fid, seq=fr.seq, kind=fr.kind, res=self._rx_verdict(fr, bad))
        if not fr.llr_eligible:
            if bad:
                self.stats["rx_crc_drop"] += 1
                if fr.kind == "data":
                    self.lost_fids.append(fr.fid)
                return
            self._deliver(fr)
            return
        if bad:                                    # FCS bad: NACK the expected frame
            self.stats["rx_bad"] += 1
            if self.ack_state == "SEND_ACKS":
                self.ack_state = "SEND_NACK"
            return
        d = seq_diff(fr.seq, self.next_rx)
        if d == 0:
            self.next_rx = seq_add(self.next_rx, 1)
            self.ack_state = "SEND_ACKS"
            self._deliver(fr)
        elif d < 0:
            self.stats["rx_dup"] += 1              # duplicate: filtered silently
        else:
            self.stats["rx_ooo"] += 1              # missing frame(s): discard window
            if self.cbfc.count_discards and fr.kind == "data" and fr.lossless:   # breaks rule 2
                self.r_cc[fr.vc] = (self.r_cc[fr.vc] + fr.credits) % CC_MOD
            if self.ack_state == "SEND_ACKS":
                self.ack_state = "SEND_NACK"

    def _rx_verdict(self, fr, bad):
        if bad:
            return "bad"
        if not fr.llr_eligible:
            return "accept"
        d = seq_diff(fr.seq, self.next_rx)
        return "accept" if d == 0 else ("dup" if d < 0 else "ooo")

    # ================================================================ CBFC receiver
    def _deliver(self, fr: Frame):
        if fr.kind == "cc_update":
            if not self.cbfc.cc_bypass_llr:
                self._rx_cc(fr)
            return
        if self.cbfc.enabled and fr.lossless:
            self.r_cc[fr.vc] = (self.r_cc[fr.vc] + fr.credits) % CC_MOD
            if self.occv[fr.vc] + fr.credits > self.cbfc.total_credits:
                self.stats["overflow"] += 1        # a lossless frame dropped: CBFC failed
                self._log("overflow", fid=fr.fid, occ=self.occ, need=fr.credits)
                self.lost_fids.append(fr.fid)
                return
            self.occ += fr.credits
            self.occv[fr.vc] += fr.credits
            fr.t_rx = self.sim.now
            self.rxbuf.append(fr)
            self._drain()
        elif self.sink:
            self.sink(fr, self.sim.now)

    def _drain(self):
        if self.forward is not None:
            self.forward.kick()                    # the egress port pulls from rxbuf when it can send
            return
        if self.draining or not self.rxbuf:
            return
        self.draining = True
        fr = self.rxbuf[0]
        dt = fr.size / (self.cbfc.drain_gbps / 8.0)
        self._log("egress", fid=fr.fid, t_end=round(self.sim.now + dt, 3))
        self.sim.after(dt, self._drained)

    def _drained(self):
        fr = self.rxbuf.popleft()
        self._free(fr)
        self.draining = False
        if self.sink:
            self.sink(fr, self.sim.now)
        self._drain()

    def _free(self, fr):
        self.occ -= fr.credits
        self.occv[fr.vc] -= fr.credits
        self.r_cf[fr.vc] = (self.r_cf[fr.vc] + fr.credits) % CF_MOD
        self.cf_dirty = True

    def release_head(self) -> Frame:
        """The switch's egress port took the oldest buffered frame: free its credits (sim/path.py)."""
        return self.release(self.rxbuf[0])

    def release(self, fr: Frame) -> Frame:
        """An egress port took this buffered frame (any position: virtual output queueing, sim/fabric.py)."""
        self.rxbuf.remove(fr)
        self._free(fr)
        self._log("fwd", fid=fr.fid)
        return fr

    def _rx_cc(self, fr: Frame):
        self.stats["cc_rx"] += 1
        for vc, s in fr.cc_snapshot.items():
            lost = (s - self.r_cc[vc]) % CC_MOD
            if lost:
                self._log("cc", lost=lost if lost < CC_MOD // 2 else lost - CC_MOD)
            if lost >= CC_MOD // 2:
                self.stats["cc_negative"] += 1     # "a serious error has occurred" (§5.2.5.7.4)
            elif lost:
                self.stats["cc_reclaimed"] += lost
                self.r_cf[vc] = (self.r_cf[vc] + lost) % CF_MOD
                self.cf_dirty = True
            self.r_cc[vc] = s

    def _cc_timer(self):
        self.cc_pending = True
        self.kick()
        self.sim.after(self.cbfc.cc_interval_ns, self._cc_timer)

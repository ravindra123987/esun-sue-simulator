"""Event traces for the visualiser (docs/viz).

The path has three devices (XPU A, the switch, XPU B) and two cables. Each cable end runs
its own MAC with LLR and CBFC, so the trace names four link endpoints: `mac` is A (XPU A's
NIC port), S1 and S7 (the switch's ports 1 and 7) or B (XPU B's NIC port), and `dir` is
a2s / s2a (hop 1) or s2b / b2s (hop 2). `PathSession(..., trace=[])` (sim/path.py) records:

    frame    a frame put on a wire: dir, fid, seq, kind, size, replay, t0/t1 (first/last bit
             leaves; t1 - t0 includes any CtlOS slipped into the frame), arrive (last bit reaches the peer), fate ok | bad | down
    ctlos    a control ordered set: dir, kind, seq, cf, t1, arrive, fate
    rx       what the receiving MAC did with a frame: accept | bad | dup | ooo
    replay   LLR entered REPLAY: start seq, n frames, cause nack | timer
    timer    LLR replay timer expired: action replay | flush
    flush    LLR gave up: seqs/fids thrown away
    cc       CC_Update found lost credits (negative = the "serious error" case)
    overflow a lossless frame did not fit the receive buffer
    fwd      switch port 7 took a frame out of port 1's buffer (its credits are freed)
    egress   XPU B's NIC starts writing a buffered frame to HBM: fid, t_end
    deliver  the frame is in XPU B's HBM
    mac      a state snapshot of one MAC (only when something changed)

sim/link.py (one link, MACs A and B, wires a2b/b2a) records the same events without fwd.

`Annotator` turns path events into short captions. Each caption says where it happened
(`at`: a MAC, h1/h2 for a cable, cmd for a live command) and is derived from what the
simulator did, not written by hand.
"""

from .path import HOPS, NAMES

RX_HOP = {rx: (i + 1, tx, rev) for i, (tx, rx, fwd, rev) in enumerate(HOPS)}     # receiver -> hop
TX_HOP = {tx: (i + 1, rx, fwd) for i, (tx, rx, fwd, rev) in enumerate(HOPS)}     # sender -> hop
REV = {rev: (rx, tx, i + 1) for i, (tx, rx, fwd, rev) in enumerate(HOPS)}         # reverse wire -> (from, to, hop)
FWD = {fwd: (tx, rx, i + 1) for i, (tx, rx, fwd, rev) in enumerate(HOPS)}


class Annotator:
    """Captions one event at a time (the live server feeds it as the simulation runs)."""

    def __init__(self, cfg: dict | None = None):
        self.cfg = cfg or {}
        self.notes = []
        self.expected = {}                     # receiver -> next seq it wants (for captions)
        self.ooo_run, self.dup_run = set(), set()
        self.init_seen, self.echo_seen = set(), set()
        self.last_stall = {}                   # sender -> stalled flag in its last snapshot
        self.stall_note = {}                   # sender -> time of its last stall caption
        self.full_note = {}                    # receiver -> time of its last "buffer filling" caption
        self.snap = {}
        self.got = set()
        self.delivered = self.forwarded = False

    def _note(self, t, at, kind, text):
        n = {"t": round(t, 3), "at": at, "kind": kind, "text": text}
        self.notes.append(n)
        return n

    def link_down(self, hop, a, b):
        return [self._note(a, f"h{hop}", "down", f"Hop {hop}'s cable goes down: everything on it, in both "
                                                 "directions, is lost."),
                self._note(b, f"h{hop}", "up", f"Hop {hop}'s cable is back up.")]

    def feed(self, e: dict) -> list[dict]:
        """Process one event; return the captions it produced."""
        start = len(self.notes)
        ev, t = e["ev"], e["t"]
        if ev == "rx" and e["mac"] in RX_HOP:
            self._rx(e)
        elif ev == "ctlos" and e["dir"] in REV and e["kind"] == "LLR_NACK":
            frm, to, hop = REV[e["dir"]]
            lost = "" if e["fate"] == "ok" else " The NACK is lost on the cable."
            self._note(t, frm, "nack", f"{NAMES[frm]} sends LLR NACK {e['seq']} back to {NAMES[to]}: "
                                       f"replay everything after seq {e['seq']}.{lost}")
        elif ev == "replay" and e["mac"] in TX_HOP:
            why = "after the NACK" if e["cause"] == "nack" else "after its replay timer"
            other = " XPU A is not involved: LLR retries one hop at a time." if e["mac"] == "S7" else ""
            self._note(t, e["mac"], "replay", f"{NAMES[e['mac']]} enters REPLAY {why}: resends {e['n']} frame(s) "
                                              f"from seq {e['start']} out of its replay buffer, without spending "
                                              f"credits again.{other}")
        elif ev == "timer" and e["mac"] in TX_HOP:
            who = NAMES[e["mac"]]
            if e["action"] == "flush":
                self._note(t, e["mac"], "timer", f"{who}'s replay timer expires again and the retry count has "
                                                 f"reached replay_ct_max ({e['replay_ct']}): LLR gives up.")
            else:
                self._note(t, e["mac"], "timer", f"{who}'s replay timer expires with no ACK progress, so it replays.")
        elif ev == "flush" and e["mac"] in TX_HOP:
            hop, rx, _ = TX_HOP[e["mac"]]
            if e["seqs"]:
                had = sum(1 for f in e["fids"] if f in self.got)
                extra = (f" XPU B already had {had} of them; only their ACKs were lost." if had and e["mac"] == "S7"
                         else f" Some may already be at {NAMES[rx]} with only their ACKs lost.")
                self._note(t, e["mac"], "flush", f"FLUSH: {NAMES[e['mac']]} throws away {len(e['seqs'])} frame(s) "
                                                 f"(seq {e['seqs'][0]}–{e['seqs'][-1]}).{extra} Anything really "
                                                 "missing is now the transport's problem.")
            else:
                self._note(t, e["mac"], "flush", f"FLUSH: {NAMES[e['mac']]}'s replay buffer was already empty.")
        elif ev == "ctlos" and e["kind"] == "LLR_INIT" and e["dir"] in FWD:
            tx, rx, hop = FWD[e["dir"]]
            if hop not in self.init_seen:
                self.init_seen.add(hop)
                self._note(t, tx, "init", f"{NAMES[tx]} sends LLR_INIT {e['seq']} to agree on sequence numbers again.")
        elif ev == "ctlos" and e["kind"] == "LLR_INIT_ECHO" and e["fate"] == "ok" and e["dir"] in REV:
            frm, to, hop = REV[e["dir"]]
            if hop not in self.echo_seen:
                self.echo_seen.add(hop)
                self._note(t, frm, "init", f"{NAMES[frm]} echoes the INIT. When the echo arrives, {NAMES[to]} "
                                           "goes back to ADVANCE.")
        elif ev == "cc" and e["mac"] in RX_HOP:
            hop, tx, _ = RX_HOP[e["mac"]]
            if e["lost"] > 0:
                self._note(t, e["mac"], "cc", f"{NAMES[e['mac']]}: a CC_Update from {NAMES[tx]} shows "
                                              f"{e['lost']} credits were spent on frames that never arrived. "
                                              "They go back in the next CF_Update.")
            else:
                self._note(t, e["mac"], "cc", f"{NAMES[e['mac']]}: a CC_Update gives negative lost credits "
                                              f"({e['lost']}): the spec's \"serious error\".")
        elif ev == "overflow":
            self._note(t, e["mac"], "overflow", f"{NAMES.get(e['mac'], e['mac'])}: a lossless frame does not fit "
                                                "the buffer and is dropped. CBFC should never let this happen.")
        elif ev == "fwd" and not self.forwarded:
            self.forwarded = True
            self._note(t, "S1", "fwd", f"The switch forwards frame #{e['fid']}: port 7 takes it out of port 1's "
                                       "buffer, which frees those credits for XPU A.")
        elif ev == "deliver":
            self.got.add(e["fid"])
            if not self.delivered:
                self.delivered = True
                self._note(t, "B", "deliver", f"Frame #{e['fid']} is in XPU B's HBM {e['lat']:.0f} ns after XPU A "
                                              "queued it: two cables and one switch buffer.")
        elif ev == "mac":
            self.snap[e["mac"]] = e
            self._mac(e)
        return self.notes[start:]

    def _rx(self, e):
        rx, t = e["mac"], e["t"]
        hop = RX_HOP[rx][0]
        who, what = NAMES[rx], f"#{e['fid']}" if e["kind"] == "data" else "a CC_Update"
        if e["res"] == "accept":
            self.expected[rx] = None if e["seq"] is None else e["seq"] + 1
            self.ooo_run.discard(rx)
            self.dup_run.discard(rx)
        elif e["res"] == "bad" and e["seq"] is None:
            self._note(t, rx, "bad", f"{who}: frame {what} fails the FCS check and is dropped. Without LLR "
                                     f"nothing on hop {hop} resends it.")
        elif e["res"] == "bad":
            self._note(t, rx, "bad", f"{who}: frame {what} (seq {e['seq']}) fails the FCS check and is "
                                     "discarded. It will NACK.")
        elif e["res"] == "ooo" and rx not in self.ooo_run:
            self.ooo_run.add(rx)
            exp = self.expected.get(rx)
            exp = f", it still wants seq {exp}" if exp is not None else ""
            self._note(t, rx, "ooo", f"{who} discards {what} (seq {e['seq']}): out of order{exp}. LLR keeps "
                                     "nothing out of order and sends no second NACK.")
        elif e["res"] == "dup" and rx not in self.dup_run:
            self.dup_run.add(rx)
            self._note(t, rx, "dup", f"{who} silently drops {what} (seq {e['seq']}): a duplicate of a frame "
                                     "it already has.")

    def _mac(self, e):
        m, t = e["mac"], e["t"]
        if m in TX_HOP:                                        # senders: credit stalls
            rx = TX_HOP[m][1]
            if e["stalled"] and not self.last_stall.get(m) and t - self.stall_note.get(m, -1e9) > 1500:
                self.stall_note[m] = t
                occ = (self.snap.get(rx) or {}).get("occ", 0)
                why = (f"{NAMES[rx]}'s buffer holds {occ} of them and the rest are frames and CF_Updates "
                       "still on the cable" if occ >= 0.5 * e["cl"] else
                       f"only {occ} are in {NAMES[rx]}'s buffer, the rest are tied up in frames and "
                       "CF_Updates still on the cable")
                self._note(t, m, "stall", f"{NAMES[m]} is out of credits ({e['cr_used']} of {e['cl']} in use): "
                                          f"{why}. It waits for a CF_Update.")
            self.last_stall[m] = e["stalled"]
        if m in RX_HOP:                                        # receivers: buffer filling up
            tot = self.cfg.get("credits", {}).get(m)
            if tot and e["occ"] >= 0.75 * tot and t - self.full_note.get(m, -1e9) > 1500:
                self.full_note[m] = t
                if m == "B":
                    g = self.cfg.get("nic_gbps")
                    why = f"XPU B writes to HBM at {g:g} Gb/s, slower than the link brings frames in"
                else:
                    why = "port 7 cannot send to XPU B as fast as port 1 receives"
                self._note(t, m, "fill", f"{NAMES[m]}'s buffer is {100 * e['occ'] // tot}% full: {why}. "
                                         "Credits come back more slowly, so the sender is held back; nothing is dropped.")


def annotate(events: list[dict], down: dict | None = None, cfg: dict | None = None) -> list[dict]:
    """down: {hop: [(t0, t1), ...]}."""
    a = Annotator(cfg)
    for hop, spans in (down or {}).items():
        for t0, t1 in spans:
            a.link_down(hop, t0, t1)
    for e in events:
        a.feed(e)
    return sorted(a.notes, key=lambda n: n["t"])

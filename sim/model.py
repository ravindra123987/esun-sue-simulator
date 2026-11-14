"""Frames, control ordered sets, wires and configuration for the link model."""

import math
import random
from dataclasses import dataclass, field

PREAMBLE_IPG = 20          # bytes of preamble + SFD + IPG per frame (LLR seq rides in the preamble)
CTLOS_BYTES = 8            # one 64b/66b control block
SEQ_BITS = 20              # LLR frame_seq (UEC §5.1.1.1)
SEQ_MOD = 1 << SEQ_BITS


def seq_add(a, n):
    return (a + n) % SEQ_MOD


def seq_diff(a, b):
    """a - b as a signed value in the 20-bit sequence space."""
    d = (a - b) % SEQ_MOD
    return d - SEQ_MOD if d >= SEQ_MOD // 2 else d


@dataclass
class Frame:
    fid: int
    size: int                       # bytes from DA to FCS
    vc: int = 0
    lossless: bool = True           # CBFC lossless VC (uses credits)
    llr_eligible: bool = True
    kind: str = "data"              # "data" | "cc_update"
    born: float = 0.0
    seq: int | None = None          # LLR frame_seq, assigned at first transmission
    credits: int = 0
    cc_snapshot: dict | None = None # CC_Update payload: {vc: S_VC_CC}
    tx_count: int = 0


@dataclass
class CtlOS:
    kind: str                       # LLR_ACK | LLR_NACK | LLR_INIT | LLR_INIT_ECHO | CF_UPDATE
    seq: int = 0
    cf: dict | None = None          # CF_UPDATE: {vc: R_VC_CF}


@dataclass
class LinkCfg:
    rate_gbps: float = 800.0
    cable_m: float = 3.0
    ns_per_m: float = 4.6           # twinax (RM104 App A)
    mac_phy_ns: float = 50.0        # one MAC+PHY traversal (half of the 100 ns TX+RX budget)
    ber: float = 0.0                # post-FEC bit error rate applied per frame/CtlOS
    down: list = field(default_factory=list)   # [(t0, t1)] intervals when everything is lost
    seed: int = 1

    @property
    def rate(self) -> float:        # bytes per ns
        return self.rate_gbps / 8.0

    @property
    def prop_ns(self) -> float:
        return self.cable_m * self.ns_per_m + self.mac_phy_ns


@dataclass
class LLRCfg:
    enabled: bool = True
    outstanding_data_max: int = 64 * 1024     # should be ~ link BDP (Table 5-9)
    outstanding_seq_max: int = 4096
    replay_timer_ns: float = 2000.0           # ~10x link RTT
    replay_ct_max: int = 8                    # 255 = never give up
    data_age_ns: float = 1e6
    ctlos_spacing: int = 2048                 # bytes between CtlOS slots (suggested 2048)
    re_init: bool = True


@dataclass
class CBFCCfg:
    enabled: bool = True
    credit_size: int = 64
    pkt_ovhd: int = 0
    total_credits: int = 1024                 # receiver buffer in credits (per VC limit here)
    drain_gbps: float = 800.0                 # receiver input-buffer drain rate
    cf_min_ns: float = 20.0
    cf_max_ns: float = 500.0
    cc_interval_ns: float = 2000.0
    # deliberately broken variants for experiment 4 (UEC §5.2.9 rules)
    cc_bypass_llr: bool = False               # rule 3: process CC_Update even in the LLR discard window
    count_replays: bool = False               # rule 1: count credits again when LLR replays
    count_discards: bool = False              # rule 2: count credits for frames LLR discards

    def credits_for(self, size: int) -> int:
        return math.ceil((size + self.pkt_ovhd) / self.credit_size)


class Wire:
    """One direction of a link: serialisation is done by the sender; this adds
    propagation delay, random corruption (BER) and down intervals."""

    def __init__(self, sim, cfg: LinkCfg, name: str):
        self.sim, self.cfg, self.name = sim, cfg, name
        self.rng = random.Random(cfg.seed * 1_000_003 + sum(ord(ch) * 31 ** i for i, ch in enumerate(name)))
        self.peer = None
        self.corrupt_hook = None    # tests: fn(obj) -> bool forces corruption
        self.stats = {"frames": 0, "corrupted": 0, "lost_down": 0, "ctlos": 0, "ctlos_lost": 0}

    def _down(self, t):
        return any(a <= t < b for a, b in self.cfg.down)

    def _corrupt(self, obj, nbytes):
        if self.corrupt_hook is not None:
            forced = self.corrupt_hook(obj)
            if forced is not None:
                return forced
        if self.cfg.ber <= 0:
            return False
        return self.rng.random() < 1.0 - (1.0 - self.cfg.ber) ** (8 * nbytes)

    def send_frame(self, fr: Frame, t_end: float):
        self.stats["frames"] += 1
        down = self._down(t_end)
        bad = False if down else self._corrupt(fr, fr.size)
        if self.sim.trace is not None:
            self.sim.log("frame", dir=self.name, fid=fr.fid, seq=fr.seq, kind=fr.kind, size=fr.size,
                         replay=fr.tx_count > 1, t0=round(t_end - (fr.size + PREAMBLE_IPG) / self.cfg.rate, 3),
                         t1=round(t_end, 3), arrive=round(t_end + self.cfg.prop_ns, 3),
                         fate="down" if down else ("bad" if bad else "ok"))
        if down:
            self.stats["lost_down"] += 1
            return
        if bad:
            self.stats["corrupted"] += 1
        self.sim.at(t_end + self.cfg.prop_ns, self.peer.on_frame, fr, bad)

    def send_ctlos(self, c: CtlOS, t_end: float):
        self.stats["ctlos"] += 1
        down = self._down(t_end)
        lost = down or self._corrupt(c, CTLOS_BYTES)
        if self.sim.trace is not None:
            self.sim.log("ctlos", dir=self.name, kind=c.kind, seq=c.seq, cf=(c.cf or {}).get(0),
                         t1=round(t_end, 3), arrive=round(t_end + self.cfg.prop_ns, 3),
                         fate="down" if down else ("bad" if lost else "ok"))
        if lost:
            self.stats["ctlos_lost"] += 1
            return
        self.sim.at(t_end + self.cfg.prop_ns, self.peer.on_ctlos, c)

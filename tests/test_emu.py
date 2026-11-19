"""The emulator's link layer and endpoint (emu/), run over an in-memory wire: no namespaces, no root.

The netns lab itself (emu/lab.py) only runs as root on Linux; tools/run_m4.py drives it in the VM.
"""

import time
from collections import deque

import pytest

from emu import shim as S
from emu.endpoint import Endpoint
from emu.port import Port, PortCfg, Timers, TxFrame
from emu.switch import dst_port_of, sw_mac, xpu_mac
from sue import consts as C
from sue.frame import decode


# ---------------------------------------------------------------------- shim
def test_shim_units_round_trip():
    a, b = xpu_mac(0), sw_mac(0)
    inner = b"\x42" * 100
    u = S.unwrap(S.wrap_frame(b, a, 0xABCDE, inner))
    assert u.is_frame and u.seq == 0xABCDE and u.crc_ok and u.inner == inner and u.dst == b and u.src == a
    bad = bytearray(S.wrap_frame(b, a, 1, inner))
    bad[-1] ^= 0x80
    assert S.unwrap(bytes(bad)).crc_ok is False
    for t in (S.T_ACK, S.T_NACK, S.T_INIT, S.T_INIT_ECHO):
        u = S.unwrap(S.llr_ctlos(b, a, t, 0x8A72C, 0x4DE1))
        assert u.mtype == t and u.seq == 0x8A72C and (u.init_data == 0x4DE1)
    u = S.unwrap(S.cf_update(b, a, 0, 12345, 1, 0x7FFF))
    assert u.mtype == S.T_CF and u.cf == {0: 12345, 1: 0x7FFF}
    assert S.unwrap(b"\x00" * 60) is None


def test_ctlos_bytes_follow_uec_table_5_8():
    """UEC §5.1.3.1.1 example: LLR_INIT with init_seq 0x8A72C, init_data 0x4DE1 -> D2..D7 = 8A 72 C6 4D E1 00."""
    raw = S.llr_ctlos(sw_mac(0), xpu_mac(0), S.T_INIT, 0x8A72C, 0x4DE1)
    assert raw[14] == 0x03 and raw[22:28] == bytes.fromhex("8a72c64de100")
    raw = S.llr_ctlos(sw_mac(0), xpu_mac(0), S.T_ACK, 0x12345)
    assert raw[22:28] == bytes.fromhex("123456000000")


def test_cc_update_is_a_64_byte_mac_control_frame():
    fr = S.cc_update_frame(xpu_mac(3), {0: 0xFFFFF, 1: 7, 15: 9})
    assert len(fr) == 60 and fr[:6] == S.CC_DA and fr[12:16] == bytes.fromhex("8808fffe") and fr[16:20] == bytes.fromhex("fa7acb01")
    assert S.is_cc_update(fr) and S.parse_cc_update(fr) == {**{i: 0 for i in range(16)}, 0: 0xFFFFF, 1: 7, 15: 9}


# ---------------------------------------------------------------------- an in-memory link
class Wire:
    """Two ports joined back to back; `pump()` moves what they sent, through `corrupt` if set."""

    def __init__(self):
        self.q = deque()
        self.ports = {}
        self.corrupt = None
        self.down = False
        self.n = 0
        self.fail_after = None          # the wire dies after this many units (a fault mid-burst)
        self.on_fail = None
        self.sent = 0

    def sender(self, name):
        def send(raw):
            if self.fail_after is not None and self.sent >= self.fail_after and not self.down:
                self.down = True
                if self.on_fail:
                    self.on_fail()
            if self.down:
                raise OSError("link down")
            self.sent += 1
            self.q.append((name, raw))
        return send

    def pump(self):
        moved = 0
        while self.q:
            name, raw = self.q.popleft()
            self.n += 1
            if self.corrupt is not None:
                raw = self.corrupt(self.n, raw)
                if raw is None:
                    continue
            self.ports[name].on_wire(raw)
            moved += 1
        return moved


class Source:
    def __init__(self, frames):
        self.frames = deque(frames)

    def peek(self):
        return self.frames[0] if self.frames else None

    def pop(self):
        return self.frames.popleft()


def spin(timers, wire, until, done=lambda: False):
    t_end = time.monotonic() + until
    while time.monotonic() < t_end:
        timers.run()
        more = any([p.kick() for p in wire.ports.values()])
        if wire.pump() == 0 and not more:
            if done():
                return True
            time.sleep(0.0005)
    return done()


def link(cfg_a=None, cfg_b=None, frames=(), sink=None):
    timers, wire = Timers(), Wire()
    cfg_a, cfg_b = cfg_a or PortCfg(), cfg_b or PortCfg()
    a = Port("a", cfg_a, timers, wire.sender("b"), xpu_mac(0), sw_mac(0), source=Source(frames))
    b = Port("b", cfg_b, timers, wire.sender("a"), sw_mac(0), xpu_mac(0), sink=sink)
    wire.ports = {"a": a, "b": b}
    return timers, wire, a, b


def frames(n, size=1000):
    return [TxFrame(bytes([i & 0xFF]) * size, vc=0) for i in range(n)]


def fast():
    return PortCfg(replay_timer_s=0.003, slot_s=0.0005, cf_min_s=0.0002, cf_max_s=0.002, cc_interval_s=0.01)


def test_init_handshake_then_in_order_delivery():
    got = []
    timers, wire, a, b = link(fast(), fast(), frames(50), sink=lambda fr: got.append(fr.inner[0]))
    a.start(); b.start()
    assert a.state == "INIT" and b.state == "INIT"
    assert spin(timers, wire, 1.0, lambda: len(got) == 50)
    assert got == list(range(50)) and a.state == "ADVANCE" and b.state == "ADVANCE"
    assert a.stats["tx_frames"] == 50 and a.stats["replayed"] == 0 and b.stats["rx_bad"] == 0
    assert a.stats["acks_rx"] > 0                                 # LLR_ACKs came back as CtlOS units
    assert spin(timers, wire, 0.05, lambda: not a.buf)            # the replay buffer empties once ACKed


def test_one_corrupted_frame_one_nack_one_replay():
    got = []
    timers, wire, a, b = link(fast(), fast(), frames(40), sink=lambda fr: got.append(fr.inner[0]))

    def corrupt(n, raw):
        u = S.unwrap(raw)
        if u is not None and u.is_frame and u.seq == 7 and not getattr(corrupt, "done", False):
            corrupt.done = True
            raw = bytearray(raw)
            raw[-1] ^= 1
            return bytes(raw)
        return raw
    wire.corrupt = corrupt
    a.start(); b.start()
    assert spin(timers, wire, 1.0, lambda: len(got) == 40)
    assert got == list(range(40))                                 # delivered once, in order
    assert b.stats["rx_bad"] == 1 and b.stats["nacks_tx"] == 1 and a.stats["nacks_rx"] == 1
    assert a.stats["replayed"] >= 1 and a.stats["timer_replays"] == 0   # repaired by the NACK, not the timer
    assert a.stats["flushes"] == 0


def test_lost_nack_is_covered_by_the_replay_timer():
    got = []
    timers, wire, a, b = link(fast(), fast(), frames(20), sink=lambda fr: got.append(fr.inner[0]))

    def corrupt(n, raw):
        u = S.unwrap(raw)
        if u is None:
            return raw
        if u.is_frame and u.seq == 3 and not getattr(corrupt, "hit", False):
            corrupt.hit = True
            raw = bytearray(raw); raw[-1] ^= 1
            return bytes(raw)
        if u.mtype == S.T_NACK and not getattr(corrupt, "dropped", False):
            corrupt.dropped = True
            return None                                           # the NACK dies on the wire
        return raw
    wire.corrupt = corrupt
    a.start(); b.start()
    assert spin(timers, wire, 1.5, lambda: len(got) == 20)
    assert got == list(range(20)) and a.stats["timer_replays"] >= 1


def test_without_llr_a_corrupted_frame_is_simply_lost():
    got = []
    off = fast(); off.llr = False
    timers, wire, a, b = link(off, off, frames(10), sink=lambda fr: got.append(fr.inner[0]))
    wire.corrupt = lambda n, raw: (bytes(bytearray(raw[:-1]) + bytes([raw[-1] ^ 1])) if (S.unwrap(raw) or S.Unit(1, 0, 1, b"", 0, None, 0, 0)).seq == 0 and S.unwrap(raw) is not None and S.unwrap(raw).is_frame and n <= 1 else raw)
    a.start(); b.start()
    spin(timers, wire, 0.3, lambda: len(got) == 9)
    assert len(got) == 9 and b.stats["rx_crc_drop"] == 1 and a.stats["replayed"] == 0


def test_credits_stop_the_sender_without_overflow():
    """The receiver holds its buffer (stuck client): the sender runs out of credits and waits; CF_Updates
    after the stall release it. Nothing is dropped."""
    got = []
    small = fast(); small.total_credits = 64                      # 4 KB per VC
    timers, wire, a, b = link(fast(), small, frames(30, 1000), sink=lambda fr: got.append(fr.inner[0]))
    a.cl = {vc: 64 for vc in a.cl}                                # what a may send into b
    a.start(); b.start()
    b.stall(0.2)
    spin(timers, wire, 0.1)
    assert len(got) == 0 and a.stats["credit_stalls"] >= 1 and b.stats["overflow"] == 0 and 0 < b.occ <= 64
    assert spin(timers, wire, 1.0, lambda: len(got) == 30)
    assert got == list(range(30)) and b.stats["overflow"] == 0 and a.stats["cf_rx"] > 0


def test_cc_update_reclaims_credits_of_a_frame_lost_without_llr():
    off = fast(); off.llr = False; off.cc_interval_s = 0.01
    got = []
    timers, wire, a, b = link(off, off, frames(5, 1000), sink=lambda fr: got.append(fr))
    first = {"done": False}

    def corrupt(n, raw):
        u = S.unwrap(raw)
        if u is not None and u.is_frame and not S.is_cc_update(u.inner) and not first["done"]:
            first["done"] = True
            raw = bytearray(raw); raw[-1] ^= 1
            return bytes(raw)
        return raw
    wire.corrupt = corrupt
    a.start(); b.start()
    assert spin(timers, wire, 0.5, lambda: b.stats["cc_reclaimed"] > 0)
    assert b.stats["rx_crc_drop"] == 1 and b.stats["cc_reclaimed"] == 16 and len(got) == 4   # 1000 B = 16 credits


def test_link_down_then_up_recovers_with_llr():
    got = []
    timers, wire, a, b = link(fast(), fast(), frames(30), sink=lambda fr: got.append(fr.inner[0]))
    a.start(); b.start()
    spin(timers, wire, 0.02, lambda: len(got) >= 5)
    wire.down = True
    a.source.frames.extend(frames(0))
    spin(timers, wire, 0.02)
    wire.down = False
    assert spin(timers, wire, 1.5, lambda: len(got) == 30)
    assert got == list(range(30)) and a.stats["tx_err"] > 0 and (a.stats["timer_replays"] + a.stats["nacks_rx"]) >= 1


# ---------------------------------------------------------------------- two endpoints, one link
def endpoints(n_bytes=8192, retx=True, cfg=None, senders=None, **kw):
    timers, wire = Timers(), Wire()
    cfg = cfg or fast()
    e0 = Endpoint(0, 2, bytes_per_peer=n_bytes, retx=retx, timers=timers, rto_s=0.05, ack_hold_s=0.001, senders=senders, **kw)
    e1 = Endpoint(1, 2, bytes_per_peer=n_bytes, retx=retx, timers=timers, rto_s=0.05, ack_hold_s=0.001, senders=senders, **kw)
    p0 = Port("xpu0", cfg, timers, wire.sender("xpu1"), xpu_mac(0), xpu_mac(1), source=e0, sink=e0.on_deliver)
    p1 = Port("xpu1", cfg, timers, wire.sender("xpu0"), xpu_mac(1), xpu_mac(0), source=e1, sink=e1.on_deliver)
    e0.port, e1.port = p0, p1
    wire.ports = {"xpu0": p0, "xpu1": p1}
    return timers, wire, e0, e1, p0, p1


def run_eps(timers, wire, e0, e1, p0, p1, until=3.0):
    e0.issue(); e1.issue()
    p0.start(); p1.start()

    def done():
        return e0.finished and e1.finished
    ok = spin(timers, wire, until, lambda: (p0.kick(), p1.kick(), done())[-1])
    return ok


def test_stores_complete_both_ways_with_packing_and_piggybacked_acks():
    """256 KB each way: more than the window and the transmit buffer, so requests keep flowing while
    ACK state is pending and some of it rides on reverse requests instead of bare ACK packets."""
    timers, wire, e0, e1, p0, p1 = endpoints(262144)
    assert run_eps(timers, wire, e0, e1, p0, p1, until=10.0)
    for e in (e0, e1):
        assert e.stats["done"] == 1024 and e.stats["failed"] == 0 and e.stats["retx_pkts"] == 0 and e.stats["rtos"] == 0
        assert max(e.pack_hist) == 8 and e.stats["rx_payload"] == 262144
        assert e.stats["piggybacked"] > 0                           # ACK state rode on reverse requests
        assert e.stats["acks_tx"] < e.stats["rx_pkts"]              # fewer bare ACKs than packets received
    # what is left in the replay buffer are real UFH_16 frames sue/frame.py can decode
    assert all(decode(f.inner).kind in ("ufh16-rodl", "ufh16-ack") for f in p0.buf if f.kind == "data")


def test_frames_on_the_wire_decode_and_carry_the_hidden_psn():
    seen = []
    timers, wire, e0, e1, p0, p1 = endpoints(4096, senders=[0])
    wire.corrupt = lambda n, raw: (seen.append(raw), raw)[1]
    assert run_eps(timers, wire, e0, e1, p0, p1)
    inner = [S.unwrap(r).inner for r in seen if S.unwrap(r) and S.unwrap(r).is_frame and not S.is_cc_update(S.unwrap(r).inner)]
    reqs = [d for d in (decode(i, expected_psn=None) for i in inner) if d.kind == "ufh16-rodl"]
    acks = [d for d in (decode(i) for i in inner) if d.kind == "ufh16-ack"]
    assert reqs and acks and reqs[0].pkt.syn == 1 and reqs[0].pkt.explicit_psn == 1000
    assert decode(inner[0], expected_psn=1000).crc_ok is True
    assert all(a.crc_ok for a in acks) and acks[-1].pkt.cack_psn == 1000 + len(reqs) - 1


def test_llr_off_a_lost_packet_is_repaired_by_rodl_go_back_n():
    off = fast(); off.llr = False
    timers, wire, e0, e1, p0, p1 = endpoints(16384, cfg=off, senders=[0])
    state = {"hit": 0}

    def corrupt(n, raw):
        u = S.unwrap(raw)
        if u and u.is_frame and not S.is_cc_update(u.inner) and u.inner[1] >> 3 == C.PDS_TYPE_RODL and state["hit"] == 0 and n > 3:
            state["hit"] = 1
            raw = bytearray(raw); raw[-1] ^= 1
            return bytes(raw)
        return raw
    wire.corrupt = corrupt
    assert run_eps(timers, wire, e0, e1, p0, p1)
    assert e0.stats["done"] == 64 and e0.stats["failed"] == 0
    assert e1.stats["gap_drops"] >= 1 and e1.stats["nacks_tx"] == 1 and e0.stats["nacks_rx"] == 1 and e0.stats["retx_pkts"] >= 1
    assert e1.stats["rx_payload"] == 16384 and e1.stats["dup_rx"] >= 0


def test_llr_off_sue_lite_fails_what_was_in_flight_and_re_establishes_the_pdc():
    off = fast(); off.llr = False
    timers, wire, e0, e1, p0, p1 = endpoints(16384, cfg=off, retx=False, senders=[0])
    state = {"hit": 0}

    def corrupt(n, raw):
        u = S.unwrap(raw)
        if u and u.is_frame and not S.is_cc_update(u.inner) and u.inner[1] >> 3 == C.PDS_TYPE_RODL and state["hit"] == 0 and n > 3:
            state["hit"] = 1
            raw = bytearray(raw); raw[-1] ^= 1
            return bytes(raw)
        return raw
    wire.corrupt = corrupt
    assert run_eps(timers, wire, e0, e1, p0, p1)
    assert e0.stats["failed"] > 0 and e0.stats["fatal"] == 1 and e0.stats["retx_pkts"] == 0
    assert e0.stats["done"] + e0.stats["failed"] == 64 and e0.stats["done"] > 0      # later stores got through on a new syn


def test_llr_on_hides_the_same_loss_from_rodl():
    timers, wire, e0, e1, p0, p1 = endpoints(16384, senders=[0])
    state = {"hit": 0}

    def corrupt(n, raw):
        u = S.unwrap(raw)
        if u and u.is_frame and not S.is_cc_update(u.inner) and u.inner[1] >> 3 == C.PDS_TYPE_RODL and state["hit"] == 0 and n > 3:
            state["hit"] = 1
            raw = bytearray(raw); raw[-1] ^= 1
            return bytes(raw)
        return raw
    wire.corrupt = corrupt
    assert run_eps(timers, wire, e0, e1, p0, p1)
    assert e0.stats["done"] == 64 and e0.stats["retx_pkts"] == 0 and e0.stats["nacks_rx"] == 0 and e1.stats["gap_drops"] == 0
    assert p1.stats["nacks_tx"] == 1 and p0.stats["replayed"] >= 1


def test_switch_lookup_reads_the_ufh16_destination():
    timers, wire, e0, e1, p0, p1 = endpoints(2048, senders=[0])
    e0.issue()
    fr = e0.peek()
    assert dst_port_of(fr.inner) == 1
    assert dst_port_of(xpu_mac(3) + xpu_mac(0) + b"\x88\xb5" + b"\x00" * 40) == 3
    assert dst_port_of(b"\xff" * 60) == -1


# ---------------------------------------------------------------------- several planes (M5b)
from emu.endpoint import PortSource  # noqa: E402


def two_plane(path, order, llr=True, n_bytes=65536, rto=0.05, **kw):
    """XPU 0 and XPU 1 joined back to back on two planes (no switch: the wire is the plane)."""
    timers = Timers()
    wires = [Wire(), Wire()]
    cfg = fast()
    cfg.llr = llr
    eps = [Endpoint(i, 2, bytes_per_peer=n_bytes, timers=timers, rto_s=rto, ack_hold_s=0.001, planes=2, path=path,
                    order=order, probe_s=0.05, **kw) for i in range(2)]
    ports = {}
    for q, w in enumerate(wires):
        for i, ep in enumerate(eps):
            other = f"x{1 - i}"
            p = Port(f"x{i}", cfg, timers, w.sender(other), xpu_mac(i), xpu_mac(1 - i), source=PortSource(ep, q),
                     sink=ep.deliver_from(q))
            ep.ports[q] = p
            ports[(i, q)] = p
        w.ports = {f"x{i}": ports[(i, q)] for i in range(2)}
    return timers, wires, eps, ports


def spin_planes(timers, wires, eps, until, cut=None):
    """Run until both endpoints finish; `cut(t)` may take a plane down."""
    t_end = time.monotonic() + until
    t0 = time.monotonic()
    while time.monotonic() < t_end:
        timers.run()
        if cut:
            cut(time.monotonic() - t0)
        more = any([p.kick() for ep in eps for p in ep.ports])
        moved = sum(w.pump() for w in wires)
        if not moved and not more:
            if all(ep.finished for ep in eps):
                return True
            time.sleep(0.0005)
    return all(ep.finished for ep in eps)


def start_all(eps):
    for ep in eps:
        ep.issue()
        for p in ep.ports:
            p.start()


def test_spray_uses_both_planes_and_delivers_out_of_order():
    timers, wires, eps, ports = two_plane("spray", "rud")
    start_all(eps)
    assert spin_planes(timers, wires, eps, 5.0)
    for ep in eps:
        assert ep.stats["done"] == 256 and ep.stats["failed"] == 0 and ep.stats["rx_payload"] == 65536
        assert min(ep.port_pkts) > 0                                 # both planes carried requests


def test_pinned_pdc_on_a_dead_plane_fails_but_spray_and_failover_survive():
    res = {}
    for path, order, kw in (("pin", "rodl", dict(max_rtos=2)), ("failover", "rodl", {}), ("spray", "rud", {})):
        timers, wires, eps, ports = two_plane(path, order, n_bytes=262144, **kw)
        wires[1].fail_after = 30                                     # plane 1 dies mid-transfer, for good
        wires[1].on_fail = lambda eps=eps: [ep.set_carrier(1, False) for ep in eps]
        start_all(eps)
        ok = spin_planes(timers, wires, eps, 8.0)
        res[path] = (ok, sum(ep.stats["failed"] for ep in eps), sum(ep.stats["moves"] for ep in eps))
    assert res["failover"][0] and res["failover"][1] == 0 and res["failover"][2] >= 1
    assert res["spray"][0] and res["spray"][1] == 0
    assert res["pin"][1] > 0 or not res["pin"][0]                    # the pinned PDC on plane 1 cannot recover


def test_probe_brings_a_marked_plane_back():
    timers, wires, eps, ports = two_plane("spray", "rud", llr=False, n_bytes=262144)
    start_all(eps)
    wires[1].fail_after = 30                                         # remote-style: no carrier change, only losses
    state = {"phase": 0}

    def heal(t):
        if wires[1].down and state["phase"] == 0:
            state["phase"], state["t"] = 1, t
        elif state["phase"] == 1 and t - state["t"] > 0.2:
            state["phase"] = 2
            wires[1].down, wires[1].fail_after = False, None
    assert spin_planes(timers, wires, eps, 10.0, cut=heal)
    st = {k: sum(ep.stats[k] for ep in eps) for k in ("bad_marks", "restores", "failed")}
    assert st["bad_marks"] >= 1 and st["failed"] == 0

"""SUE-T endpoint (sim/suet.py) on the fabric (sim/fabric.py): packing, RODL, ACK modes, workloads."""

import pytest

from sim import wire
from sim.fabric import Fabric
from sim.model import CBFCCfg, Frame, LinkCfg, LLRCfg
from sim.suet import SUETCfg
from sim.workloads import AllToAll, RingAllReduce


def run(n=4, ports=1, wl=None, until=200_000, **kw):
    f = Fabric(n=n, ports=ports, workload=wl or AllToAll(n, bytes_per_peer=8192), **kw)
    f.run(until)
    return f, f.result()


def test_all_to_all_completes_in_order_with_nothing_lost():
    f, r = run()
    assert r.failed == 0 and r.done == f.workload.total and r.finished_ns is not None
    assert r.ep["nacks_tx"] == r.ep["retx_pkts"] == r.ep["rtos"] == 0
    assert r.mac["sw"]["overflow"] == r.mac["nic"]["overflow"] == 0


def test_packing_is_opportunistic_and_bounded():
    """A fast XPU interface fills the queues, so packets carry several CMD_PDUs, never more than the
    payload cap (2 KB = 8 stores) or 16; a slow one sends each transaction alone (§7.3)."""
    f, r = run(suet=SUETCfg(xpu_gbps=1600))
    assert max(r.pack_hist) == 8 and r.pack_avg > 3
    f, r = run(suet=SUETCfg(xpu_gbps=50))
    assert r.pack_hist == {1: r.ep["tx_pkts"] - r.ep["acks_tx"]}


def test_wire_bytes_match_the_accounting():
    """One-way traffic, one store per packet: every request is the 300 B frame sim/wire.py predicts,
    every bare ACK 64 B, and the efficiency lands between "an ACK per packet" and "ACKs for free"."""
    tr = []
    f, r = run(n=2, wl=AllToAll(2, bytes_per_peer=8192, senders=[0]), suet=SUETCfg(xpu_gbps=50), trace=tr)
    sizes = {(e["kind"], e["n"]) for e in tr if e["ev"] == "pkt_tx"}
    assert sizes == {("req", 1), ("ack", 0)}
    assert {e["size"] for e in tr if e["ev"] == "pkt_tx" and e["kind"] == "req"} == {wire.packet_bytes("ufh16", "req", wire.ses_requests([256]))} == {292}
    assert {e["size"] for e in tr if e["ev"] == "pkt_tx" and e["kind"] == "ack"} == {64}
    assert r.wire_bytes == sum(wire.on_wire(e["size"]) for e in tr if e["ev"] == "pkt_tx")
    lo = wire.transaction_bytes("ufh16", "operational", 1, piggyback=False)["wire_eff"]
    hi = wire.transaction_bytes("ufh16", "operational", 1, piggyback=True)["wire_eff"]
    assert lo < r.efficiency < hi


def test_operational_acks_beat_delivery_acks_on_the_wire():
    op = run(suet=SUETCfg(ack_mode="operational"))[1]
    dl = run(suet=SUETCfg(ack_mode="delivery"))[1]
    assert op.efficiency > 0.9 > dl.efficiency
    assert dl.done == op.done and dl.failed == 0
    assert dl.ep["rx_pkts"] > op.ep["rx_pkts"]                 # the response commands are packets too


def test_loads_return_data_in_both_ack_modes():
    for mode in ("delivery", "operational"):
        f, r = run(wl=AllToAll(4, bytes_per_peer=4096, op="load"), suet=SUETCfg(ack_mode=mode))
        assert r.failed == 0 and r.finished_ns is not None
        assert r.efficiency < 0.9                              # data travels back, headers in both directions


def test_a_lost_packet_is_recovered_by_go_back_n():
    """LLR off and one frame corrupted on the way up: the target sees a PSN gap, NACKs once, drops
    what follows; the source replays from the missing PSN (UEC §3.5.7.2)."""
    def hooks(f):
        w = f.wires["n0p0>s0"]
        w.corrupt_hook = lambda o: True if isinstance(o, Frame) and o.fid == 9 and o.tx_count == 1 else None
    f, r = run(llr=LLRCfg(enabled=False), hooks=hooks)
    assert r.failed == 0 and r.finished_ns is not None
    assert r.ep["nacks_tx"] == 1 and r.ep["retx_pkts"] >= 1 and r.ep["gap_drops"] >= 1
    assert r.ep["dup_rx"] == 0


def test_without_retransmission_a_loss_closes_the_pdc():
    def hooks(f):
        w = f.wires["n0p0>s0"]
        w.corrupt_hook = lambda o: True if isinstance(o, Frame) and o.fid == 9 and o.tx_count == 1 else None
    f, r = run(llr=LLRCfg(enabled=False), suet=SUETCfg(retx=False), until=60_000, hooks=hooks)
    assert r.ep["fatal"] == 1 and r.failed > 0
    assert r.done + r.failed == f.workload.total                # the run still ends: later packets re-sync (syn)


def test_llr_hides_the_same_loss_from_the_transport():
    def hooks(f):
        w = f.wires["n0p0>s0"]
        w.corrupt_hook = lambda o: True if isinstance(o, Frame) and o.fid == 9 and o.tx_count == 1 else None
    f, r = run(hooks=hooks)
    assert r.ep["nacks_tx"] == r.ep["retx_pkts"] == 0 and r.mac["nic"]["replayed"] >= 1
    assert r.failed == 0


def test_lost_acks_are_covered_by_the_rto():
    """One-way traffic, LLR off, every bare ACK corrupted for the first 3 µs: cumulative ACKs cannot
    help, so the source's timer replays everything; the target sees duplicates and re-ACKs."""
    def hooks(f):
        f.wires["n1p0>s0"].corrupt_hook = lambda o: True if isinstance(o, Frame) and o.pkt is not None \
            and o.pkt.kind == "ack" and f.sim.now < 3000 else None
    f, r = run(n=2, wl=AllToAll(2, bytes_per_peer=2048, senders=[0]), llr=LLRCfg(enabled=False),
               suet=SUETCfg(rto_ns=1500), hooks=hooks)
    assert r.ep["rtos"] >= 1 and r.ep["dup_rx"] >= 1 and r.failed == 0 and r.finished_ns is not None
    assert r.ep["nacks_tx"] == 0                               # duplicates are not gaps


def test_two_planes_fixed_port_per_pdc_keeps_order():
    f, r = run(ports=2, suet=SUETCfg(lb="pdc"))
    assert r.failed == 0 and r.ep["nacks_tx"] == 0
    assert all(m.stats["tx_frames"] > 0 for n, m in f.macs.items() if n.startswith("N"))


def test_per_group_balancing_can_reorder_a_pdc():
    """§7.6 puts each packed group on the port with bandwidth; RODL wants one path per PDC
    (delta-table open item 8). Two planes with unequal cables make the reorder visible."""
    def hooks(f):
        for n, w in f.wires.items():
            if "p1" in n:
                w.cfg = LinkCfg(cable_m=30)
    f, r = run(ports=2, suet=SUETCfg(lb="group"), hooks=hooks)
    assert r.failed == 0 and r.finished_ns is not None
    assert r.ep["nacks_tx"] > 0 and r.ep["retx_pkts"] > 0


def test_ring_all_reduce_finishes_every_step():
    wl = RingAllReduce(4, total_bytes=1 << 16)
    f, r = run(wl=wl)
    assert r.finished_ns is not None and r.failed == 0 and r.done == wl.total
    assert all(wl.fin[i] == wl.steps for i in range(4))


def test_slow_xpu_backpressures_through_the_switch_without_drops():
    f, r = run(nic=CBFCCfg(total_credits=256, drain_gbps=200), sw=CBFCCfg(total_credits=256))
    assert r.failed == 0 and r.finished_ns is not None
    assert r.mac["sw"]["overflow"] == 0 and r.mac["sw"]["credit_stalls"] > 0 and r.mac["nic"]["credit_stalls"] > 0


def test_tracing_does_not_change_the_fabric():
    a = run(n=3)[1]
    b = run(n=3, trace=[])[1]
    assert (a.done, a.finished_ns, a.wire_bytes, a.lat_p99_ns) == (b.done, b.finished_ns, b.wire_bytes, b.lat_p99_ns)

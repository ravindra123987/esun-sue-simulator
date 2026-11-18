"""M5: path policies (pin / failover / spray), out-of-order delivery with SACK, and plane faults (sim/planes.py)."""

import dataclasses

import pytest

from sim.fabric import Fabric
from sim.model import LinkCfg, LLRCfg
from sim.planes import plane_wires, run
from sim.suet import SUETCfg
from sim.workloads import AllToAll

SMALL = 1 << 19          # 512 KB per peer: the fault at 5 µs hits mid-run for every design


def go(design, scenario, **kw):
    return run(design, scenario, bytes_per_peer=1 << 21, until=200_000, **kw)


def test_defaults_are_the_spec_and_spread_is_symmetric():
    c = SUETCfg()
    assert c.path == "pin" and c.order == "rodl" and c.max_rtos == 0
    for d in ("sue-t", "sue-t+fo", "metaroce", "mrc", "mrc+llr"):
        f, r, wl = go(d, "clean")
        assert r.failed == 0 and r.done == wl.total and r.ep["retx_pkts"] == 0 and r.ep["rtos"] == 0


def test_pinned_sue_t_cannot_survive_a_dead_plane():
    f, r, wl = go("sue-t", "plane-kill")
    assert wl.finished is None                           # never completes
    assert r.ep["fatal"] >= 1 and r.failed > 0           # PDCs declared dead after max_rtos, their stores failed
    assert r.mac["nic"]["flushes"] + r.mac["sw"]["flushes"] > 0


def test_failover_moves_pdcs_off_a_dead_plane_without_losing_anything():
    f, r, wl = go("sue-t+fo", "plane-kill")
    assert wl.finished is not None and r.failed == 0 and r.ep["moves"] >= 1
    for ep in f.eps:
        assert all(p.port != 1 for p in ep.pdcs.values() if p.port is not None)


def test_spray_routes_around_a_dead_plane_and_marks_it_bad():
    for d in ("mrc", "metaroce"):
        f, r, wl = go(d, "plane-kill")
        assert wl.finished is not None and r.failed == 0
        assert r.ep["bad_marks"] >= 1 and r.ep["retx_pkts"] >= 1
        assert all(f.macs[f"N{i}.1"].stats["tx_frames"] < f.macs[f"N{i}.0"].stats["tx_frames"] for i in range(4))


def test_a_remote_link_failure_needs_timeouts_and_the_switch_discards():
    f, r, wl = go("mrc", "remote-link")
    assert wl.finished is not None and r.failed == 0 and r.sw_dropped > 0 and r.ep["rtos"] >= 1
    f, r, wl = go("sue-t+fo", "remote-link")
    assert wl.finished is not None and r.ep["moves"] >= 1 and r.ep["rtos"] >= 1


def test_llr_absorbs_an_outage_shorter_than_its_give_up_time():
    f, r, wl = go("mrc+llr", "plane-flap")
    assert wl.finished is not None and r.ep["rtos"] == 0 and r.ep["retx_pkts"] == 0
    assert r.mac["nic"]["replayed"] + r.mac["sw"]["replayed"] > 0


def test_probes_bring_a_plane_back_after_it_heals():
    f, r, wl = run("mrc", "plane-flap", bytes_per_peer=1 << 22, until=200_000)   # long enough for the first probe
    assert r.ep["bad_marks"] >= 1 and r.ep["restores"] >= 1
    assert all(not p.bad for ep in f.eps for p in ep.pdcs.values())


def test_rud_tolerates_reordering_that_rodl_turns_into_go_back_n():
    """T5's failure (per-group balancing over unequal planes) disappears with out-of-order delivery."""
    def slow_plane(f):
        for name, w in f.wires.items():
            if "p1" in name:
                w.cfg = dataclasses.replace(w.cfg, cable_m=20)
    res = {}
    for order, path in (("rodl", "spray"), ("rud", "spray")):
        f = Fabric(n=4, ports=2, llr=LLRCfg(), workload=AllToAll(4, bytes_per_peer=SMALL),
                   suet=SUETCfg(path=path, order=order, rto_ns=20_000), hooks=slow_plane)
        f.run(500_000)
        res[order] = f.result()
    assert res["rodl"].ep["gap_drops"] > 0 and res["rodl"].ep["retx_pkts"] > 0
    assert res["rud"].ep["gap_drops"] == 0 and res["rud"].ep["retx_pkts"] == 0 and res["rud"].failed == 0
    assert res["rud"].finished_ns < res["rodl"].finished_ns


def test_sack_completes_out_of_order_packets_without_resending_them():
    def drop_one(f):
        state = {"n": 0}

        def hook(fr):
            if fr.kind == "data" and fr.pkt is not None and fr.pkt.kind == "req" and fr.pkt.psn == 5 and state["n"] == 0:
                state["n"] = 1
                return True
            return None
        for q in range(2):
            f.wires[f"n0p{q}>s{q}"].corrupt_hook = hook
    f = Fabric(n=2, ports=2, llr=LLRCfg(enabled=False), workload=AllToAll(2, bytes_per_peer=SMALL, senders=[0]),
               suet=SUETCfg(path="spray", order="rud", rto_ns=10_000), hooks=drop_one)
    f.run(300_000)
    r = f.result()
    assert r.failed == 0 and f.workload.finished is not None
    assert r.ep["retx_pkts"] == 1                        # only the lost packet; everything after it was SACKed


def test_rud_needs_operational_acks():
    with pytest.raises(ValueError):
        Fabric(n=2, suet=SUETCfg(order="rud", ack_mode="delivery"))


def test_plane_wires_names_both_directions():
    assert set(plane_wires(1, n=2)) == {"n0p1>s1", "n1p1>s1", "s1>n0p1", "s1>n1p1"}

"""Two hops through one switch (sim/path.py): per-hop LLR, per-hop credits, hop-by-hop backpressure."""

import pytest

from sim.model import CBFCCfg, Frame, LinkCfg
from sim.path import PathSession, run_path


def test_clean_path_runs_at_line_rate_in_order():
    r = run_path(sim_ns=20_000)
    assert r.in_order and r.lost == 0 and r.duplicates == 0
    assert r.goodput_gbps > 0.95 * 800 * 1024 / (1024 + 20) * 0.99


def test_slow_receiver_pushes_back_hop_by_hop_without_drops():
    r = run_path(sim_ns=20_000, sw=CBFCCfg(total_credits=512), nic=CBFCCfg(total_credits=512, drain_gbps=400))
    assert r.goodput_gbps == pytest.approx(400, rel=0.02)
    assert r.lost == 0 and r.in_order
    assert all(m["overflow"] == 0 for m in r.macs.values())
    assert r.macs["S7"]["credit_stalls"] > 0 and r.macs["A"]["credit_stalls"] > 0     # both senders held back


def test_error_on_hop_2_is_repaired_by_the_switch_alone():
    def hooks(sim, macs, wires):
        wires["s2b"].corrupt_hook = lambda o: True if isinstance(o, Frame) and o.fid == 30 and o.tx_count == 1 else None
    r = run_path(sim_ns=5_000, warmup_ns=0, hooks=hooks)
    assert r.lost == 0 and r.in_order
    assert r.macs["S7"]["replayed"] > 0 and r.macs["B"]["nacks_tx"] == 1
    assert r.macs["A"]["replayed"] == 0 and r.macs["A"]["nacks_rx"] == 0


@pytest.mark.parametrize("seed", [1, 4])
def test_bit_errors_on_both_hops_lose_nothing(seed):
    r = run_path(sim_ns=20_000, hop1=LinkCfg(ber=1e-6, seed=seed), hop2=LinkCfg(ber=1e-6, seed=seed + 10))
    assert r.lost == 0 and r.in_order and r.duplicates == 0
    assert r.macs["A"]["replayed"] > 0 and r.macs["S7"]["replayed"] > 0


def test_switch_buffer_never_holds_more_than_it_advertised():
    tr = []
    s = PathSession(sw=CBFCCfg(total_credits=256), nic=CBFCCfg(total_credits=256, drain_gbps=200), trace=tr)
    s.run(8_000)
    occ = [e["occ"] for e in tr if e["ev"] == "mac" and e["mac"] == "S1"]
    assert max(occ) <= 256 and max(occ) > 128


def test_tracing_does_not_change_the_path():
    kw = dict(hop1=LinkCfg(ber=2e-6, seed=3), sw=CBFCCfg(total_credits=512), nic=CBFCCfg(drain_gbps=500))
    a = PathSession(**kw)
    a.run(8_000)
    b = PathSession(**kw, trace=[])
    b.run(8_000)
    assert a.result() == b.result()

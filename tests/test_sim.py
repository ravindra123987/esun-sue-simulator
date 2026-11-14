"""Link simulator: LLR (UEC 1.1 §5.1), CBFC (§5.2) and their interaction (§5.2.9)."""

import pytest

from sim.link import link_rtt_ns, run_link
from sim.model import SEQ_MOD, CBFCCfg, CtlOS, Frame, LinkCfg, LLRCfg


def corrupt_once(pred):
    """Corruption hook that fires for the first object matching pred."""
    state = {"done": False}

    def hook(obj):
        if not state["done"] and pred(obj):
            state["done"] = True
            return True
        return None
    return hook


def test_clean_link_runs_at_line_rate():
    r = run_link(sim_ns=20_000)
    wire_eff = 1024 / (1024 + 20) * 800              # frame / (frame + preamble + IPG)
    assert r.goodput_gbps == pytest.approx(wire_eff, rel=0.01)   # CtlOS cost ~8/2048
    assert r.in_order and r.lost == 0 and r.duplicates == 0
    assert r.a["replayed"] == 0 and r.b["overflow"] == 0


def test_corrupted_frame_is_replayed_after_one_nack():
    def hooks(sim, A, B, a2b, b2a):
        a2b.corrupt_hook = corrupt_once(lambda o: isinstance(o, Frame) and o.fid == 300)
    r = run_link(hooks=hooks, sim_ns=20_000)
    assert r.b["rx_bad"] == 1 and r.b["nacks_tx"] == 1 and r.a["nacks_rx"] == 1
    assert r.a["replayed"] >= 1 and r.a["timer_replays"] == 0
    assert r.in_order and r.lost == 0 and r.duplicates == 0


def test_lost_nack_is_covered_by_replay_timer():
    def hooks(sim, A, B, a2b, b2a):
        a2b.corrupt_hook = corrupt_once(lambda o: isinstance(o, Frame) and o.fid == 300)
        b2a.corrupt_hook = corrupt_once(lambda o: isinstance(o, CtlOS) and o.kind == "LLR_NACK")
    r = run_link(hooks=hooks, sim_ns=30_000)
    assert r.a["nacks_rx"] == 0 and r.a["timer_replays"] >= 1
    assert r.in_order and r.lost == 0 and r.duplicates == 0


def test_sequence_numbers_wrap():
    def hooks(sim, A, B, a2b, b2a):
        start = SEQ_MOD - 100
        A.tx_seq, A.acked_seq, B.next_rx = start, start - 1, start
        a2b.corrupt_hook = corrupt_once(lambda o: isinstance(o, Frame) and o.seq == 5)   # just after the wrap
    r = run_link(hooks=hooks, sim_ns=20_000)
    assert r.delivered > 200 and r.a["nacks_rx"] == 1
    assert r.in_order and r.lost == 0 and r.duplicates == 0


def test_long_outage_flushes_then_reinitialises():
    llr = LLRCfg(outstanding_data_max=16_384, replay_timer_ns=500, replay_ct_max=3)
    r = run_link(link=LinkCfg(down=[(10_000, 15_000)]), llr=llr, sim_ns=40_000)
    assert r.a["flushes"] == 1
    assert r.in_order and r.duplicates == 0 and r.lost > 0
    # CBFC recovers exactly the credits of the frames FLUSH threw away
    assert r.b["cc_reclaimed"] == r.lost * 16
    assert r.goodput_gbps > 500                          # traffic resumed after INIT


def test_short_outage_recovers_without_loss():
    r = run_link(link=LinkCfg(down=[(10_000, 10_300)]), sim_ns=30_000)
    assert r.a["flushes"] == 0 and r.lost == 0 and r.in_order


def test_cbfc_matches_slow_receiver_without_overflow():
    r = run_link(cbfc=CBFCCfg(drain_gbps=400, total_credits=256), sim_ns=30_000)
    assert r.goodput_gbps == pytest.approx(400, rel=0.02)
    assert r.b["overflow"] == 0 and r.a["credit_stalls"] > 0


def test_lost_cf_updates_are_harmless():
    drop = {"n": 0}

    def hook(o):
        if isinstance(o, CtlOS) and o.kind == "CF_UPDATE":
            drop["n"] += 1
            return drop["n"] % 2 == 0                    # lose every other CF_Update
        return None

    def hooks(sim, A, B, a2b, b2a):
        b2a.corrupt_hook = hook
    r = run_link(cbfc=CBFCCfg(drain_gbps=400, total_credits=256), hooks=hooks, sim_ns=30_000)
    assert r.b["overflow"] == 0 and r.goodput_gbps == pytest.approx(400, rel=0.03)


def test_cc_update_reclaims_credits_of_frames_lost_without_llr():
    bad = {300, 301, 900}

    def hooks(sim, A, B, a2b, b2a):
        a2b.corrupt_hook = lambda o: True if isinstance(o, Frame) and o.fid in bad else None
    r = run_link(llr=LLRCfg(enabled=False), hooks=hooks, sim_ns=30_000)
    assert r.lost == 3 and r.b["rx_crc_drop"] == 3
    assert r.b["cc_reclaimed"] == 3 * 16                 # 1024 B / 64 B credits


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_llr_with_cbfc_never_overflows_or_loses(seed):
    r = run_link(link=LinkCfg(ber=2e-6, seed=seed),
                 cbfc=CBFCCfg(drain_gbps=400, total_credits=256, cc_interval_ns=300), sim_ns=40_000)
    assert r.a["replayed"] > 0                           # replays did happen
    assert r.b["overflow"] == 0 and r.lost == 0 and r.in_order and r.duplicates == 0
    assert r.b["cc_negative"] == 0 and r.b["cc_reclaimed"] == 0


BROKEN = dict(drain_gbps=400, total_credits=256, cc_interval_ns=300)


def _sum(kw, key, side="b", seeds=range(1, 5)):
    return sum(run_link(link=LinkCfg(ber=2e-6, seed=s), cbfc=CBFCCfg(**BROKEN, **kw), sim_ns=40_000).__dict__[side][key]
               for s in seeds)


def test_rule1_counting_replays_reports_phantom_leaks():
    assert _sum({"count_replays": True}, "cc_reclaimed") > 0


def test_rule2_counting_discards_makes_lost_credits_negative():
    assert _sum({"count_discards": True}, "cc_negative") > 0


def test_rule3_cc_update_in_discard_window_overflows_buffer():
    assert _sum({"cc_bypass_llr": True}, "overflow") > 0


def test_replay_buffer_below_bdp_limits_throughput():
    link = LinkCfg(cable_m=10)
    llr = LLRCfg()
    rtt = link_rtt_ns(link, llr)
    small = run_link(link=link, llr=LLRCfg(outstanding_data_max=4096), cbfc=CBFCCfg(enabled=False))
    big = run_link(link=link, llr=LLRCfg(outstanding_data_max=65536), cbfc=CBFCCfg(enabled=False))
    assert big.goodput_gbps > 750
    assert small.goodput_gbps < 0.6 * big.goodput_gbps
    # window-limited: about one buffer per round trip (plus one frame of slack)
    assert small.goodput_gbps == pytest.approx((4096 + 1024) * 8 / (rtt + 1044 / link.rate), rel=0.35)

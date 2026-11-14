"""M2 experiments: LLR + CBFC on one 800G link. Writes plots to docs/experiments/img/
and numbers to docs/experiments/llr-cbfc-results.json.

    .venv/bin/python tools/run_m2.py
"""

import json
import statistics
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from sim.link import link_rtt_ns, run_link  # noqa: E402
from sim.model import CBFCCfg, LinkCfg, LLRCfg  # noqa: E402

OUT = Path(__file__).resolve().parent.parent / "docs" / "experiments"
IMG = OUT / "img"
CABLES = [2, 10, 50, 100]
COLORS = {2: "#2f6fde", 10: "#0c9a86", 50: "#cf9200", 100: "#d23f73"}
plt.rcParams.update({"figure.dpi": 130, "axes.grid": True, "grid.alpha": 0.3, "font.size": 10})


def e1_replay_buffer():
    """How deep must the replay buffer be? (CBFC off, no errors)"""
    sizes = [2048 * 2 ** i for i in range(8)]            # 2 KB .. 256 KB
    res = {}
    fig, ax = plt.subplots(figsize=(6.4, 3.8))
    for m in CABLES:
        link, llr = LinkCfg(cable_m=m), LLRCfg()
        bdp = link_rtt_ns(link, llr) * link.rate
        ys = [run_link(link=link, llr=LLRCfg(outstanding_data_max=s, outstanding_seq_max=100000),
                       cbfc=CBFCCfg(enabled=False), sim_ns=30_000).goodput_gbps for s in sizes]
        res[m] = {"bdp_bytes": round(bdp), "goodput": dict(zip(sizes, [round(y, 1) for y in ys]))}
        ax.plot([s / 1024 for s in sizes], ys, "o-", color=COLORS[m], label=f"{m} m (BDP ≈ {bdp / 1024:.0f} KB)")
        ax.axvline(bdp / 1024, color=COLORS[m], ls=":", lw=1)
    ax.set_xscale("log", base=2)
    ax.set_xlabel("outstanding_data_max (KB)")
    ax.set_ylabel("goodput (Gb/s)")
    ax.set_title("E1  LLR replay buffer vs cable length (800G, 1 KB frames)")
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(IMG / "e1-replay-buffer.png")
    return res


def e2_credits():
    """What credit pool keeps the link at line rate? (64 B credits, LLR on)"""
    pools = [16 * 2 ** i for i in range(8)]              # 16 .. 2048 credits
    res = {}
    fig, ax = plt.subplots(figsize=(6.4, 3.8))
    for m in CABLES:
        link = LinkCfg(cable_m=m)
        cb0 = CBFCCfg()
        # credit loop: frame flight + CF_Update wait (slot + cf_min) + flight back
        loop_ns = 2 * link.prop_ns + LLRCfg().ctlos_spacing / link.rate + cb0.cf_min_ns + 1044 / link.rate
        need = loop_ns * link.rate / cb0.credit_size
        ys = [run_link(link=link, llr=LLRCfg(outstanding_data_max=1 << 20, outstanding_seq_max=100000),
                       cbfc=CBFCCfg(total_credits=p), sim_ns=30_000).goodput_gbps for p in pools]
        res[m] = {"estimated_credits_needed": round(need), "goodput": dict(zip(pools, [round(y, 1) for y in ys]))}
        ax.plot(pools, ys, "o-", color=COLORS[m], label=f"{m} m (≈{need:.0f} credits)")
        ax.axvline(need, color=COLORS[m], ls=":", lw=1)
    ax.set_xscale("log", base=2)
    ax.set_xlabel("receiver credits (TotalCredits, 64 B each)")
    ax.set_ylabel("goodput (Gb/s)")
    ax.set_title("E2  CBFC credit pool vs cable length (800G, 1 KB frames)")
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(IMG / "e2-credits.png")
    return res


def e3_ber():
    """LLR on vs off: what reaches the transport? (post-FEC BER, 3 m, 1 KB frames)"""
    bers = [1e-9, 1e-8, 1e-7, 1e-6, 1e-5]
    seeds = [1, 2, 3]
    res = {"on": {}, "off": {}}
    for mode in ("on", "off"):
        for ber in bers:
            runs = [run_link(link=LinkCfg(ber=ber, seed=s), llr=LLRCfg(enabled=(mode == "on")),
                             sim_ns=200_000) for s in seeds]
            sent = statistics.mean(r.a["tx_frames"] for r in runs)
            res[mode][ber] = {
                "goodput": round(statistics.mean(r.goodput_gbps for r in runs), 1),
                "lost_per_million": round(1e6 * statistics.mean(r.lost for r in runs) / sent, 1),
                "replayed_per_error": round(statistics.mean(
                    r.a["replayed"] / max(1, r.b["rx_bad"]) for r in runs), 1) if mode == "on" else None,
                "p99_latency_ns": round(statistics.mean(r.lat_p99_ns for r in runs), 1),
            }
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(9.6, 3.6))
    for mode, c in (("on", "#0c9a86"), ("off", "#d23f73")):
        a1.plot(bers, [res[mode][b]["goodput"] for b in bers], "o-", color=c, label=f"LLR {mode}")
        a2.plot(bers, [max(res[mode][b]["lost_per_million"], 0.05) for b in bers], "o-", color=c, label=f"LLR {mode}")
    for a in (a1, a2):
        a.set_xscale("log")
        a.set_xlabel("post-FEC bit error rate")
        a.legend(fontsize=8)
    a1.set_ylabel("goodput (Gb/s)")
    a1.set_title("E3a  goodput")
    a2.set_yscale("log")
    a2.set_ylabel("lost frames per million")
    a2.set_title("E3b  loss seen by the transport (0 drawn at 0.05)")
    fig.tight_layout()
    fig.savefig(IMG / "e3-ber.png")
    return res


def e4_rules():
    """§5.2.9: what each LLR+CBFC rule protects against (slow receiver, BER 2e-6)."""
    variants = {"correct": {}, "rule 1 broken (replays counted)": {"count_replays": True},
                "rule 2 broken (discards counted)": {"count_discards": True},
                "rule 3 broken (CC_Update in discard window)": {"cc_bypass_llr": True}}
    res = {}
    for name, kw in variants.items():
        runs = [run_link(link=LinkCfg(ber=2e-6, seed=s),
                         cbfc=CBFCCfg(drain_gbps=400, total_credits=256, cc_interval_ns=300, **kw),
                         sim_ns=60_000) for s in range(1, 6)]
        res[name] = {
            "overflow_drops": sum(r.b["overflow"] for r in runs),
            "frames_lost": sum(r.lost for r in runs),
            "cc_negative_events": sum(r.b["cc_negative"] for r in runs),
            "credits_falsely_reclaimed": sum(r.b["cc_reclaimed"] for r in runs),
            "goodput_gbps": round(statistics.mean(r.goodput_gbps for r in runs), 1),
        }
    return res


def e5_outage():
    """How long an outage can LLR absorb? (replay_timer 1 us, replay_ct_max 3)"""
    llr = LLRCfg(outstanding_data_max=16_384, replay_timer_ns=1000, replay_ct_max=3)
    durs = [100, 300, 1000, 2000, 3000, 4000, 6000, 10000]
    res = {}
    for d in durs:
        r = run_link(link=LinkCfg(down=[(10_000, 10_000 + d)]), llr=llr, sim_ns=40_000)
        res[d] = {"flushes": r.a["flushes"], "timer_replays": r.a["timer_replays"], "nacks": r.a["nacks_rx"],
                  "frames_lost": r.lost, "credits_reclaimed": r.b["cc_reclaimed"], "in_order": r.in_order}
    return res


def main():
    IMG.mkdir(parents=True, exist_ok=True)
    out = {"e1_replay_buffer": e1_replay_buffer(), "e2_credits": e2_credits(), "e3_ber": e3_ber(),
           "e4_rules": e4_rules(), "e5_outage": e5_outage()}
    (OUT / "llr-cbfc-results.json").write_text(json.dumps(out, indent=2, default=str) + "\n")
    print(json.dumps(out, indent=1, default=str))


if __name__ == "__main__":
    main()

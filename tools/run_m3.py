"""M3 experiments: the SUE-T endpoint (sim/suet.py) on a one-hop fabric (sim/fabric.py).
Writes plots to docs/experiments/img/m3-*.png and numbers to docs/experiments/suet-endpoint-results.json.

    .venv/bin/python tools/run_m3.py          # about a minute
"""

import json
import statistics
import time
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from sim import wire  # noqa: E402
from sim.fabric import Fabric  # noqa: E402
from sim.model import LinkCfg, LLRCfg  # noqa: E402
from sim.suet import SUETCfg  # noqa: E402
from sim.workloads import AllToAll, RingAllReduce  # noqa: E402

OUT = Path(__file__).resolve().parent.parent / "docs" / "experiments"
IMG = OUT / "img"
plt.rcParams.update({"figure.dpi": 130, "axes.grid": True, "grid.alpha": 0.3, "font.size": 10})
STACK_COL = {"ufh16": "#2f6fde", "esun": "#0c9a86", "udp": "#cf9200"}


def summary(r, extra=None):
    d = {"done": r.done, "failed": r.failed, "finished_us": round(r.finished_ns / 1000, 3) if r.finished_ns else None,
         "efficiency": round(r.efficiency, 4), "overhead_per_payload_byte": round(r.wire_bytes / r.payload_bytes - 1, 4) if r.payload_bytes else None,
         "pack_avg": round(r.pack_avg, 2), "lat_p50_ns": round(r.lat_p50_ns, 1), "lat_p99_ns": round(r.lat_p99_ns, 1),
         "pkts": r.ep["tx_pkts"], "bare_acks": r.ep["acks_tx"], "rodl_retx": r.ep["retx_pkts"], "rodl_nacks": r.ep["nacks_tx"],
         "rtos": r.ep["rtos"], "fatal_pdcs": r.ep["fatal"], "llr_replays": r.mac["nic"]["replayed"] + r.mac["sw"]["replayed"]}
    if extra:
        d.update(extra)
    return d


def t1_wire_table():
    """SUE-T §7.2.3: wire efficiency by header stack, ACK mode and packing, against RoCEv2 (analytical)."""
    res = {"suet": {}, "roce": {}}
    fig, ax = plt.subplots(figsize=(7, 4))
    ns = [1, 2, 4, 8, 16]
    for stack in ("ufh16", "esun", "udp"):
        for mode, ls in (("operational", "-"), ("delivery", "--")):
            ys = []
            for n in ns:
                pb = wire.transaction_bytes(stack, mode, n, piggyback=True)
                bare = wire.transaction_bytes(stack, mode, n, piggyback=False)
                res["suet"][f"{stack}/{mode}/{n}"] = {"frame_eff": round(pb["frame_eff"], 4), "wire_eff": round(pb["wire_eff"], 4),
                                                       "wire_eff_bare_ack": round(bare["wire_eff"], 4), "fwd_bytes": pb["fwd"], "rev_bytes": pb["rev"]}
                ys.append(100 * pb["wire_eff"])
            ax.plot(ns, ys, "o" + ls, color=STACK_COL[stack], label=f"{stack} · {mode} ACK")
    for size, n_eq in ((256, 1), (1024, 4), (4096, 16)):
        for ack_every in (1, 4):
            r = wire.roce_transaction_bytes("store", size, ack_every)
            res["roce"][f"write/{size}/ack_every_{ack_every}"] = {"frame_eff": round(r["frame_eff"], 4), "wire_eff": round(r["wire_eff"], 4), "fwd_bytes": r["fwd"], "rev_bytes": r["rev"]}
        r = wire.roce_transaction_bytes("load", size)
        res["roce"][f"read/{size}"] = {"frame_eff": round(r["frame_eff"], 4), "wire_eff": round(r["wire_eff"], 4)}
    for size, n_eq, c in ((256, 1, "#d23f73"), (1024, 4, "#a23fd2"), (4096, 16, "#6b6b6b")):
        y = 100 * wire.roce_transaction_bytes("store", size, 4)["wire_eff"]
        ax.axhline(y, color=c, ls=":", lw=1.2)
        ax.annotate(f"RoCEv2 write {size} B (ACK/4)", (16, y), xytext=(-4, 3), textcoords="offset points", ha="right", fontsize=8, color=c)
    for n, size in ((4, 1024), (16, 4096)):
        pb = wire.transaction_bytes("ufh16", "operational", n, piggyback=True)
        res["suet"][f"same_payload/{size}"] = {"packed": n, "wire_eff": round(pb["wire_eff"], 4)}
    ax.set_xscale("log", base=2)
    ax.set_xticks(ns)
    ax.set_xticklabels(ns)
    ax.set_xlabel("256 B transactions packed per packet")
    ax.set_ylabel("wire efficiency (%), preamble + IPG included")
    ax.set_title("T1  SUE-T wire efficiency vs RoCEv2 (stores, ACKs piggybacked)")
    ax.legend(fontsize=7.5, ncol=2)
    fig.tight_layout()
    fig.savefig(IMG / "m3-t1-wire.png")
    return res


def t2_packing_vs_load():
    """Packing is opportunistic (§7.3): what a slow and a fast XPU interface get, one way, two XPUs."""
    rates = [100, 200, 400, 600, 800, 1200, 1600, 3200]
    res = {}
    for g in rates:
        f = Fabric(n=2, workload=AllToAll(2, bytes_per_peer=1 << 20, senders=[0]), suet=SUETCfg(xpu_gbps=g))
        f.run(30_000_000)
        r = f.result()
        res[g] = summary(r, {"goodput_gbps": round(r.payload_bytes * 8 / r.finished_ns, 1), "pack_hist": r.pack_hist})
        # the same with a RODL window that never closes: the packing that remains is the port's, not the window's
        f = Fabric(n=2, workload=AllToAll(2, bytes_per_peer=1 << 20, senders=[0]), suet=SUETCfg(xpu_gbps=g, window=1024))
        f.run(30_000_000)
        r = f.result()
        res[g]["window_1024"] = {"pack_avg": round(r.pack_avg, 2), "efficiency": round(r.efficiency, 4),
                                 "lat_p50_ns": round(r.lat_p50_ns, 1), "lat_p99_ns": round(r.lat_p99_ns, 1)}
    fig, a1 = plt.subplots(figsize=(6.4, 3.8))
    a2 = a1.twinx()
    a1.plot(rates, [res[g]["pack_avg"] for g in rates], "o-", color="#2f6fde", label="CMD_PDUs per packet")
    a1.plot(rates, [res[g]["window_1024"]["pack_avg"] for g in rates], "o:", color="#2f6fde", lw=1, ms=4, label="… with a 1024-packet RODL window")
    a1.plot(rates, [100 * res[g]["efficiency"] / 10 for g in rates], "s--", color="#0c9a86", label="wire efficiency (% / 10)")
    a2.plot(rates, [res[g]["lat_p50_ns"] for g in rates], "^-", color="#d23f73", label="p50 latency")
    a2.plot(rates, [res[g]["lat_p99_ns"] for g in rates], "v:", color="#d23f73", label="p99 latency")
    a1.axvline(800, color="#888", ls=":", lw=1)
    a1.set_xscale("log", base=2)
    a1.set_xlabel("XPU command-interface rate (Gb/s), one 800G port")
    a1.set_ylabel("packing / efficiency")
    a2.set_ylabel("transaction latency (ns)")
    a2.grid(False)
    a1.set_title("T2  Packing and latency vs offered load (256 B stores)")
    h1, l1 = a1.get_legend_handles_labels()
    h2, l2 = a2.get_legend_handles_labels()
    a1.legend(h1 + h2, l1 + l2, fontsize=8, loc="center left")
    fig.tight_layout()
    fig.savefig(IMG / "m3-t2-packing.png")
    return res


def t3_ack_modes():
    """All-to-all on 8 XPUs: delivery vs operational ACK, three header stacks, stores and loads."""
    res = {}
    for op in ("store", "load"):
        for stack in ("ufh16", "esun", "udp"):
            for mode in ("operational", "delivery"):
                f = Fabric(n=8, workload=AllToAll(8, bytes_per_peer=32768, op=op), suet=SUETCfg(ack_mode=mode, stack=stack))
                f.run(3_000_000)
                res[f"{op}/{stack}/{mode}"] = summary(f.result())
    return res


def t4_where_the_retry_lives():
    """Bit errors on every cable: LLR hides them, RODL Go-Back-N repairs them end to end, SUE-lite dies."""
    bers = [1e-7, 1e-6, 1e-5]
    variants = {"LLR on + RODL retx": (True, True, 20000), "LLR off + RODL retx": (False, True, 20000),
                "LLR off + RODL retx, RTO 4 µs": (False, True, 4000), "LLR off, no retx (SUE-lite)": (False, False, 20000)}
    res = {}
    for name, (llr_on, retx, rto) in variants.items():
        res[name] = {}
        for ber in bers:
            runs = []
            for seed in (1, 2):
                f = Fabric(n=8, link=LinkCfg(ber=ber, seed=seed), llr=LLRCfg(enabled=llr_on),
                           workload=AllToAll(8, bytes_per_peer=32768, seed=seed), suet=SUETCfg(retx=retx, rto_ns=rto))
                f.run(3_000_000)
                runs.append(f.result())
            res[name][ber] = {
                "done": sum(r.done for r in runs), "failed": sum(r.failed for r in runs),
                "finished_us": round(statistics.mean(r.finished_ns for r in runs if r.finished_ns) / 1000, 2) if all(r.finished_ns for r in runs) else None,
                "lat_p99_ns": round(statistics.mean(r.lat_p99_ns for r in runs), 1),
                "lat_max_ns": round(max(r.lat_max_ns for r in runs), 1),
                "efficiency": round(statistics.mean(r.efficiency for r in runs), 4),
                "rodl_retx": sum(r.ep["retx_pkts"] for r in runs), "rodl_nacks": sum(r.ep["nacks_tx"] for r in runs),
                "rtos": sum(r.ep["rtos"] for r in runs), "fatal_pdcs": sum(r.ep["fatal"] for r in runs),
                "llr_replays": sum(r.mac["nic"]["replayed"] + r.mac["sw"]["replayed"] for r in runs)}
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(9.6, 3.6))
    cols = {"LLR on + RODL retx": "#0c9a86", "LLR off + RODL retx": "#cf9200", "LLR off + RODL retx, RTO 4 µs": "#a23fd2",
            "LLR off, no retx (SUE-lite)": "#d23f73"}
    for name in variants:
        fin = [res[name][b]["finished_us"] or float("nan") for b in bers]
        a1.plot(bers, fin, "o-", color=cols[name], label=name)
        a2.plot(bers, [res[name][b]["lat_p99_ns"] for b in bers], "o-", color=cols[name], label=name)
    for a in (a1, a2):
        a.set_xscale("log")
        a.set_xlabel("post-FEC bit error rate")
        a.legend(fontsize=7.5)
    a1.set_ylabel("all-to-all completion (µs)")
    a1.set_title("T4a  completion time (SUE-lite: survivors only)")
    a2.set_ylabel("p99 transaction latency (ns)")
    a2.set_yscale("log")
    a2.set_title("T4b  tail latency")
    fig.tight_layout()
    fig.savefig(IMG / "m3-t4-retry.png")
    return res


def t5_load_balancing():
    """Two ports per XPU: fixed port per PDC (§6 step 6) vs per-packed-group balancing (§7.6)."""
    res = {}
    for cables, hook in (("equal 3 m", None), ("plane 1 at 20 m", 20)):
        for lb in ("pdc", "group"):
            def hooks(f, m=hook):
                if m:
                    for n, w in f.wires.items():
                        if "p1" in n:
                            w.cfg = LinkCfg(cable_m=m)
            f = Fabric(n=8, ports=2, workload=AllToAll(8, bytes_per_peer=32768), suet=SUETCfg(lb=lb), hooks=hooks)
            f.run(3_000_000)
            res[f"{cables}/{lb}"] = summary(f.result())
    return res


def t6_allreduce_tail():
    """Ring all-reduce of 1 MB on 8 XPUs, 12 seeds with start jitter: completion-time distribution."""
    res = {}
    fig, ax = plt.subplots(figsize=(6.4, 3.8))
    for mode, c in (("operational", "#0c9a86"), ("delivery", "#cf9200")):
        fins, p99s = [], []
        for seed in range(1, 13):
            f = Fabric(n=8, workload=RingAllReduce(8, total_bytes=1 << 20, jitter_ns=300, seed=seed), suet=SUETCfg(ack_mode=mode))
            f.run(5_000_000)
            r = f.result()
            fins.append(r.finished_ns / 1000)
            p99s.append(r.lat_p99_ns)
        fins.sort()
        res[mode] = {"completion_us_p50": round(statistics.median(fins), 2), "completion_us_max": round(fins[-1], 2),
                     "completion_us_min": round(fins[0], 2), "txn_p99_ns_mean": round(statistics.mean(p99s), 1),
                     "ideal_us": round(2 * 7 * (1 << 20) / 8 / 100 / 1000, 2)}
        ax.step(fins, [i / len(fins) for i in range(1, len(fins) + 1)], where="post", color=c, label=f"{mode} ACK")
    ax.axvline(res["operational"]["ideal_us"], color="#888", ls=":", lw=1, label="2(n−1) chunks at line rate")
    ax.set_xlabel("ring all-reduce completion (µs), 1 MB over 8 XPUs")
    ax.set_ylabel("fraction of runs")
    ax.set_title("T6  completion-time distribution")
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(IMG / "m3-t6-allreduce.png")
    return res


def main():
    IMG.mkdir(parents=True, exist_ok=True)
    out = {}
    for name, fn in (("t1_wire", t1_wire_table), ("t2_packing", t2_packing_vs_load), ("t3_ack_modes", t3_ack_modes),
                     ("t4_retry", t4_where_the_retry_lives), ("t5_load_balancing", t5_load_balancing), ("t6_allreduce", t6_allreduce_tail)):
        t = time.time()
        out[name] = fn()
        print(f"{name}: {time.time() - t:.1f} s")
    (OUT / "suet-endpoint-results.json").write_text(json.dumps(out, indent=2, default=str) + "\n")
    print(json.dumps(out, indent=1, default=str))


if __name__ == "__main__":
    main()

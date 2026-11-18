"""M5: where should the retry live? Five recovery designs under six faults on a 4-XPU x 4-plane fabric.

Writes docs/experiments/img/m5-*.png and docs/experiments/planes-results.json; the write-up is
docs/where-should-retry-live.md.

    .venv/bin/python tools/run_m5.py            # about two minutes
"""

import json
import statistics
import sys
import textwrap
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sim.planes import DESIGNS, FAULT_AT, N, P, SCENARIOS, run  # noqa: E402

OUT = Path(__file__).resolve().parent.parent / "docs" / "experiments"
IMG = OUT / "img"
plt.rcParams.update({"figure.dpi": 130, "axes.grid": True, "grid.alpha": 0.3, "font.size": 10})
COL = {"sue-t": "#d23f73", "sue-t+fo": "#cf9200", "metaroce": "#0c9a86", "mrc": "#2f6fde", "mrc+llr": "#6b6b6b"}
LABEL = {"sue-t": "SUE-T 1.0 (pinned)", "sue-t+fo": "SUE-T + failover", "metaroce": "MetaRoCE-style",
         "mrc": "MRC-style", "mrc+llr": "MRC-style + LLR"}
BYTES = 4 << 20
UNTIL = 600_000.0
SEEDS = (1, 2, 3)
BIN = 1000.0

ASSUME = (f"{N} XPUs x {P} planes, one switch per plane, all-to-all of {BYTES >> 20} MB per peer as 256 B stores, packed to 2 KB, "
          "operational ACKs, UFH_16; XPU interface 3.2 Tb/s (= 4 ports); every link 800G, 3 m, 50 ns MAC/PHY, CBFC on, "
          "LLR as the design says (64 KB replay buffer, 2 us timer, 8 retries); switches store-and-forward, 0 ns pipeline, "
          "discard frames for a down egress after 1 us; endpoints see their own link down after 1 us. Transport timer fixed: "
          "20 us with LLR (> LLR's 18 us worst case), 10 us without. Faults on plane 1 at 5 us.")


def assumptions(fig, text):
    lines = textwrap.wrap("Assumptions: " + text, width=int(fig.get_figwidth() * 22))
    fig.text(0.01, 0.012, "\n".join(lines), fontsize=6.2, color="#555", ha="left", va="bottom", linespacing=1.25)
    fig.tight_layout(rect=(0, 0.02 + len(lines) * 10.5 / 72 / fig.get_figheight(), 1, 1))


def one(design, scenario, seed):
    f, r, wl = run(design, scenario, until=UNTIL, bytes_per_peer=BYTES, seed=seed)
    e = r.ep
    ok = r.done - r.failed
    return {
        "ok": ok, "failed": r.failed, "total": wl.total, "stuck": wl.total - r.done,
        "finished_us": round(r.finished_ns / 1000, 2) if r.finished_ns else None,
        "lat_p99_us": round(r.lat_p99_ns / 1000, 2), "lat_max_us": round(r.lat_max_ns / 1000, 2),
        "retx": e["retx_pkts"], "rtos": e["rtos"], "moves": e["moves"], "bad_marks": e["bad_marks"],
        "restores": e["restores"], "fatal": e["fatal"], "dup_rx": e["dup_rx"], "gap_drops": e["gap_drops"],
        "nacks": e["nacks_rx"], "llr_replays": r.mac["nic"]["replayed"] + r.mac["sw"]["replayed"],
        "llr_flushes": r.mac["nic"]["flushes"] + r.mac["sw"]["flushes"], "sw_dropped": r.sw_dropped,
        "efficiency": round(r.efficiency, 4),
        "timeline": _bins(wl.timeline),
    }


def _bins(tl):
    out = {}
    for t, b in tl:
        k = int(t // BIN)
        out[k] = out.get(k, 0) + b
    return out


def agg(runs):
    a = {}
    for k in runs[0]:
        if k == "timeline":
            continue
        vals = [r[k] for r in runs]
        if all(v is None for v in vals):
            a[k] = None
        elif any(v is None for v in vals):
            a[k] = None                       # not every seed finished: report as unfinished
            a[k + "_finished_seeds"] = sum(v is not None for v in vals)
        elif isinstance(vals[0], float):
            a[k] = round(statistics.mean(vals), 2)
        else:
            a[k] = round(statistics.mean(vals), 1) if k not in ("total",) else vals[0]
    a["timeline"] = runs[0]["timeline"]
    return a


def timeline_plot(res, scenario, fname, title):
    fig, ax = plt.subplots(figsize=(7.2, 3.9))
    for d in DESIGNS:
        tl = res[scenario][d]["timeline"]
        if not tl:
            continue
        xs = sorted(int(k) for k in tl)
        last = xs[-1]
        xs = list(range(0, min(last + 2, int(UNTIL / BIN))))
        ys = [tl.get(x, tl.get(str(x), 0)) * 8 / BIN for x in xs]          # Gb/s
        ax.plot([x + 0.5 for x in xs], ys, color=COL[d], lw=1.4, label=LABEL[d])
    ax.axvline(FAULT_AT / 1000, color="#888", ls=":", lw=1)
    ax.set_xlim(0, 100)
    ax.set_xlabel("time (us)")
    ax.set_ylabel("stores completed, all XPUs (Gb/s per us bin)")
    ax.set_title(title)
    ax.legend(fontsize=7.5, loc="upper right")
    assumptions(fig, ASSUME + " Seed 1 shown.")
    fig.savefig(IMG / fname)


def main():
    IMG.mkdir(parents=True, exist_ok=True)
    res = {}
    for sc in SCENARIOS:
        res[sc] = {}
        for d in DESIGNS:
            res[sc][d] = agg([one(d, sc, s) for s in SEEDS])
            a = res[sc][d]
            print(f"{sc:13s} {d:9s} ok {a['ok']:.0f}/{a['total']} failed {a['failed']:.0f} stuck {a['stuck']:.0f} "
                  f"fin {a['finished_us']} p99 {a['lat_p99_us']} max {a['lat_max_us']} retx {a['retx']} rto {a['rtos']} "
                  f"mv {a['moves']} bad {a['bad_marks']} rest {a['restores']} fatal {a['fatal']} llr {a['llr_replays']} "
                  f"fl {a['llr_flushes']} drop {a['sw_dropped']}", flush=True)
    timeline_plot(res, "plane-kill", "m5-plane-kill.png", "M5  Plane 1 dies at 5 us")
    timeline_plot(res, "remote-link", "m5-remote-link.png", "M5  Switch 1 -> XPU 2 link dies at 5 us")
    timeline_plot(res, "plane-flap", "m5-plane-flap.png", "M5  Plane 1 down from 5 to 15 us")
    slim = {sc: {d: {k: v for k, v in a.items() if k != "timeline"} for d, a in ds.items()} for sc, ds in res.items()}
    (OUT / "planes-results.json").write_text(json.dumps(slim, indent=1))


if __name__ == "__main__":
    main()

"""Run the visualiser scenarios through the two-hop simulator and write docs/viz/traces.js.

    .venv/bin/python tools/make_traces.py

The path is XPU A -> switch -> XPU B (sim/path.py). Every frame, control block and state
change in the viewer comes from these runs.
"""

import json
from pathlib import Path

from sim.model import CBFCCfg, CtlOS, Frame, LinkCfg, LLRCfg
from sim.path import PathSession
from sim.trace import annotate

OUT = Path(__file__).resolve().parent.parent / "docs" / "viz" / "traces.js"


def corrupt(*preds):
    """Corruption hook: each predicate fires once, for the first object it matches."""
    left = list(preds)

    def hook(obj):
        for p in left:
            if p(obj):
                left.remove(p)
                return True
        return None
    return hook


def frame_fid(n):
    return lambda o: isinstance(o, Frame) and o.fid == n and o.tx_count == 1


def first_ctlos(kind):
    return lambda o: isinstance(o, CtlOS) and o.kind == kind


SCENARIOS = [
    dict(id="clean", title="Clean path", sim_ns=500,
         summary="XPU A streams 1 KB frames to XPU B through one switch. Both hops are error-free 3 m, 800G "
                 "cables. Each cable end ACKs in every control slot and returns credits as fast as they are "
                 "spent, so the switch holds each frame for only a moment.",
         watch="Two replay buffers fill: XPU A's NIC keeps every frame until switch port 1 ACKs it, and switch "
               "port 7 keeps it again until XPU B ACKs it. LLR and credits work per cable, not end to end."),
    dict(id="bit-error", title="Bit error on hop 1", sim_ns=600,
         corrupt={"a2s": lambda: corrupt(frame_fid(12))},
         summary="Frame #12 is corrupted on the first cable. Switch port 1's FCS check fails, it sends one "
                 "NACK, drops the frames that follow and XPU A's NIC replays from its buffer. Nothing is lost.",
         watch="Port 1 stops accepting until the replayed frames (dashed) arrive. The switch buffer and "
               "hop 2 go quiet for about one round trip, then catch up in order."),
    dict(id="bit-error-2", title="Bit error on hop 2", sim_ns=600,
         corrupt={"s2b": lambda: corrupt(frame_fid(12))},
         summary="The same error on the second cable. Now switch port 7 gets the NACK and replays out of its "
                 "own replay buffer. XPU A never hears about it.",
         watch="XPU A keeps sending; the error is fixed inside hop 2. The switch buffer grows a little while "
               "port 7 replays, and its credits to XPU A come back a little later."),
    dict(id="lost-nack", title="Bit error and a lost NACK", sim_ns=900,
         corrupt={"a2s": lambda: corrupt(frame_fid(12)), "s2a": lambda: corrupt(first_ctlos("LLR_NACK"))},
         llr=dict(replay_timer_ns=300),
         summary="An error on hop 1, but port 1's NACK is corrupted on the way back. Port 1 stays silent (one "
                 "NACK per error), so XPU A's NIC only notices when its replay timer expires.",
         watch="The replay starts a full replay-timer later (300 ns here, 2 µs by default): the timer must be "
               "short, but never shorter than a round trip."),
    dict(id="backpressure", title="Slow XPU B: backpressure", sim_ns=1800,
         sw=dict(total_credits=512), nic=dict(total_credits=512, drain_gbps=400),
         summary="XPU B's NIC can write only 400 Gb/s into HBM. Its 32 KB receive buffer fills, so it returns "
                 "credits to switch port 7 more slowly. Port 7 stalls, port 1's 32 KB buffer fills behind it, "
                 "and finally XPU A's NIC runs out of credits too.",
         watch="Backpressure travels back one hop at a time: XPU B's buffer, then port 7's credits, then the "
               "switch buffer, then XPU A. The path settles at 400G and nothing is ever dropped."),
    dict(id="small-pool", title="Too few credits on hop 1", sim_ns=700,
         sw=dict(total_credits=64),
         summary="The switch gives port 1 only 64 credits (four 1 KB frames). That cannot cover hop 1's credit "
                 "loop (frame flight, a control slot and the CF_Update flight back, about 150 ns), so XPU A's NIC "
                 "keeps running out even though the switch buffer is almost empty.",
         watch="XPU A's credits sit at 64/64 while the switch buffer stays nearly empty: the credits are tied up "
               "on the cable. Hop 2 is starved too. Experiment E2 sizes the pool."),
    dict(id="outage-short", title="Short outage: LLR absorbs it", sim_ns=1600,
         hop1=dict(down=[(150, 1000)]), llr=dict(replay_timer_ns=250, replay_ct_max=2),
         sw=dict(cc_interval_ns=350),
         summary="Hop 1's cable drops for 850 ns. Every 250 ns XPU A's replay timer expires and it replays into "
                 "the dead cable. The cable returns before it runs out of retries, so nothing is lost.",
         watch="Dashed replays die on the dead cable until it comes back. The switch and hop 2 drain and wait; "
               "frames that crossed before the outage show up as duplicates and are dropped at port 1."),
    dict(id="outage-flush", title="Long outage → FLUSH", sim_ns=2600,
         hop1=dict(down=[(150, 1400)]), llr=dict(replay_timer_ns=250, replay_ct_max=2),
         sw=dict(cc_interval_ns=350),
         summary="Hop 1 is down for 1250 ns, longer than LLR will wait (250 ns timer, 2 retries). XPU A's NIC "
                 "gives up and flushes, resynchronises with INIT when the cable is back, and CBFC's CC_Update "
                 "returns the credits of the lost frames.",
         watch="The replay buffer empties at FLUSH, INIT and INIT_ECHO cross the cable and the credit gauge "
               "drops when the CC_Update shows the lost frames. Only the transport can resend them."),
    dict(id="no-llr", title="Bit error without LLR", sim_ns=1200,
         corrupt={"a2s": lambda: corrupt(frame_fid(12))}, llr=dict(enabled=False),
         sw=dict(cc_interval_ns=400),
         summary="LLR turned off, as ESUN allows. The corrupted frame is dropped at switch port 1 and the next "
                 "frames go on to XPU B with a hole. Only the transport (RODL) could recover it.",
         watch="No NACK, no replay, no replay buffers. The credits the lost frame used come back only when a "
               "CC_Update shows them missing."),
]


def setup(sc):
    """PathSession arguments and the viewer's cfg block for one scenario (shared with tools/live.py)."""
    def link(k, seed):
        kw = dict(sc.get(k, {}))
        if "down" in kw:
            kw["down"] = [tuple(d) for d in kw["down"]]
        return LinkCfg(seed=seed, **kw)
    hop1, hop2 = link("hop1", 1), link("hop2", 2)
    llr = LLRCfg(**sc.get("llr", {}))
    sw, nic = CBFCCfg(**sc.get("sw", {})), CBFCCfg(**sc.get("nic", {}))

    def hooks(sim, macs, wires):
        for name, make in sc.get("corrupt", {}).items():
            wires[name].corrupt_hook = make()        # fresh hook each run: hooks are stateful
    cfg = {"rate_gbps": hop1.rate_gbps, "frame": 1024, "sim_ns": sc.get("sim_ns"),
           "hops": [{"cable_m": h.cable_m, "prop_ns": round(h.prop_ns, 3), "down": [list(d) for d in h.down]}
                    for h in (hop1, hop2)],
           "llr": {"enabled": llr.enabled, "replay_timer_ns": llr.replay_timer_ns,
                   "replay_ct_max": llr.replay_ct_max, "ctlos_spacing": llr.ctlos_spacing},
           "credits": {"S1": sw.total_credits, "B": nic.total_credits}, "credit_size": sw.credit_size,
           "nic_gbps": nic.drain_gbps}
    kw = dict(hop1=hop1, hop2=hop2, llr=llr, sw=sw, nic=nic, hooks=hooks)
    return kw, cfg


def down_of(cfg):
    return {i + 1: h["down"] for i, h in enumerate(cfg["hops"]) if h["down"]}


def run(sc):
    kw, cfg = setup(sc)
    tr = []
    s = PathSession(trace=tr, **kw)
    s.run(sc["sim_ns"])
    r = s.result(warmup_ns=0)
    return {
        "id": sc["id"], "title": sc["title"], "summary": sc["summary"], "watch": sc["watch"],
        "cfg": cfg,
        "result": {"delivered": r.delivered, "lost": r.lost, "in_order": r.in_order,
                   "replayed": r.macs["A"]["replayed"] + r.macs["S7"]["replayed"]},
        "events": tr,
        "notes": annotate(tr, down_of(cfg), cfg),
    }


def build():
    return [run(sc) for sc in SCENARIOS]


def render(traces) -> str:
    body = json.dumps(traces, separators=(",", ":"))
    return ("// Generated by tools/make_traces.py from the two-hop simulator (sim/path.py). Do not edit.\n"
            f"window.SUE_TRACES = {body};\n")


def main(out: Path = OUT):
    out.parent.mkdir(parents=True, exist_ok=True)
    traces = build()
    out.write_text(render(traces))
    for t in traces:
        print(f"{t['id']:15s} {len(t['events']):5d} events  {len(t['notes']):2d} notes  {t['result']}")
    print(f"wrote {out} ({out.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()

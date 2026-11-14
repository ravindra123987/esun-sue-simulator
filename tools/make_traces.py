"""Run the visualiser scenarios through the link simulator and write docs/viz/traces.js.

    .venv/bin/python tools/make_traces.py

Every frame, control block and state change in the viewer comes from these runs.
"""

import json
from pathlib import Path

from sim.link import run_link
from sim.model import CBFCCfg, CtlOS, Frame, LinkCfg, LLRCfg
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
    dict(id="clean", title="Clean link", sim_ns=400,
         summary="A backlogged sender on an error-free 3 m link. The pipe fills, B acknowledges in every "
                 "control slot, A's replay buffer stays about one link round trip deep, and credits come "
                 "back as fast as they are spent.",
         watch="The replay buffer (A) grows until the first ACK arrives, then stays level. Credits in use "
               "stay flat: the 1024-credit pool is far more than this short link needs."),
    dict(id="bit-error", title="Bit error → NACK → replay", sim_ns=500,
         a2b=lambda: corrupt(frame_fid(12)),
         summary="One frame is corrupted on the wire. B discards it, sends one NACK, drops the frames that "
                 "follow, and A replays from its buffer. Nothing is lost.",
         watch="B's next_rx_seq stops while the replayed frames (dashed) are on their way. The delivered "
               "count pauses for about one round trip, then catches up in order."),
    dict(id="lost-nack", title="Bit error and a lost NACK", sim_ns=900,
         a2b=lambda: corrupt(frame_fid(12)), b2a=lambda: corrupt(first_ctlos("LLR_NACK")),
         llr=dict(replay_timer_ns=300),
         summary="The same error, but B's NACK is corrupted too. B stays silent (one NACK per error), so "
                 "A only notices when its replay timer expires.",
         watch="The replay starts a full replay-timer later than in the previous scenario (300 ns here, "
               "2 µs by default), which is why the timer must be short but never shorter than a round trip."),
    dict(id="slow-receiver", title="Slow receiver: credits run out", sim_ns=700,
         cbfc=dict(drain_gbps=400, total_credits=64),
         summary="B's buffer holds only 64 credits (four 1 KB frames) and drains at 400 Gb/s. A must stop "
                 "whenever its credits are used up and wait for CF_Updates.",
         watch="A's credit bar hits the limit and the stall flag lights. Gaps open on the wire: the link "
               "runs at the receiver's pace and nothing is ever dropped."),
    dict(id="outage-short", title="Short outage: LLR absorbs it", sim_ns=1600,
         link=dict(down=[(150, 1000)]), llr=dict(replay_timer_ns=250, replay_ct_max=2),
         cbfc=dict(cc_interval_ns=350),
         summary="The link drops for 850 ns. Every 250 ns A's replay timer expires and A replays into the "
                 "dead link. The link returns before A runs out of retries, so the next replay gets through "
                 "and nothing is lost.",
         watch="Dashed replays die on the dead link until it comes back. The replay buffer never empties, "
               "and B delivers the frames in order. Frames that arrived before the outage show up as "
               "duplicates and are dropped."),
    dict(id="outage-flush", title="Long outage → FLUSH", sim_ns=2600,
         link=dict(down=[(150, 1400)]), llr=dict(replay_timer_ns=250, replay_ct_max=2),
         cbfc=dict(cc_interval_ns=350),
         summary="The same link down for 1250 ns, longer than LLR will wait (250 ns timer, 2 retries). LLR "
                 "gives up and flushes, resynchronises with INIT once the link is back, and CBFC's "
                 "CC_Update returns the credits of the lost frames.",
         watch="The replay buffer empties at FLUSH, INIT and INIT_ECHO cross, and A's credits in use drop "
               "when the CC_Update shows the lost frames. Those frames are gone: only the transport can "
               "resend them."),
    dict(id="no-llr", title="Same bit error without LLR", sim_ns=1200,
         a2b=lambda: corrupt(frame_fid(12)), llr=dict(enabled=False), cbfc=dict(cc_interval_ns=400),
         summary="LLR turned off, as ESUN allows on host links. The corrupted frame is simply dropped; "
                 "the next frames are delivered with a hole. Only the transport (RODL) could recover it.",
         watch="No NACK, no replay, no replay buffer. The credits the lost frame used come back only when "
               "a CC_Update shows them missing."),
]


def run(sc):
    link = LinkCfg(**sc.get("link", {}))
    llr = LLRCfg(**sc.get("llr", {}))
    cbfc = CBFCCfg(**sc.get("cbfc", {}))

    def hooks(sim, A, B, a2b, b2a):
        if "a2b" in sc:
            a2b.corrupt_hook = sc["a2b"]()          # fresh hook each run: hooks are stateful
        if "b2a" in sc:
            b2a.corrupt_hook = sc["b2a"]()
    tr = []
    r = run_link(link=link, llr=llr, cbfc=cbfc, sim_ns=sc["sim_ns"], warmup_ns=0, hooks=hooks, trace=tr)
    return {
        "id": sc["id"], "title": sc["title"], "summary": sc["summary"], "watch": sc["watch"],
        "cfg": {"rate_gbps": link.rate_gbps, "cable_m": link.cable_m, "prop_ns": round(link.prop_ns, 3),
                "frame": 1024, "down": link.down, "sim_ns": sc["sim_ns"],
                "llr": {"enabled": llr.enabled, "replay_timer_ns": llr.replay_timer_ns,
                        "replay_ct_max": llr.replay_ct_max, "ctlos_spacing": llr.ctlos_spacing},
                "cbfc": {"total_credits": cbfc.total_credits, "credit_size": cbfc.credit_size,
                         "drain_gbps": cbfc.drain_gbps}},
        "result": {"delivered": r.delivered, "lost": r.lost, "in_order": r.in_order,
                   "replayed": r.a["replayed"], "goodput_gbps": round(r.goodput_gbps, 1)},
        "events": tr,
        "notes": annotate(tr, link.down),
    }


def build():
    return [run(sc) for sc in SCENARIOS]


def render(traces) -> str:
    body = json.dumps(traces, separators=(",", ":"))
    return ("// Generated by tools/make_traces.py from the link simulator (sim/). Do not edit.\n"
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

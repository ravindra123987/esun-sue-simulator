"""Run the visualiser scenarios through the simulator and write docs/viz/traces.js.

    .venv/bin/python tools/make_traces.py

Link-layer scenarios run the two-hop path XPU A -> switch -> XPU B (sim/path.py). Endpoint
scenarios run two SUE-T instances on the one-hop fabric (sim/fabric.py) and are relabelled
to the same names, so the viewer draws both on one picture. Every frame, control block and
state change in the viewer comes from these runs.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))      # run as a script: make `tools` importable

from sim.fabric import Fabric
from sim.model import CBFCCfg, CtlOS, Frame, LinkCfg, LLRCfg
from sim.path import PathSession
from sim.suet import SUETCfg
from sim.trace import annotate
from sim.workloads import AllToAll

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
    # ---- SUE-T endpoint (M3): two SUE-T instances on the one-hop fabric, same picture
    dict(id="suet-stores", kind="endpoint", title="SUE-T: packed stores, operational ACK", sim_ns=1300,
         wl=dict(op="store", bytes=16384, senders=["A"]), suet=dict(ack_mode="operational"),
         summary="XPU A issues 64 stores of 256 B to XPU B at 1.6 Tb/s, twice what one 800G port carries. The "
                 "first one leaves alone; while it is on the wire the queue builds, so the next packets carry "
                 "up to eight stores each (2 KB). XPU B acknowledges once its XPU has executed them; the ACK "
                 "comes back as a 64 B packet because nothing else is going A's way.",
         watch="Packet labels: PSN and how many transactions are inside. Click a #store to follow it from the "
               "XPU's queue into a PSN, across both hops and back as an ACK. The Counters tab shows the wire "
               "efficiency climbing as packets fill up."),
    dict(id="suet-delivery", kind="endpoint", title="SUE-T: delivery ACK mode", sim_ns=1400,
         wl=dict(op="store", bytes=16384, senders=["A"]), suet=dict(ack_mode="delivery"),
         summary="The same 64 stores with delivery ACKs: XPU B acknowledges on arrival, and its XPU's response "
                 "to every store travels back as a 16 B command on the response TC. Those response packets "
                 "are what operational ACK mode saves.",
         watch="Twice as many packets cross the fabric. The purple packets going left are response commands "
               "(packed eight at a time, like requests); they need ACKs of their own, carried by A's requests."),
    dict(id="suet-loads", kind="endpoint", title="SUE-T: loads, data in the ACK", sim_ns=1300,
         wl=dict(op="load", bytes=8192, senders=["A"]), suet=dict(ack_mode="operational"),
         summary="XPU A loads 32 × 256 B from XPU B. Load requests carry no data (a 92 B packet for eight of "
                 "them); the data comes back as SES responses inside an ACK packet, up to 2 KB per packet.",
         watch="Tiny packets right, big ones left. A load is complete when its data arrives, not when the "
               "request is acknowledged."),
    dict(id="suet-bidir", kind="endpoint", title="SUE-T: traffic both ways, free ACKs", sim_ns=1500,
         wl=dict(op="store", bytes=32768, senders=["A", "B"]), suet=dict(ack_mode="operational"),
         summary="Both XPUs store 32 KB to each other. Every request header carries the ACK state for the "
                 "other direction, so almost no ACK packets are needed: this is the case SUE-T is designed for.",
         watch="Look for 'carries the ACK' captions and the small number of bare ACK packets in the Counters."),
    dict(id="suet-gbn", kind="endpoint", title="RODL Go-Back-N (LLR off)", sim_ns=2200,
         wl=dict(op="store", bytes=16384, senders=["A"]), suet=dict(ack_mode="operational"), llr=dict(enabled=False),
         corrupt={"a2s": lambda: corrupt(frame_fid(3))}, sw=dict(cc_interval_ns=600),
         summary="LLR is off and the packet with PSN 2 is corrupted on hop 1. The switch drops it; XPU B sees "
                 "PSN 3 when it expects 2, drops everything after the gap and NACKs once. XPU A goes back to "
                 "PSN 2 and resends the hold buffer in order: a path round trip of traffic, not a link one.",
         watch="Compare with 'Bit error on hop 1': there LLR repaired the loss inside hop 1 in one link round trip "
               "and RODL never knew. Here the transport does it end to end."),
    dict(id="suet-lite", kind="endpoint", title="SUE-lite: a loss closes the PDC", sim_ns=1500,
         wl=dict(op="store", bytes=16384, senders=["A"]), suet=dict(ack_mode="operational", retx=False),
         llr=dict(enabled=False), corrupt={"a2s": lambda: corrupt(frame_fid(3))}, sw=dict(cc_interval_ns=600),
         summary="The same loss on a SUE-lite instance (no transport retransmission, §7.8). The NACK has nothing "
                 "to trigger: XPU A closes the connection and every store in flight fails; a later packet would "
                 "re-establish the PDC with syn.",
         watch="The 'fails' captions. SUE-lite is only viable where the link itself is lossless, which at real "
               "error rates means LLR on."),
    dict(id="suet-slow-xpu", kind="endpoint", title="SUE-T: slow XPU, no packing", sim_ns=1200,
         wl=dict(op="store", bytes=4096, senders=["A"]), suet=dict(ack_mode="operational", xpu_gbps=200),
         summary="XPU A issues stores at only 200 Gb/s into an 800G port. The queue never builds, so every "
                 "packet carries one 256 B store (292 B on the wire) and every packet gets its own ACK.",
         watch="Wire efficiency in the Counters stays below 80%: §7.3's work-conserving scheduler never waits "
               "to pack. Packing is a property of the load, not of the scheduler."),
    # ---- captured on the wire (M4): emulator runs with two XPUs, both links captured, tools/pcap2trace.py
    dict(id="cap-clean", kind="captured", title="Captured: a clean run", pcap="cap-clean",
         summary="The M4 emulator with two XPUs: XPU A writes 64 KB to XPU B through the user-space switch. Every "
                 "frame and control unit here was captured on the two veths; times are real (milliseconds), only the "
                 "crossing of each cable is drawn slower so you can see it.",
         watch="The LLR_INIT handshake at the start, then data frames carrying LLR sequence numbers, a stream of LLR "
               "ACKs and CF_Updates coming back, and periodic CC_Updates: the link layer, on real frames."),
    dict(id="cap-ber-hop2", kind="captured", title="Captured: bit errors on hop 2, LLR repairs them", pcap="cap-ber-hop2",
         summary="Bit errors (2e-5) on XPU B's cable in both directions. Corrupted frames fail the shim's CRC at the "
                 "receiving port, which NACKs; switch port 7 replays from its buffer.",
         watch="Red frames on hop 2, NACKs going back, dashed replays. XPU B's RODL never sees a gap: the transport "
               "does not know anything happened."),
    dict(id="cap-outage-hop1", kind="captured", title="Captured: hop 1 down, FLUSH, RODL recovers", pcap="cap-outage-hop1",
         summary="XPU A's cable goes down for 0.7 s, longer than LLR will wait. XPU A's port flushes its replay buffer, "
                 "re-initialises when the cable is back, and what was flushed is missing at XPU B: RODL sees a gap, "
                 "NACKs, and XPU A resends with the retransmission flag set.",
         watch="The silence on hop 1 (inferred as the outage), LLR_INIT again afterwards, then the RODL NACK and the "
               "resent packets: the transport repairing what the link gave up on."),
    dict(id="cap-no-llr", kind="captured", title="Captured: LLR off, RODL does the work", pcap="cap-no-llr",
         summary="The same bit errors on hop 1 with LLR off. A corrupted frame is simply gone; XPU B's RODL sees the "
                 "gap, NACKs, and XPU A goes back and resends in order.",
         watch="No LLR units at all: no sequence numbers, no ACK/NACK control blocks. Every repair is end to end, "
               "flagged as a RODL retransmission."),
]

# fabric names (sim/fabric.py) -> the viewer's path names
EP_MACS = {"N0.0": "A", "S0.0": "S1", "S0.1": "S7", "N1.0": "B"}
EP_DIRS = {"n0p0>s0": "a2s", "s0>n0p0": "s2a", "s0>n1p0": "s2b", "n1p0>s0": "b2s"}
EP_XPU = {0: "A", 1: "B"}
EP_WIRES = {v: k for k, v in EP_DIRS.items()}


def setup(sc):
    """PathSession arguments and the viewer's cfg block for a link scenario (shared with tools/live.py)."""
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
    cfg = {"kind": "link", "rate_gbps": hop1.rate_gbps, "frame": 1024, "sim_ns": sc.get("sim_ns"),
           "hops": [{"cable_m": h.cable_m, "prop_ns": round(h.prop_ns, 3), "down": [list(d) for d in h.down]}
                    for h in (hop1, hop2)],
           "llr": {"enabled": llr.enabled, "replay_timer_ns": llr.replay_timer_ns,
                   "replay_ct_max": llr.replay_ct_max, "ctlos_spacing": llr.ctlos_spacing},
           "credits": {"S1": sw.total_credits, "B": nic.total_credits}, "credit_size": sw.credit_size,
           "nic_gbps": nic.drain_gbps}
    kw = dict(hop1=hop1, hop2=hop2, llr=llr, sw=sw, nic=nic, hooks=hooks)
    return kw, cfg


def setup_endpoint(sc):
    """Fabric arguments and the viewer's cfg block for an endpoint scenario."""
    link = LinkCfg(**sc.get("link", {}))
    llr = LLRCfg(**sc.get("llr", {}))
    sw, nic = CBFCCfg(**sc.get("sw", {})), CBFCCfg(**sc.get("nic", {}))
    su = SUETCfg(**sc.get("suet", {}))
    wl = sc["wl"]
    senders = [k for k, v in EP_XPU.items() if v in wl.get("senders", ["A", "B"])]

    def hooks(f):
        for name, make in sc.get("corrupt", {}).items():
            f.wires[EP_WIRES[name]].corrupt_hook = make()
    cfg = {"kind": "endpoint", "rate_gbps": link.rate_gbps, "frame": None, "sim_ns": sc.get("sim_ns"),
           "hops": [{"cable_m": link.cable_m, "prop_ns": round(link.prop_ns, 3), "down": []} for _ in range(2)],
           "llr": {"enabled": llr.enabled, "replay_timer_ns": llr.replay_timer_ns,
                   "replay_ct_max": llr.replay_ct_max, "ctlos_spacing": llr.ctlos_spacing},
           "credits": {"S1": sw.total_credits, "B": nic.total_credits}, "credit_size": sw.credit_size,
           "nic_gbps": nic.drain_gbps,
           "suet": {"ack_mode": su.ack_mode, "retx": su.retx, "stack": su.stack, "max_pack": su.max_pack,
                    "max_payload": su.max_payload, "xpu_gbps": su.xpu_gbps, "tx_buf": su.tx_buf,
                    "ack_hold_ns": su.ack_hold_ns, "rto_ns": su.rto_ns, "window": su.window, "resp_cmd": su.resp_cmd},
           "wl": {"op": wl["op"], "bytes": wl["bytes"], "size": wl.get("size", 256), "senders": wl.get("senders", ["A", "B"])}}
    kw = dict(n=2, ports=1, link=link, llr=llr, nic=nic, sw=sw, suet=su, hooks=hooks,
              workload=AllToAll(2, bytes_per_peer=wl["bytes"], size=wl.get("size", 256), op=wl["op"], senders=senders))
    return kw, cfg


def relabel(events):
    """Fabric names -> path names, in place."""
    for e in events:
        if "mac" in e:
            e["mac"] = EP_MACS.get(e["mac"], e["mac"])
        if "dir" in e:
            e["dir"] = EP_DIRS.get(e["dir"], e["dir"])
        if "xpu" in e:
            e["xpu"] = EP_XPU[e["xpu"]]
            for k in ("dst", "src", "peer"):
                if k in e:
                    e[k] = EP_XPU[e[k]]
    return events


def down_of(cfg):
    return {i + 1: h["down"] for i, h in enumerate(cfg["hops"]) if h["down"]}


CAPTURES = Path(__file__).resolve().parent.parent / "pcaps" / "emu" / "path"


def run(sc):
    if sc.get("kind", "link") == "endpoint":
        return run_endpoint(sc)
    if sc.get("kind") == "captured":
        from tools.pcap2trace import convert
        return convert(CAPTURES / sc["pcap"], sc)
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


def run_endpoint(sc):
    kw, cfg = setup_endpoint(sc)
    tr = []
    f = Fabric(trace=tr, **kw)
    f.run(sc["sim_ns"], stop_when_done=False)
    r = f.result()
    relabel(tr)
    return {
        "id": sc["id"], "title": sc["title"], "summary": sc["summary"], "watch": sc["watch"],
        "cfg": cfg,
        "result": {"delivered": r.done, "lost": r.failed, "in_order": True,
                   "replayed": r.mac["nic"]["replayed"] + r.mac["sw"]["replayed"],
                   "done": r.done, "failed": r.failed, "retx": r.ep["retx_pkts"], "nacks": r.ep["nacks_tx"],
                   "pkts": r.ep["tx_pkts"], "acks": r.ep["acks_tx"], "eff": round(r.efficiency, 3),
                   "pack": round(r.pack_avg, 2), "total": f.workload.total},
        "events": tr,
        "notes": annotate(tr, {}, cfg),
    }


def build():
    return [run(sc) for sc in SCENARIOS]


def render(traces) -> str:
    body = json.dumps(traces, separators=(",", ":"))
    return ("// Generated by tools/make_traces.py from the simulator (sim/path.py, sim/fabric.py) and emulator captures (pcaps/emu/path). Do not edit.\n"
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

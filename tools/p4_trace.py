"""M6 packet-viewer scenario: what the P4 switch (p4/esun_switch.p4 in bmv2) did with each test frame.

Input is docs/experiments/p4-results.json, written by tools/run_m6.py in the lab: per frame the bytes sent (as
the fields the switch reads), bmv2's own log of that packet (parser states, table lookups, the program's log_msg
lines, egress port, dropped or sent) and what each XPU received. Nothing here is simulated; the drop reasons are
read back from the program's rules (p4/esun_switch.p4) because a direct `drop()` call is not a table hit and
bmv2's log does not name it.

Time is in "steps": each frame gets STEP steps, and walks the pipeline's stages in order.
"""
from __future__ import annotations

import json
from pathlib import Path

RESULTS = Path(__file__).resolve().parent.parent / "docs" / "experiments" / "p4-results.json"
STEP = 10                     # steps per frame
STAGES = ["frame in", "parser", "ingress", "queues", "egress", "deparser", "frame out"]
STAGE_STEPS = 1.25            # 7 stages x 1.25 = 8.75 steps, then a short pause before the next frame
MACC = 0x8808                 # MAC control ethertype (CC_Update)


def _short(name: str) -> str:
    return name.split(".")[-1]


def _msg(msgs, prefix):
    return next((m for m in msgs if m.startswith(prefix)), None)


def drop_reason(p: dict) -> str | None:
    b, x = p["bmv2"], p["in"]
    if not b["dropped"]:
        return None
    for t in b["tables"]:
        if not t["hit"] and _short(t["action"]) == "drop":
            return f"no entry in {_short(t['table'])}: the default action drops it (no flooding)"
    if x["kind"] == "ESUN" and x.get("ttl", 16) <= 1:
        return f"TTL {x['ttl']} would reach 0 at this hop: dropped before the DA lookup"
    if "ether_type=%d" % MACC in " ".join(b["msgs"]) or x["kind"].startswith("MAC control"):
        return "MAC control (ethertype 0x8808) is link-local: consumed, never forwarded"
    return "dropped (egress port 511)"


def frame(p: dict, why: dict) -> dict:
    b = p["bmv2"]
    res = _msg(b["msgs"], "ingress result")
    queue = int(res.rsplit("priority=", 1)[1]) if res else None
    ttl = _msg(b["msgs"], "esun ttl decremented")
    ecn = _msg(b["msgs"], "egress ecn marked")
    if ecn:
        ecn_txt = "ECN-capable and the queue is at the marking threshold: ECN set to CE (" + ecn.split(", ")[1] + ")"
    elif b["dropped"]:
        ecn_txt = None
    elif p["in"].get("ecn", 0) == 0 and "ecn" in p["in"]:
        ecn_txt = "not ECN-capable (ECN 0): never marked"
    elif "ecn" not in p["in"]:
        ecn_txt = "no ECN field the program reads (plain Ethernet / IP): untouched"
    else:
        ecn_txt = "queue below the marking threshold: not marked"
    return {
        "check": p["check"], "why": why.get(p["check"], ""), "src": p["src"], "port_in": b["port_in"],
        "in": p["in"], "out": p["out"], "states": b["states"], "headers": b["headers"],
        "tables": [{"table": _short(t["table"]), "key": {k.split(".")[-1]: v for k, v in t["key"].items()},
                    "hit": t["hit"], "action": _short(t["action"]), "params": t["params"]} for t in b["tables"]],
        "msgs": b["msgs"], "egress": b["egress_port"], "tx": b["tx_port"], "dropped": b["dropped"],
        "deparsed": b["deparsed"], "queue": queue, "ttl": ttl.rsplit(" ", 1)[1] if ttl else None,
        "ecn": ecn_txt, "ecn_marked": bool(ecn), "drop": drop_reason(p),
    }


def outcome(f: dict) -> str:
    if f["dropped"]:
        return "dropped: " + f["drop"]
    ports = ", ".join(f"XPU {k}" for k in f["out"]) or "nobody"
    bits = [f"queue {f['queue']}"] if f["queue"] is not None else []
    if f["ttl"] is not None:
        bits.append(f"TTL now {f['ttl']}")
    if f["ecn_marked"]:
        bits.append("ECN set to CE")
    return f"sent on port {f['tx']} to {ports}" + (" · " + " · ".join(bits) if bits else "")


def build(path: Path = RESULTS) -> dict:
    r = json.loads(Path(path).read_text())
    why = {c["check"]: c["why"] for c in r["checks"]}
    frames = [frame(p, why) for p in r["packets"]]
    notes = []
    for i, f in enumerate(frames):
        t0 = i * STEP
        notes.append({"t": t0, "at": "p4", "kind": "frame",
                      "text": f"Frame {i + 1}: {f['in']['kind']} from XPU {f['src']} on port {f['port_in']}. Check: {f['check']}."})
        if f["dropped"]:                    # decided in ingress
            notes.append({"t": round(t0 + 2 * STAGE_STEPS, 3), "at": "p4", "kind": "drop", "text": f"Ingress drops it: {f['drop']}."})
        else:                               # known once the frame is out (egress may have marked it)
            o = outcome(f)
            notes.append({"t": round(t0 + 6 * STAGE_STEPS, 3), "at": "p4", "kind": "ok", "text": o[0].upper() + o[1:] + "."})
    n = len(frames)
    fwd = sum(not f["dropped"] for f in frames)
    return {
        "id": "p4-pipeline", "title": "What the P4 switch did with each frame",
        "cfg": {"kind": "p4", "time_unit": "step", "sim_ns": n * STEP, "speed_mult": 0.5, "speed_default": 1,
                "no_flow": True, "step": STEP, "stage_steps": STAGE_STEPS, "stages": STAGES,
                "hops": [{"down": []}, {"down": []}]},
        "result": {"frames": n, "forwarded": fwd, "dropped": n - fwd, "pairing": r["pairing"],
                   "checks_ok": sum(c["ok"] for c in r["checks"]), "checks": len(r["checks"])},
        "events": [], "notes": notes,
        "extra": {"frames": frames,
                  "chips": ["bmv2 simple_switch 1.15.8", "p4/esun_switch.p4", f"{n} test frames from emu/p4check.py",
                            f"{r['pairing']['bmv2_packets']} bmv2 log records paired", f"{fwd} forwarded · {n - fwd} dropped",
                            f"{STEP} steps per frame"],
                  "intro": "Each test frame from the M6 checks walks the switch's pipeline as bmv2 logged it. "
                           "Press Play, or click a stage or a frame in the strip below."},
    }

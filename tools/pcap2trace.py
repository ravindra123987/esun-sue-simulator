"""Turn emulator captures (M4) into packet-viewer events: what actually crossed the wire, replayed on the
same path picture as the simulator's runs.

A path capture is two pcaps from one run of the M4 lab with two XPUs (tools/run_m4.py run --viewer):
link0.pcap is hop 1 (XPU A <-> switch port "1"), link1.pcap is hop 2 (switch port "7" <-> XPU B), each
taken on the switch side of the veth, so it holds both directions. The emulator's link-layer shim
(emu/shim.py, decision E1) puts the LLR sequence number, LLR_ACK/NACK/INIT/INIT_ECHO and CF_Update on
the wire, so a capture shows the link layer as well as the frames.

What the converter knows and what it infers:
  - frames, control units, their order and capture timestamps: as captured;
  - a frame's fate (bad = the shim's CRC-32 fails): as captured;
  - replays (a frame whose LLR sequence number, or with LLR off its exact bytes, was seen before on that
    direction): as captured;
  - what the receiving port did with each frame (accept / duplicate / out of order / bad): inferred from
    the LLR sequence numbers, by the rules of UEC §5.1.7;
  - SUE-T packets (PSN, packed count, ACKs, RODL retransmissions): decoded from the frames, the hidden
    PSN recovered from the UET CRC as the dissector does; what the destination's RODL did with each one
    (accept / duplicate / gap): inferred from the PSNs;
  - cable outages: inferred where a link that normally carries ACKs every few ms falls silent in both
    directions for longer than `GAP_MS`.
Nothing internal to a device (credits, replay buffers, timers, queues) is on the wire, so the viewer
draws captured runs without those blocks.

Times are milliseconds from the first captured unit; a backward step of the capture host's clock is undone
(`read`). A frame is drawn crossing its cable in `VIS_MS`
(the real crossing takes nanoseconds and is not in the capture).

    .venv/bin/python tools/pcap2trace.py <run-dir> [<run-dir> ...]      # prints a summary per run
"""

import hashlib
import sys
from pathlib import Path

from scapy.utils import RawPcapReader

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from emu import shim as S  # noqa: E402
from emu.endpoint import Endpoint  # noqa: E402
from sue import consts as C  # noqa: E402
from sue import crc as K  # noqa: E402
from sue.layers import UFH16Ack, UFH16RODL, is_ufh16  # noqa: E402

VIS_MS = 0.6               # how long a frame is drawn crossing a cable
SER_MS = 0.05              # and how long it is drawn leaving the port
GAP_MS = 60.0              # silence on a link (both directions) taken as the cable being down
TAIL_MS = 60.0             # kept after the last data frame
# capture direction by link and source MAC prefix (XPU side 02:a0, switch side 02:5f)
DIRS = {(0, b"\x02\xa0"): "a2s", (0, b"\x02\x5f"): "s2a", (1, b"\x02\x5f"): "s2b", (1, b"\x02\xa0"): "b2s"}
TX = {"a2s": "A", "s2a": "S1", "s2b": "S7", "b2s": "B"}
RX = {"a2s": "S1", "s2a": "A", "s2b": "B", "b2s": "S7"}
NAME = {"A": "XPU A", "S1": "switch port 1", "S7": "switch port 7", "B": "XPU B"}
XPU_OF = {0: "A", 1: "B"}


STEP_S = 0.001             # a timestamp this far behind the previous one is the VM's clock being stepped


def read(path):
    """(timestamp, bytes) in file order. If the capture host's clock was stepped backwards during the run
    (the Lima VM's time daemon does this), every later timestamp is shifted forward by the step, so the
    timeline stays monotonic; tcpdump writes records in arrival order, so file order is the true order."""
    out, shift, prev = [], 0.0, None
    for raw, meta in RawPcapReader(str(path)):
        ts = meta.sec + meta.usec / 1e6 + shift
        if prev is not None and ts < prev - STEP_S:
            shift += prev - ts
            ts = prev
        prev = ts
        out.append((ts, bytes(raw)))
    return out


def convert(run_dir, meta):
    run_dir = Path(run_dir)
    units = []
    for link in (0, 1):
        for ts, raw in read(run_dir / f"link{link}.pcap"):
            u = S.unwrap(raw)
            if u is None:
                continue
            units.append((ts, link, u))
    units.sort(key=lambda x: x[0])
    t0 = units[0][0]
    ms = lambda ts: round((ts - t0) * 1000, 4)  # noqa: E731

    events, notes = [], []
    fids, nfid = {}, 0
    seen_seq = {d: set() for d in TX}           # LLR seqs seen per direction since the last INIT
    seen_body = {d: set() for d in TX}          # LLR off: frames identified by their bytes
    expect = {d: None for d in TX}              # receiver's next LLR seq (None: not initialised yet)
    llr_on = any(not u.is_frame and u.mtype in (S.T_ACK, S.T_INIT) for _, _, u in units)
    last_unit = {0: None, 1: None}
    downs = {0: [], 1: []}
    in_replay = {d: False for d in TX}
    psn_exp = {}                                 # (src, dst) -> next PSN expected (CRC recovery and RODL inference)
    rodl_exp = {}                                # (src, dst) -> RODL receiver's expected PSN
    said = set()
    last_data = 0.0
    carried = {0: False, 1: False}               # a link has carried data (so a later INIT is a re-INIT)
    counts = {"frames": 0, "bad": 0, "replayed": 0, "llr_nacks": 0, "rodl_retx": 0, "rodl_nacks": 0, "cc_updates": 0}

    def note(t, at, kind, text):
        notes.append({"t": t, "at": at, "kind": kind, "text": text})

    def once(key):
        if key in said:
            return False
        said.add(key)
        return True

    for ts, link, u in units:
        t = ms(ts)
        d = DIRS.get((link, u.src[:2]))
        if d is None:
            continue
        # outages: a long silence on a link that was carrying traffic
        lu = last_unit[link]
        if lu is not None and t - lu > GAP_MS:
            downs[link].append([round(lu + 1, 3), round(t - 1, 3)])
            h = f"h{link + 1}"
            note(round(lu + 1, 3), h, "down", f"Nothing crosses hop {link + 1} in either direction for {t - lu:.0f} ms: "
                                             "the cable is down (inferred from the capture's silence).")
            note(round(t - 1, 3), h, "up", f"Hop {link + 1} carries frames again.")
        last_unit[link] = t
        if not u.is_frame:
            kind = S.TYPE_NAME[u.mtype]
            ev = {"ev": "ctlos", "dir": d, "kind": kind, "seq": u.seq, "cf": (u.cf or {}).get(0), "t1": t,
                  "arrive": round(t + VIS_MS, 4), "fate": "ok"}
            events.append(ev)
            if kind == "LLR_INIT":
                expect[d] = u.seq
                seen_seq[d] = set()
                if not carried[link]:                    # start-up: repeated every few ms until the peer answers
                    if once(("init", d)):
                        note(t, TX[d], "init", f"{NAME[TX[d]]} sends LLR_INIT {u.seq}: the start-up handshake, repeated "
                                              "until the other end answers.")
                elif once(("reinit", d, len(downs[link]))):
                    note(t, TX[d], "init", f"{NAME[TX[d]]} sends LLR_INIT {u.seq} again: after a FLUSH, the two ends "
                                          "agree on sequence numbers before any frame moves.")
            elif kind == "LLR_INIT_ECHO":
                if once(("echo", d, carried[link], len(downs[link]))):
                    note(t, TX[d], "init", f"{NAME[TX[d]]} echoes the INIT: the link is {'back ' if carried[link] else ''}in ADVANCE"
                                          f"{'' if carried[link] else ' and frames can flow'}.")
            elif kind == "LLR_NACK":
                counts["llr_nacks"] += 1
                peer = TX[{"s2a": "a2s", "a2s": "s2a", "s2b": "b2s", "b2s": "s2b"}[d]]
                note(t, TX[d], "nack", f"{NAME[TX[d]]} sends LLR NACK {u.seq}: {NAME[peer]} must replay everything after seq {u.seq}.")
            continue
        # a frame
        inner = u.inner
        cc = S.is_cc_update(inner)
        key = hashlib.blake2b(inner, digest_size=8).digest()
        if not cc and key not in fids:
            nfid += 1
            fids[key] = nfid
        fid = fids.get(key, 0)
        if llr_on:
            replay = u.seq in seen_seq[d]
            seen_seq[d].add(u.seq)
        else:
            replay = False                       # no LLR, no replay: transport resends show as RODL retransmissions
        fate = "ok" if u.crc_ok else "bad"
        events.append({"ev": "frame", "dir": d, "fid": fid, "seq": u.seq if llr_on else None,
                       "kind": "cc_update" if cc else "data", "size": len(inner), "replay": replay,
                       "t0": t, "t1": round(t + SER_MS, 4), "arrive": round(t + VIS_MS, 4), "fate": fate})
        counts["frames"] += not replay and not cc
        counts["replayed"] += replay
        counts["cc_updates"] += cc
        if replay and not in_replay[d]:
            note(t, TX[d], "replay", f"{NAME[TX[d]]} replays from LLR seq {u.seq}: the frames it already sent go again, "
                                     "in order (dashed).")
        in_replay[d] = replay
        # what the receiving port did (inferred from the LLR rules)
        if fate == "bad":
            res = "bad"
            counts["bad"] += 1
            note(round(t + VIS_MS, 4), RX[d], "bad", f"{'A CC_Update' if cc else f'Frame #{fid}'} arrives corrupted at {NAME[RX[d]]}: "
                                                     "its CRC fails, so it is discarded.")
        elif not llr_on:
            res = "accept"
        elif expect[d] is None or u.seq == expect[d]:
            res, expect[d] = "accept", (u.seq + 1) & 0xFFFFF
        elif S.seq_diff(u.seq, expect[d]) < 0:
            res = "dup"
        else:
            res = "ooo"
        events.append({"ev": "rx", "mac": RX[d], "fid": fid, "seq": u.seq, "kind": "cc_update" if cc else "data",
                       "res": res, "t": round(t + VIS_MS, 4)})
        if cc and once(("cc", d)):
            note(t, TX[d], "cc", f"{NAME[TX[d]]} sends a CC_Update: its credit counters, so {NAME[RX[d]]} can reclaim "
                                 "credits of frames that never arrived.")
        if cc or fate == "bad":
            continue
        last_data = t
        carried[link] = True
        # the SUE-T packet inside
        if not (is_ufh16(inner) and inner[12:14] == b"\xe7\x90"):
            continue
        ptype = inner[1] >> 3
        body, wire = inner[:-C.UET_CRC_LEN], int.from_bytes(inner[-C.UET_CRC_LEN:], C.CRC_BYTE_ORDER)
        origin = d in ("a2s", "b2s")                     # the packet's first hop: log it as sent
        final = d in ("s2b", "s2a")                      # its last hop: what the destination's RODL does
        if ptype in (C.PDS_TYPE_ACK, C.PDS_TYPE_NACK):
            h = UFH16Ack(body)
            src, dst = XPU_OF.get(h.src), XPU_OF.get(h.dst)
            nack = ptype == C.PDS_TYPE_NACK
            if origin and not replay:
                events.append({"ev": "pkt_tx", "t": t, "xpu": src, "fid": fid, "kind": "ack", "dst": dst, "tc": 1, "psn": -1,
                               "n": 0, "cack": h.cack_psn, "nack": h.ack_psn if nack else -1, "retx": False, "size": len(inner),
                               "port": 0, "pdus": [], "data": 0, "pay": 0})
                if nack:
                    counts["rodl_nacks"] += 1
                    note(t, src, "rnack", f"XPU {src} sends a RODL NACK: PSN {h.ack_psn} is missing, resend from there.")
            if final and res == "accept":
                events.append({"ev": "pkt_rx", "t": round(t + VIS_MS, 4), "xpu": dst, "fid": fid, "res": "ack", "src": src,
                               "cack": h.cack_psn, "nack": h.ack_psn if nack else -1})
            continue
        if ptype != C.PDS_TYPE_RODL:
            continue
        h = UFH16RODL(body)
        src, dst = XPU_OF.get(h.src), XPU_OF.get(h.dst)
        k = (h.src, h.dst)
        reg = K.crc32c(Endpoint._masked(body))
        if h.syn:
            psn = h.explicit_psn
        else:
            psn = Endpoint._find_psn(reg, wire, psn_exp.get(k, 0), h.retx) if k in psn_exp else None
        if psn is None:
            continue
        psn_exp[k] = max(psn_exp.get(k, 0), psn + 1)
        n = 0
        layer = h.payload
        while layer is not None and layer.name != "NoPayload" and hasattr(layer, "fields"):
            if hasattr(layer, "request_length"):
                n += 1
            layer = layer.payload if layer.payload else None
        if origin and not replay:
            events.append({"ev": "pkt_tx", "t": t, "xpu": src, "fid": fid, "kind": "req", "dst": dst, "tc": 0, "psn": psn,
                           "n": n, "cack": -1, "nack": -1, "retx": bool(h.retx), "size": len(inner), "port": 0,
                           "pdus": [], "data": 0, "pay": 256 * n})
            if h.retx:
                counts["rodl_retx"] += 1
                if once(("retx", src, psn // 64)):
                    note(t, src, "retx", f"XPU {src} resends PSN {psn} with the RODL retransmission flag set: the transport, "
                                         "not the link, is recovering this loss.")
            elif once(("first", src)):
                note(t, src, "pack", f"XPU {src} sends PSN {psn} with {n} store(s) packed: the first SUE-T packet of the run.")
        if final and res == "accept":                      # only frames the link layer passed up reach RODL
            exp = rodl_exp.get(k)
            if h.syn and exp is None:
                exp = psn
            res = "accept" if exp is None or psn == exp else ("dup" if psn < exp else "gap")
            if res == "accept":
                rodl_exp[k] = psn + 1
            ev = {"ev": "pkt_rx", "t": round(t + VIS_MS, 4), "xpu": dst, "fid": fid, "res": res, "src": src, "psn": psn,
                  "cack": -1, "nack": -1}
            if res == "gap":
                ev["expect"] = exp
                if once(("gap", dst, exp)):
                    note(round(t + VIS_MS, 4), dst, "gap", f"XPU {dst} receives PSN {psn} while it expects {exp}: a packet is "
                                                           "missing, so RODL drops this one (inferred from the PSNs).")
            events.append(ev)

    end = last_data + TAIL_MS                     # the run is over: drop the idle chatter after it
    tkey = lambda e: e.get("t0", e.get("t1", e.get("t", 0)))  # noqa: E731
    events = [e for e in events if tkey(e) <= end]
    notes = [n for n in notes if n["t"] <= end]
    dur = round(min(end, max(e.get("arrive", e.get("t", 0)) for e in events)) + 1, 3)
    events.sort(key=tkey)
    cfg = {"kind": "captured", "time_unit": "ms", "span_mult": 0.05, "rate_gbps": None, "frame": None, "sim_ns": dur,
           "hops": [{"cable_m": None, "prop_ns": VIS_MS, "down": downs[0]}, {"cable_m": None, "prop_ns": VIS_MS, "down": downs[1]}],
           "llr": {"enabled": llr_on, "replay_timer_ns": None, "replay_ct_max": None, "ctlos_spacing": None},
           "credits": {"S1": 1, "B": 1}, "credit_size": 64, "nic_gbps": None, "source": str(meta.get("source", ""))}
    notes.sort(key=lambda n: n["t"])
    return {"id": meta["id"], "title": meta["title"], "summary": meta["summary"], "watch": meta["watch"],
            "cfg": cfg, "result": counts, "events": events, "notes": notes}


def main(argv=None):
    for d in (argv or sys.argv[1:]):
        tr = convert(d, {"id": Path(d).name, "title": Path(d).name, "summary": "", "watch": ""})
        kinds = {}
        for n in tr["notes"]:
            kinds[n["kind"]] = kinds.get(n["kind"], 0) + 1
        print(Path(d).name, len(tr["events"]), "events", tr["result"], "notes", kinds, "dur", tr["cfg"]["sim_ns"], "ms",
              "downs", [h["down"] for h in tr["cfg"]["hops"]])


if __name__ == "__main__":
    main()

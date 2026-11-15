"""Event traces for the visualiser (docs/viz).

`run_link(..., trace=[])` records:

    frame    a frame put on a wire: dir, fid, seq, kind, size, replay, t0/t1 (first/last bit
             leaves), arrive (last bit reaches the peer), fate ok | bad | down
    ctlos    a control ordered set: dir, kind, seq, cf, t1, arrive, fate
    rx       what the receiving MAC did with a frame: accept | bad | dup | ooo
    replay   LLR entered REPLAY: start seq, n frames, cause nack | timer
    timer    LLR replay timer expired: action replay | flush
    flush    LLR gave up: seqs/fids thrown away
    cc       CC_Update found lost credits (negative = the "serious error" case)
    overflow a lossless frame did not fit the receive buffer
    deliver  a frame reached the client
    mac      a state snapshot of one MAC (only when something changed)

`annotate()` turns the events into short captions, naming A as the NIC and B as
the switch port it is cabled to (the viewer draws the link that way). Each one is derived from
what the simulator did, not written by hand.
"""


WHO = {"A": "NIC", "B": "Switch port"}


def annotate(events: list[dict], link_down: list | None = None) -> list[dict]:
    notes = []

    def note(t, kind, text):
        notes.append({"t": round(t, 3), "kind": kind, "text": text})

    for a, b in link_down or []:
        note(a, "down", "Link goes down: everything on the wire in either direction is lost.")
        note(b, "up", "Link is back up.")

    expected = None
    ooo_run = dup_run = False
    init_seen = echo_seen = stall_seen = delivered = False
    last_stall = False
    got = set()
    for e in events:
        ev = e["ev"]
        if ev == "rx" and e["mac"] == "B":
            if e["res"] == "accept":
                expected = None if e["seq"] is None else e["seq"] + 1
                ooo_run = dup_run = False
            elif e["res"] == "bad" and e["seq"] is None:
                note(e["t"], "bad", "Switch port: a frame fails the FCS check and is dropped. Without LLR nothing "
                                    "on this link will resend it.")
            elif e["res"] == "bad":
                note(e["t"], "bad", f"Switch port: seq {e['seq']} fails the FCS check and is discarded. It will NACK.")
            elif e["res"] == "ooo" and not ooo_run:
                ooo_run = True
                exp = f", still waiting for seq {expected}" if expected is not None else ""
                note(e["t"], "ooo", f"Switch port discards seq {e['seq']}: out of order{exp}. "
                                    "LLR keeps nothing out of order and sends no second NACK.")
            elif e["res"] == "dup" and not dup_run:
                dup_run = True
                note(e["t"], "dup", f"Switch port silently drops seq {e['seq']}: a duplicate of a frame it already has.")
        elif ev == "ctlos" and e["dir"] == "b2a" and e["kind"] == "LLR_NACK":
            lost = "" if e["fate"] == "ok" else " The NACK is lost on the wire."
            note(e["t"], "nack", f"Switch port sends LLR NACK {e['seq']}: replay everything after seq {e['seq']}.{lost}")
        elif ev == "replay" and e["mac"] == "A":
            why = "after the NACK" if e["cause"] == "nack" else "after the replay timer"
            note(e["t"], "replay", f"NIC enters REPLAY {why}: resends {e['n']} frame(s) from seq {e['start']} "
                                   "out of its replay buffer, without spending credits again.")
        elif ev == "timer" and e["mac"] == "A":
            if e["action"] == "flush":
                note(e["t"], "timer", f"The NIC's replay timer expires again and the retry count has reached "
                                      f"replay_ct_max ({e['replay_ct']}): LLR gives up.")
            else:
                note(e["t"], "timer", "The NIC's replay timer expires with no ACK progress, so it replays.")
        elif ev == "flush" and e["mac"] == "A":
            had = sum(1 for f in e["fids"] if f in got)
            extra = (f" The switch already had {had} of them; only their ACKs were lost." if had else "")
            note(e["t"], "flush", f"FLUSH: the NIC throws away {len(e['seqs'])} frame(s) "
                                  f"(seq {e['seqs'][0]}–{e['seqs'][-1]}).{extra} The rest are now the "
                                  "transport's problem." if e["seqs"] else "FLUSH: the replay buffer was already empty.")
        elif ev == "ctlos" and e["kind"] == "LLR_INIT" and not init_seen:
            init_seen = True
            note(e["t"], "init", f"The NIC sends LLR_INIT {e['seq']} to agree on sequence numbers again.")
        elif ev == "ctlos" and e["kind"] == "LLR_INIT_ECHO" and e["fate"] == "ok" and not echo_seen:
            echo_seen = True
            note(e["t"], "init", "The switch port echoes the INIT. When the echo arrives, the NIC goes back to ADVANCE.")
        elif ev == "cc":
            if e["lost"] > 0:
                note(e["t"], "cc", f"{WHO[e['mac']]}: a CC_Update shows {e['lost']} credits were spent on frames "
                                   "that never arrived. They go back to the sender in the next CF_Update.")
            else:
                note(e["t"], "cc", f"{WHO[e['mac']]}: CC_Update gives negative lost credits ({e['lost']}): "
                                   "the spec's \"serious error\".")
        elif ev == "overflow":
            note(e["t"], "overflow", f"{WHO[e['mac']]}: a lossless frame does not fit the ingress buffer and is dropped.")
        elif ev == "deliver":
            got.add(e["fid"])
        if ev == "deliver" and not delivered:
            delivered = True
            note(e["t"], "deliver", f"The first frame leaves the switch's egress port {e['lat']:.0f} ns after the NIC queued it.")
        elif ev == "mac" and e["mac"] == "A":
            if e["stalled"] and not last_stall and not stall_seen:
                stall_seen = True
                note(e["t"], "stall", f"The NIC is out of credits ({e['cr_used']} of {e['cl']} in use) "
                                      "and waits for a CF_Update from the switch.")
            last_stall = e["stalled"]
    notes.sort(key=lambda n: n["t"])
    return notes

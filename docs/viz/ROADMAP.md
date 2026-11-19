# Packet viewer roadmap

What the viewer at [docs/viz/](.) shows today, what each milestone adds to it, and the open action items. The rule from the start stays: every frame, block and caption on screen comes from a simulator trace (`sim/trace.py`, `tools/make_traces.py`), never from a scripted animation.

## Today (M2)

One path, XPU A → switch → XPU B, two 800G cables, one direction of data. Blocks: HBM send queue, credit gate, LLR TX, replay buffer; switch port 1 RX, ingress buffer, port 7 TX, second replay buffer; XPU B port RX, RX buffer, DMA, HBM. Control blocks (ACK, NACK, CF_Update, INIT) travel back on each cable. Simple and Detailed views, Recorded and Live sources, Events / Counters / Flow graph / Inspector dock, follow-a-frame, share links.

## M3: the endpoint (next)

The simulator now has the SUE-T endpoint (`sim/suet.py`), and its traces already carry the events the viewer needs: `pkt_tx` (packet with PSN, packed CMD_PDU ids, carried ACK state, port), `pkt_rx` (accept / dup / gap / ack), `rodl` (timeout, go-back, fatal) and `txn` (completion, latency). What is missing is the picture.

Design (a second picture, chosen per scenario; the M2 picture stays for the link-layer scenarios):

```
XPU A                              Switch (plane 0)                      XPU B
┌ SUE-T ───────────────┐           ┌──────────────────────┐            ┌ SUE-T ───────────────┐
│ XPU cmd interface    │  hop 1    │ port 0 ⇄ VOQ ⇄ port 1│   hop 2    │ RODL RX: expect PSN  │
│ queues per {dst,TC}  │ ───────▶  │ ingress buffers both │ ─────────▶ │ ACK state, held ACKs │
│ packer: PSN n ×k     │ ◀───────  │ directions           │ ◀───────── │ XPU: execute, respond│
│ RODL TX: window, RTO │  frames   └──────────────────────┘   frames   │ queues per {dst,TC}  │
│ NIC port (M2 blocks) │  both ways                                     │ NIC port (M2 blocks) │
└──────────────────────┘                                                └──────────────────────┘
```

- Frames in **both directions** on each cable: requests one way, ACK packets and response commands the other, labelled `PSN 7 ×8` (packet, PSN, packed count) or `ACK 7`.
- Transactions, not frames, are what the user follows: click a `#txn` to see it queued, packed into a PSN, sent, accepted, executed, acknowledged, completed, with the latency breakdown.
- Scenarios (from a two-XPU `Fabric`): stores with operational ACKs; the same with delivery ACKs (see the response commands); loads (data in the ACK); a lost packet with LLR off (NACK, Go-Back-N); SUE-lite (PDC closed, `syn` re-establishes); low vs high XPU rate (packing appears).
- Counters tab: packets, CMD_PDUs per packet, wire efficiency so far, PSN / cack per PDC, retransmissions. Inspector: packet contents (CMD_PDU ids, sizes, carried ACK state), PDC state.
- Live mode: the same fault buttons plus "XPU rate" and "ACK mode" in the custom-run form.

Action items:

- [ ] `tools/make_traces.py`: a `kind: "endpoint"` scenario family built on `sim.fabric.Fabric(n=2)`; map MAC names N0.0 / S0.0 / S0.1 / N1.0 to the viewer's A / S1 / S7 / B and wires to a2s / s2a / s2b / b2s.
- [ ] `sim/trace.py`: captions for `pkt_tx` / `pkt_rx` / `rodl` / `txn` ("XPU A packs 8 stores into PSN 3", "XPU B: PSN 4 arrived before 3, NACK", "XPU A goes back to PSN 3: 5 packets resent", "store #41 complete after 612 ns").
- [ ] `docs/viz/js/data.js`: ingest the four event kinds; frames keyed by direction including s2a / b2s; `txnHistory(d, id)`.
- [ ] `docs/viz/js/render.js`: `drawEndpoint` (new picture) and reverse-direction frames in `drawCable` and the flow graph.
- [ ] `docs/viz/js/app.js`: pick the picture per scenario kind; Counters and Inspector rows for endpoint scenarios; sidebar group "SUE-T endpoint".
- [ ] `tools/live.py`: endpoint sessions (`Fabric` instead of `PathSession`), `/live/cmd` for XPU rate and faults per hop, custom-run limits for `SUETCfg`.
- [ ] Legend and Help: packets vs frames vs transactions, PSN vs LLR seq.

## M4: emulator

The emulator produces pcaps, not traces. Two options were on the table: (a) a `tools/pcap2trace.py` that turns a capture into viewer events, so a real run replays in the same viewer; (b) leave pcaps to Wireshark and keep the viewer for the simulator.

- [x] Decided: (a), because the emulator's captures carry more than a real NIC's would. The link-layer shim (`emu/shim.py`, decision E1 in [docs/experiments/emulator.md](../experiments/emulator.md)) puts the LLR sequence number, LLR_ACK/NACK/INIT and CF_Update on the wire, and `emu/analyze.py` already walks a capture unit by unit; so a capture holds every frame and control block the M2 picture draws, with real timestamps.
- [ ] `tools/pcap2trace.py`: one capture per link (both directions) → `frame` events with `t0 = t1 = timestamp` (no serialisation time), `ctlos` events from shim units, `rx` verdicts from the shim CRC and sequence (accept / dup / ooo / bad), `pkt_tx` / `pkt_rx` from the decoded UFH_16 frames. No internal state (no replay buffers, credits or timers): a "captured" picture mode that draws only what was on the wire and greys out the internal blocks.
- [ ] Time axis in milliseconds for captured scenarios (the simulator's is nanoseconds).
- [ ] Scenario entries for `pcaps/emu/*.pcap` under a "Captured (M4)" group in the sidebar.

## M5: planes and the comparison

The simulator side exists now (`sim/planes.py`, `tools/run_m5.py`); its traces carry `rodl` events with `what` = `move` (failover), `bad` and `restore` (spray), `timeout`, `fatal`, and `sw_drop` from a switch discarding frames for a dead port. What is missing is the picture.

- [ ] N XPUs × P planes picture: a plane strip per switch, one row per XPU; a plane failure dims a strip, and the reaction (LLR FLUSH → RODL, or nothing in SUE-T 1.0; MRC demotion; MetaRoCE pair move) shows as traffic moving or dying. Input: a `make_traces.py` family built on `sim.planes.build(design, scenario, trace=[])`.
- [ ] Side-by-side mode: the same fault in SUE-T, MRC and MetaRoCE traces, one timeline. This is the picture for `docs/where-should-retry-live.md`.
- [ ] Load-balancing scenario from T5: per-group balancing across unequal planes, reorder → NACK storm.

## M6 / M7

- [ ] M6: a "what the switch parsed" overlay from bmv2 logs (ESUN header fields, TC → queue). Low priority. The switch now exists (p4/esun_switch.p4, docs/p4-switch.md); bmv2's `--log-console` prints the parsed headers and table hits per packet, which is the input this needs.
- [ ] M7: UALink flits are a different picture (flit-level, no packets); start a new renderer rather than stretching this one.

## General

- [ ] A JS test harness (the CDP script in the session scratchpad is the only interaction test today); at least: every scenario loads, Play reaches the end, the inspector opens for every block key.
- [ ] Touch support for the picture (tap to inspect) and a narrower phone layout for the dock.
- [ ] Export the current picture as PNG (for the write-ups).

# Packet viewer roadmap

What the viewer at [docs/viz/](.) shows today, what each milestone adds to it, and the open action items. The rule from the start stays: every frame, block and caption on screen comes from a simulator trace (`sim/trace.py`, `tools/make_traces.py`), never from a scripted animation.

## Today (M2)

One path, XPU A → switch → XPU B, two 800G cables, one direction of data. Blocks: HBM send queue, credit gate, LLR TX, replay buffer; switch port 1 RX, ingress buffer, port 7 TX, second replay buffer; XPU B port RX, RX buffer, DMA, HBM. Control blocks (ACK, NACK, CF_Update, INIT) travel back on each cable. Simple and Detailed views, Recorded and Live sources, Events / Counters / Flow graph / Inspector dock, follow-a-frame, share links.

## M3: the endpoint (done)

Seven SUE-T endpoint scenarios run on the path picture: XPU A's HBM block becomes the SUE-T transmit queue, XPU B's the receive side, packets are labelled by PSN and how many transactions they pack (`PSN 7 ×8`), ACKs and response commands travel back on each cable's lower lane, and a click on a `#transaction` follows it from the queue into a packet, across both hops and back as an ACK.

- [x] `tools/make_traces.py`: a `kind: "endpoint"` scenario family on `sim.fabric.Fabric(n=2)`, relabelled to A / S1 / S7 / B and a2s / s2a / s2b / b2s.
- [x] `sim/trace.py`: captions for `txn_in` / `pkt_tx` / `pkt_rx` / `rodl` / `txn`.
- [x] `docs/viz/js/data.js`: the four event kinds, frames in all four directions, `epState`, `txnHistory`.
- [x] `docs/viz/js/render.js`: reverse-direction packets on the cables and in the flow graph, the SUE-T blocks.
- [x] `docs/viz/js/app.js`: sidebar group, Counters and Inspector rows, transaction selection and share links.
- [x] `tools/live.py`: endpoint sessions (`EndpointLive`, the fabric relabelled live), commands for corrupting the next request packet, losing a NACK, cutting either cable, XPU B's drain rate and XPU A's issue rate, and custom runs with XPU A's rate and SUE-lite. Long live runs fold old packets into running totals (`pruneEp`) so the counters stay right.
- [x] Legend and Help: packets vs frames vs transactions, PSN vs LLR seq.
- [x] Decided: no separate endpoint picture. The design sketch above drew one, but the path picture already has every block the endpoint needs, and keeping one picture lets the endpoint scenarios be compared with the link-layer ones block by block (the same bit error with LLR on, and with LLR off and RODL repairing it).

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

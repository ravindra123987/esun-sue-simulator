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

## M4: emulator (done)

Captured runs replay in the same viewer, under "Captured on the wire (M4)". `tools/run_m4.py run --viewer` records four two-XPU runs in the lab (clean; bit errors on hop 2 with LLR; a hop-1 outage long enough to FLUSH; bit errors with LLR off), both links captured; `tools/pcap2trace.py` turns them into viewer events and `tools/make_traces.py` builds them into `traces.js` from the committed captures in `pcaps/emu/path/`.

- [x] Decided (a): the emulator's link-layer shim (decision E1) puts LLR sequence numbers, LLR_ACK/NACK/INIT and CF_Update on the wire, so a capture holds every frame and control block the link-layer picture draws, with real timestamps.
- [x] `tools/pcap2trace.py`: frames with their fate and replays, control units, receive verdicts inferred from the LLR rules, SUE-T packets with PSNs recovered from the UET CRC and RODL's verdicts inferred from them, outages inferred from silence, captions. A backward step of the VM's clock during a capture is undone.
- [x] A "captured" picture: the same three devices and two cables, each block showing only what crossed the wire at that point (frames, replays, CRC failures, LLR units, verdicts, decoded PSNs); the switch's internals are drawn as not visible.
- [x] Time in milliseconds for captured runs (every time label, the speed and the flow-graph window follow the scenario's unit); a frame is drawn crossing its cable in 0.6 ms, said on the cable.
- [x] Scenario entries in the sidebar, Counters per hop, Inspector rows for every capture block.
- Found on the way: tcpdump buffered whole blocks of the capture ring, so a short run could end before its frames reached the file. The lab now captures with `--immediate-mode`, and the M4 tables and samples were regenerated (docs/experiments/emulator.md).

## M5: planes and the comparison (done)

Six scenarios under "Planes and recovery (M5)", one per fault: plane 1 dies, flaps, one remote link dies, plane 1 gets bit errors, plane 1 is slow (small switch buffers), and spraying over two planes of unequal delay in order or out of order (M3's T5). `tools/planes_trace.py` runs each design on the 4 x 4 fabric and reduces it to 1 µs bins (cable use per direction, every port's LLR state, stores completed and failed, the port each XPU uses towards each peer) plus the recovery events, with captions per design; `docs/viz/js/planes.js` draws them.

- [x] Side-by-side picture (the default): one row per design under the same fault, with its mechanism, a status pill, a 4 x 4 XPU x plane grid of cable use now (crossed out when dead, outlined amber or red when LLR is replaying or has flushed), a completions-per-µs sparkline over the run with the playhead, and its counters. This is the picture for `docs/where-should-retry-live.md`.
- [x] One design's fabric: click a row (or open `#planes-<fault>/<design>`): four XPUs and four switches with all 32 cable directions drawn by use and state, the port each XPU uses towards each peer or the planes it has marked bad, a sparkline, counters and the latest recovery events. Every XPU, switch and design opens in the Inspector; Counters show every design.
- [x] Load-balancing scenario from T5: per-packet spraying over unequal planes, in order (NACK and Go-Back-N storms) against out of order with SACK.
- Found on the way: in the spray designs, a dead plane silences the whole fabric for most of a transport timer, because every PDC holds a hole and its window is a PSN span from it. The write-up said the other planes "never stopped"; corrected.

## M6 (done) / M7

- [x] M6: "what the switch did with each frame", from bmv2's own log. `tools/run_m6.py` runs the frame checks with `--log-console --log-level debug`; the program logs its parsed fields, the TTL rewrite, the ingress result and ECN marking (`log_msg`); `emu/p4check.parse_bmv2_log` turns the log into one record per packet and pairs it with the frame sent and what each XPU received (14 of 14). `tools/p4_trace.py` makes the scenario; `docs/viz/js/p4view.js` draws the pipeline (frame in, parser, ingress tables, queues, egress ECN, deparser, frame out per XPU with rewritten fields marked) and a strip of all frames to jump between.
  - Decided: a pipeline picture of its own, not an overlay on the path picture. The path picture is about time on cables; what the switch did to one frame is about stages and fields, and the checks send one frame at a time.
  - Found while building it: the "unknown DA not flooded" check sent a zero-padded ESUN frame, whose TTL of 0 dropped it before the DA table was looked up. It now sends TTL 15 and also checks the no-route counter.
- [ ] M7: UALink flits are a different picture (flit-level, no packets); start a new renderer rather than stretching this one.

## General

- [ ] A JS test harness (the CDP script in the session scratchpad is the only interaction test today); at least: every scenario loads, Play reaches the end, the inspector opens for every block key.
- [ ] Touch support for the picture (tap to inspect) and a narrower phone layout for the dock.
- [ ] Export the current picture as PNG (for the write-ups).

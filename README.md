# esun-sue-simulator

A learning project for Ethernet scale-up networking: **SUE-T** (endpoint transport), **ESUN** (L2 framing), and the **UEC link layer** under them (LLR, CBFC, UET CRC). It builds the protocols in a discrete-event simulator for timing and a netns emulator for packets and failures, then compares hop-by-hop recovery with the end-to-end recovery of [srv6-mrc-emulator](https://github.com/segmentrouting/srv6-mrc-emulator) and the MetaRoCE simulator.

> **Question this project answers:** where should the retry live, at the link (LLR + CBFC) or end to end (MRC, MetaRoCE)?

## Status

| Milestone | What | State |
|---|---|---|
| M0 | Read the specs, build the delta table | draft done: [docs/delta-table.md](docs/delta-table.md) |
| M1 | Scapy layers, Wireshark dissector, golden pcaps | first cut: [sue/](sue/), [wireshark/](wireshark/), [pcaps/golden/](pcaps/golden/) |
| M1b | Upstream Wireshark support for UEC 1.1 (RODL, Unified Local, UFH, CC_Update) | dissector polished for porting: [wireshark/UPSTREAM.md](wireshark/UPSTREAM.md); issue drafted, not posted |
| M2 | LLR + CBFC link simulator | first cut (one link, plus a two-hop path through a switch): [docs/experiments/llr-cbfc.md](docs/experiments/llr-cbfc.md); packet viewer: [live](https://ravindra123987.github.io/esun-sue-simulator/viz/), [docs/viz/](docs/viz/) |
| M3 | SUE-T endpoint in the simulator | first cut: queues, packing, RODL (Go-Back-N or SUE-lite), both ACK modes, ports, all-to-all and ring all-reduce on an N-XPU fabric: [docs/experiments/suet-endpoint.md](docs/experiments/suet-endpoint.md) |
| M4 | netns emulator with a user-space switch | first cut: netns lab, user-space switch with LLR + CBFC per port, SUE-T endpoints on real UFH_16 frames, nine fault scenarios checked against the simulator, captures the dissector decodes: [docs/experiments/emulator.md](docs/experiments/emulator.md) |
| M5 | Multi-plane, three-way comparison | done: five recovery designs (SUE-T 1.0, SUE-T + failover, MetaRoCE-style, MRC-style, MRC + LLR) under six plane faults, a bit-error sweep and a lossy fabric with trimming in the simulator, and the plane faults on real frames in the four-plane emulator: [docs/where-should-retry-live.md](docs/where-should-retry-live.md) |
| M6 | P4/bmv2 switch | first cut: a v1model switch for UFH_16 and ESUN (forwarding, TTL, TC to queue, ECN), 13 frame checks and SUE-T traffic through bmv2 in the lab, and a SAI mapping including the UEC LLR/CBFC additions: [docs/p4-switch.md](docs/p4-switch.md) |
| M7 | UALoE, then UALink | later |

The full plan is in [plan.md](plan.md).

## Layout

```
plan.md         milestones, design principles, open questions
specs/          reference PDFs (git-ignored) + README with sources and how they relate
docs/           delta table, findings (m1-decisions.md: choices the specs leave open), experiments
docs/viz/       packet viewer app: index.html + app.css + js/{data,render,app}.js, generated traces.js; live via tools/live.py; ROADMAP.md = what each milestone adds
sue/            Scapy layers (UFH_16, RODL, Unified Local SES, ESUN), UET CRC, frame builders
wireshark/      sue.lua dissector (UFH_16, RODL, SES, ESUN, UET CRC; the emulator's LLR shim, CF_Update, CC_Update)
pcaps/golden/   reference captures, one packet type each, + golden.json expectations
pcaps/emu/      trimmed captures from the emulator (LLR + CBFC on the wire, a corrupted link, an outage)
sim/            discrete-event model: LLR (UEC §5.1), CBFC (§5.2), their interaction (§5.2.9); link.py = one link,
                path.py = XPU A → switch → XPU B (two hops); trace.py records events and writes captions;
                suet.py = SUE-T endpoint (queues, packing, RODL, ACK modes, ports), fabric.py = N XPUs × P planes with
                VOQ switches, workloads.py = all-to-all and ring all-reduce, wire.py = header byte accounting + RoCEv2 baseline,
                planes.py = the M5 designs and plane faults (suet.py: path pin/failover/spray, RODL or out-of-order with SACK)
p4/             esun_switch.p4 (v1model) and build/esun_switch.json, the compiled program bmv2 loads
emu/            netns emulator: shim.py (what the link layer looks like on a veth), port.py (LLR + CBFC link end in real time),
                switch.py (user-space switch, VOQ), endpoint.py (SUE-T endpoint process), lab.py (namespaces, veths, tcpdump,
                faults, a bmv2 switch mode), analyze.py (pcap counts), p4check.py (frame checks of the P4 switch)
tools/          make_golden.py, run_m2.py / run_m3.py (experiments + plots), run_m4.py (emulator scenarios, run in the VM / report
                on the Mac), run_m5.py (plane faults x recovery designs, bit-error sweep, lossy fabric), run_m6.py (P4 switch in bmv2, VM), make_traces.py (viewer scenarios), live.py (live viewer server), fetch_vectors.sh (third-party test vectors, not committed)
tests/          layer/CRC tests, tshark-based dissector tests, simulator tests, emulator tests over an in-memory wire
```


## Quick start

```
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/python -m pytest                 # dissector tests need tshark; skipped otherwise
.venv/bin/python tools/make_golden.py      # regenerate pcaps/golden/
.venv/bin/pip install -e '.[sim]' && .venv/bin/python tools/run_m2.py   # M2 experiments (~5 s)
.venv/bin/python tools/run_m3.py           # M3 experiments (~20 s)
.venv/bin/python tools/run_m5.py           # M5: where should the retry live (~10 min)
tshark -X lua_script:wireshark/sue.lua -r pcaps/golden/09-ufh16-conversation.pcap
tshark -X lua_script:wireshark/sue.lua -r pcaps/emu/ber-llr-link1.pcap    # LLR, CBFC and SUE-T frames from the emulator
sudo python3 -m emu.lab --n 4 --out /tmp/emu  # M4 emulator, Linux root only; see docs/experiments/emulator.md for the VM recipe
.venv/bin/python tools/make_traces.py      # regenerate docs/viz/traces.js, then open docs/viz/index.html
python3 tools/live.py                     # live packet viewer at http://127.0.0.1:8765/ (standard library only)
```

## Packet viewer

[docs/viz/index.html](docs/viz/index.html) replays what the two-hop simulator (`sim/path.py`) actually did on the path **XPU A → switch → XPU B**. That is three devices and two 800G cables. Each cable end runs its own LLR and CBFC, so the switch is the receiver on hop 1 (port 1) and the sender on hop 2 (port 7):

- **XPU A**: an HBM send queue, then a NIC with the CBFC credit gate, LLR transmit and its replay buffer.
- **Switch**: port 1 checks the FCS and runs LLR receive, then the frame waits in the lossless ingress buffer whose size is XPU A's credit pool. Port 7 takes it out when its own LLR window and XPU B's credits allow, keeps it in a second replay buffer, and sends it on.
- **XPU B**: the NIC checks the frame, buffers it, and DMA writes it into HBM at a set rate.

It is laid out as a tool, not a page: the picture stays on screen, with a player-style transport and an event timeline under it; a sidebar lists the nine scenarios and describes the selected one; a resizable dock below holds **Events** (filterable by device or problems), **Counters** (per path and per hop), the **Flow graph** (time runs down, one column per cable end) and the **Inspector**. Click any block for its full state, or click a frame anywhere (on a cable, in a buffer, or a `#12` in a caption) to follow it: it is highlighted wherever it appears and the Inspector lists its whole journey with times. **Share moment** copies a link to the current scenario, view and time. Every caption comes from `sim/trace.py`. Nine link-layer scenarios: a clean path, a bit error on hop 1 and on hop 2 (the switch repairs hop 2 by itself), a lost NACK, a slow XPU B whose backpressure moves back one hop at a time, a credit pool too small for hop 1's loop, a short outage that LLR absorbs, a long outage that ends in FLUSH, and a bit error with LLR off. Switch pipeline latency is not modelled (0 ns). It is published at **https://ravindra123987.github.io/esun-sue-simulator/viz/** (GitHub Pages, serving `docs/`), or open the file locally; it needs only `traces.js` next to it.

**Simple** view shows each block's essential state; **Detailed** adds LLR sequence numbers, timers and ACK state. **Recorded** replays `traces.js`; **Live** drives the page from a simulator running on your machine. Live needs only Python 3.11+ and a clone (no venv):

```
python3 tools/live.py      # then open http://127.0.0.1:8765/  (--port N to change it)
```

In live mode the page asks the simulator to advance a few nanoseconds ahead of what it shows and draws the events it gets back. The sidebar gains fault injection per hop (corrupt the next frame, lose the next NACK, cut the cable), XPU B's HBM write rate, and a custom-run form (BER and cable length per hop, both buffers, HBM rate, LLR timer and retries, LLR on/off), which the server validates and clamps. Live mode is local only (it listens on 127.0.0.1); the published page offers Recorded.

The **SUE-T endpoint** group (M3) runs two SUE-T instances (`sim/suet.py`, `sim/fabric.py`) on the same picture: XPU A's HBM block becomes the transmit queue, packets are labelled by PSN and how many transactions they pack (`PSN 7 ×8`), ACK packets and delivery-mode response commands travel back on each cable's lower lane, and a click on a `#transaction` follows it from the queue into a packet, across the fabric and back as an ACK. Seven scenarios: packed stores with operational ACKs, the same with delivery ACKs, loads with the data in the ACK, traffic both ways (ACKs ride for free), RODL Go-Back-N with LLR off, SUE-lite closing the PDC, and a slow XPU that never packs. The Counters tab shows packets, transactions per packet and wire efficiency so far. Live mode covers the link-layer scenarios only for now; [docs/viz/ROADMAP.md](docs/viz/ROADMAP.md) tracks what each milestone adds.

To add a scenario, add an entry to `SCENARIOS` in `tools/make_traces.py` (per-hop cable settings, LLR, switch and XPU B buffers, plus optional corruption hooks per wire) and rerun it. `tests/test_trace.py` fails if `traces.js` is out of date.

## Specs

Public specs only. The PDFs are not committed; [specs/README.md](specs/README.md) lists where to download each one.

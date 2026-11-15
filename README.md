# esun-sue-simulator

A learning project for Ethernet scale-up networking: **SUE-T** (endpoint transport), **ESUN** (L2 framing), and the **UEC link layer** under them (LLR, CBFC, UET CRC). It builds the protocols in a discrete-event simulator for timing and a netns emulator for packets and failures, then compares hop-by-hop recovery with the end-to-end recovery of [srv6-mrc-emulator](https://github.com/segmentrouting/srv6-mrc-emulator) and the MetaRoCE simulator.

> **Question this project answers:** where should the retry live, at the link (LLR + CBFC) or end to end (MRC, MetaRoCE)?

## Status

| Milestone | What | State |
|---|---|---|
| M0 | Read the specs, build the delta table | draft done: [docs/delta-table.md](docs/delta-table.md) |
| M1 | Scapy layers, Wireshark dissector, golden pcaps | first cut: [sue/](sue/), [wireshark/](wireshark/), [pcaps/golden/](pcaps/golden/) |
| M1b | Upstream Wireshark support for UEC 1.1 (RODL, Unified Local, UFH, CC_Update) | dissector polished for porting: [wireshark/UPSTREAM.md](wireshark/UPSTREAM.md); issue drafted, not posted |
| M2 | LLR + CBFC link simulator | first cut (one link): [docs/experiments/llr-cbfc.md](docs/experiments/llr-cbfc.md); packet viewer: [live](https://ravindra123987.github.io/esun-sue-simulator/viz/), [docs/viz/](docs/viz/) |
| M3 | SUE-T endpoint in the simulator | not started |
| M4 | netns emulator with a user-space switch | not started |
| M5 | Multi-plane, three-way comparison | not started |
| M6 | P4/bmv2 switch | not started |
| M7 | UALoE, then UALink | later |

The full plan is in [plan.md](plan.md).

## Layout

```
plan.md         milestones, design principles, open questions
specs/          reference PDFs (git-ignored) + README with sources and how they relate
docs/           delta table, findings (m1-decisions.md: choices the specs leave open), experiments
docs/viz/       packet viewer: replays simulator traces (index.html + generated traces.js), or live via tools/live.py
sue/            Scapy layers (UFH_16, RODL, Unified Local SES, ESUN), UET CRC, frame builders
wireshark/      sue.lua dissector (UFH_16, RODL, SES, ESUN, UET CRC)
pcaps/golden/   reference captures, one packet type each, + golden.json expectations
sim/            discrete-event link model: LLR (UEC §5.1), CBFC (§5.2), their interaction (§5.2.9); trace.py records events
tools/          make_golden.py, run_m2.py (M2 experiments + plots), make_traces.py (viewer scenarios), live.py (live viewer server), fetch_vectors.sh (third-party test vectors, not committed)
tests/          layer/CRC tests and tshark-based dissector tests
```

`emu/` and `p4/` arrive with M4 and M6.

## Quick start

```
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/python -m pytest                 # dissector tests need tshark; skipped otherwise
.venv/bin/python tools/make_golden.py      # regenerate pcaps/golden/
.venv/bin/pip install -e '.[sim]' && .venv/bin/python tools/run_m2.py   # M2 experiments (~5 s)
tshark -X lua_script:wireshark/sue.lua -r pcaps/golden/09-ufh16-conversation.pcap
.venv/bin/python tools/make_traces.py      # regenerate docs/viz/traces.js, then open docs/viz/index.html
.venv/bin/python tools/live.py            # live packet viewer at http://127.0.0.1:8765/
```

## Packet viewer

[docs/viz/index.html](docs/viz/index.html) replays what the link simulator actually did, drawn as one scale-up hop: XPU A (HBM send queue and on-die SUE NIC with its CBFC credit gate, LLR transmit, replay buffer and MAC/PHY) cabled to port 1 of an ESUN switch (FCS check and LLR receive, lossless ingress buffer, pipeline, egress port 7). Seven scenarios: a clean link, a bit error, a bit error with a lost NACK, a credit pool too small for the loop, a short outage that LLR absorbs, a long outage that ends in FLUSH, and the same bit error with LLR off. Frames on the cable are drawn to scale, a flow graph shows the exchange over time, and captions from `sim/trace.py` explain each event. The switch pipeline latency and the second hop are drawn but not modelled yet. It is published at **https://ravindra123987.github.io/esun-sue-simulator/viz/** (GitHub Pages, serving `docs/`), or open the file locally; it needs only `traces.js` next to it.

It has two views: **Simple** (the NIC, the cable and the switch, with only the state that matters) and **Detailed** (every block inside the NIC and the switch, plus a flow graph). It also has two sources: **Recorded** replays `traces.js`, and **Live** drives the page from a simulator running on your machine:

```
.venv/bin/python tools/live.py      # then open http://127.0.0.1:8765/
```

In live mode the page asks the simulator to advance a few nanoseconds ahead of what it shows and draws the events it gets back. Buttons act on the running simulation: corrupt the next frame, lose the next NACK, cut the link, change the switch's egress rate. Live mode is local only; the published page offers Recorded.

To add a scenario, add an entry to `SCENARIOS` in `tools/make_traces.py` (link, LLR and CBFC settings, plus optional corruption hooks) and rerun it. `tests/test_trace.py` fails if `traces.js` is out of date.

## Specs

Public specs only. The PDFs are not committed; [specs/README.md](specs/README.md) lists where to download each one.

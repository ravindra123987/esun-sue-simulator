# esun-sue-simulator

A learning project for Ethernet scale-up networking: **SUE-T** (endpoint transport), **ESUN** (L2 framing), and the **UEC link layer** under them (LLR, CBFC, UET CRC). It builds the protocols in a discrete-event simulator for timing and a netns emulator for packets and failures, then compares hop-by-hop recovery with the end-to-end recovery of [srv6-mrc-emulator](https://github.com/segmentrouting/srv6-mrc-emulator) and the MetaRoCE simulator.

> **Question this project answers:** where should the retry live, at the link (LLR + CBFC) or end to end (MRC, MetaRoCE)?

## Status

| Milestone | What | State |
|---|---|---|
| M0 | Read the specs, build the delta table | draft done: [docs/delta-table.md](docs/delta-table.md) |
| M1 | Scapy layers, Wireshark dissector, golden pcaps | first cut: [sue/](sue/), [wireshark/](wireshark/), [pcaps/golden/](pcaps/golden/) |
| M1b | Upstream Wireshark support for UEC 1.1 (RODL, Unified Local, UFH, CC_Update) | dissector polished for porting: [wireshark/UPSTREAM.md](wireshark/UPSTREAM.md); issue drafted, not posted |
| M2 | LLR + CBFC link simulator | not started |
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
docs/           delta table, findings (m1-decisions.md: choices the specs leave open)
sue/            Scapy layers (UFH_16, RODL, Unified Local SES, ESUN), UET CRC, frame builders
wireshark/      sue.lua dissector (UFH_16, RODL, SES, ESUN, UET CRC)
pcaps/golden/   reference captures, one packet type each, + golden.json expectations
tools/          make_golden.py, fetch_vectors.sh (third-party test vectors, not committed)
tests/          layer/CRC tests and tshark-based dissector tests
```

`sim/`, `emu/` and `p4/` arrive with M2–M6.

## Quick start

```
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/python -m pytest                 # dissector tests need tshark; skipped otherwise
.venv/bin/python tools/make_golden.py      # regenerate pcaps/golden/
tshark -X lua_script:wireshark/sue.lua -r pcaps/golden/09-ufh16-conversation.pcap
```

## Specs

Public specs only. The PDFs are not committed; [specs/README.md](specs/README.md) lists where to download each one.

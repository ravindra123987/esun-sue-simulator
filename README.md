# esun-sue-simulator

A learning project for Ethernet scale-up networking: **SUE-T** (endpoint transport), **ESUN** (L2 framing), and the **UEC link layer** under them (LLR, CBFC, UET CRC). It builds the protocols in a discrete-event simulator for timing and a netns emulator for packets and failures, then compares hop-by-hop recovery with the end-to-end recovery of [srv6-mrc-emulator](https://github.com/segmentrouting/srv6-mrc-emulator) and the MetaRoCE simulator.

> **Question this project answers:** where should the retry live, at the link (LLR + CBFC) or end to end (MRC, MetaRoCE)?

## Status

| Milestone | What | State |
|---|---|---|
| M0 | Read the specs, build the delta table | in progress: [docs/delta-table.md](docs/delta-table.md) |
| M1 | Scapy layers, Wireshark dissector, golden pcaps | not started |
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
docs/           delta table, experiments, findings
```

More directories (`sue/`, `wireshark/`, `sim/`, `emu/`, `p4/`, `pcaps/`) arrive with their milestones.

## Specs

Public specs only. The PDFs are not committed; [specs/README.md](specs/README.md) lists where to download each one.

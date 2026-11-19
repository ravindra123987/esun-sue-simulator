# ESUN / SUE-T scale-up simulator: plan

**Goal:** learn Ethernet scale-up networking by building it. Make every SUE-T / ESUN / UEC link-layer field visible in pcaps, model the timing-critical mechanisms in a discrete-event simulator, and run the same failure scenarios we already ran for MRC and MetaRoCE, to answer one question:

> **Where should the retry live?** Compare hop-by-hop (LLR + CBFC, scale-up) with end-to-end (MRC trimming, MetaRoCE port pairs, scale-out), under the same faults.

Specs and their relationships are in [specs/README.md](specs/README.md).

## What carries over and what is new

| Already known (MRC / MetaRoCE / RoCEv2) | New in scale-up |
|---|---|
| Multi-plane, spraying, plane failure | Usually a **single switch hop** (SUE-T is optimized for 1 hop, up to 16K XPUs) |
| End-to-end loss detection, NACK, fast retransmit | **Hop-by-hop LLR** (replay buffer in the MAC) plus an end-to-end **RODL** backstop |
| Lossy fabric + ECN/trimming | **Lossless** fabric: PFC or **CBFC** (credit cyclic counters) |
| RDMA verbs, QPs, messages | **Load/store/atomic** transactions of at most 256 B, PGAS memory, AXI4 interface |
| IP/UDP headers, ICRC | Compact headers (**ESUN header / UFH**), **UET CRC**, packing several commands into one frame |
| RTT in tens of µs | **< 2 µs RTT** target, so timing questions must go in the simulator, not the emulator |

## Design principles

1. **Two engines, separate jobs** (same as metaroce-simulator):
   - `sim`: a pure-Python discrete-event simulator for **timing**: LLR replay-buffer depth, CBFC credit stalls, tail latency. It runs at ns resolution.
   - `emu`: Linux netns + veth with a **user-space switch** (AF_PACKET) for **formats, pcaps and failure behaviour**. Never quote latency numbers from it.
2. **The switch is ours.** LLR and CBFC live in the link and switch, which SONiC-vs and kernel bridges don't implement. P4/bmv2 is only for parsing and forwarding (M6).
3. **Reuse the topology/scenario format from metaroce-simulator** where it fits, so the three-way comparison in M5 is cheap.
4. **Follow the spec.** Every header field and state machine cites its spec section. Where the spec is unclear, write it down in `docs/findings/`.
5. Use public specs only, on personal time. Commits use the personal identity with no tool attribution trailers.

## Milestones

### M0: Read and build the delta table (1–2 weeks)
Read the specs in this order:
1. SUE-T base spec, all of it (33 pp). Focus on §6–7: processing flow, ACK modes, packing, RODL mapping, load balancing.
2. Broadcom SUE RM104, chapters 2 and 4 and Appendix A (latency budget), for the reasoning behind each choice.
3. UEC 1.1 (only these parts):
   - §3.5.7.3, §3.5.10, §3.5.25.8–9: RODL and headers
   - §3.4.3.3, §3.4.3.8, §3.4.9.5: Unified Local SES headers and memory model
   - §3.5.26: UET CRC
   - §5.1: LLR
   - §5.2: CBFC (and §5.2.9, how CBFC, PFC and LLR interact)
   - §5.4: UFH
   - §7.6: SAI for LLR/CBFC, which links back to SONiC
4. ESUN 1.0 spec (download manually, see specs/README.md) and the IEEE overview slides.

**Deliverable:** `docs/delta-table.md`. One row per mechanism or field, with columns: what it does, which spec section, what it replaces in RoCEv2 / MRC / MetaRoCE, and what problem it solves. Also answer the open question about the ESUN header vs UFH.

### M1: Make packets visible (1–2 weeks)
- Scapy layers: ESUN header / UFH_16, UET PDS prologue, RODL request/ACK/NACK, Unified Local SES request and response, UET CRC, and SUE-T packing of several CMD_PDUs into one frame.
- A Wireshark Lua dissector for the same layers.
- Golden pcaps: hand-crafted frames for each packet type, checked field by field against the spec figures, plus unit tests that round-trip bytes and recompute the CRC.

**Deliverable:** `wireshark/sue.lua`, `sue/layers/`, and `pcaps/golden/` with a short README.

#### M1b: Wireshark upstream contribution track

Wireshark has `epan/dissectors/packet-uet.c` (merged 2025-12-18, [MR !22094](https://gitlab.com/wireshark/wireshark/-/merge_requests/22094), Keysight + Rivos, written against UEC 1.0.1, still maintained). It decodes UDP 4793 / IP-direct UET: ROD/RUD/RUDI/UUD, ACK/NACK and CC variants, TSS, standard SES, and the IP-path UET CRC. As of 2026-11-14 nothing from UEC 1.1 is there, and no open MR or issue covers it:

| Gap | Spec | Upstream target |
|---|---|---|
| RODL (`pds.type` 15): 12 B header, and the compressed form over UFH_16 | UEC §3.5.10.5, §3.5.22 | `packet-uet.c` |
| Unified Local SES: request ac=0 (12 B), ac=1 (8 B), response (4 B), mm packing | UEC §3.4.3.3, §3.4.3.8 | `packet-uet.c` |
| UFH_16 / UFH_32 (EtherType 0xE790) | UEC §5.4 | `packet-uet.c` (EtherType registration) |
| UET CRC over UFH_16: dscp/ecn masked, expected PSN appended (needs per-PDC PSN tracking; verify syn=1 packets directly) | UEC §3.5.26.1 | `packet-uet.c` |
| CBFC CC_Update (0x8808, opcode 0xFFFE, CID FA-7A-CB, msg type 1/2) | UEC §5.2.6.2 | `packet-macctrl.c` |

Out of scope for upstream:
- **LLR and CF_Update**: they live in the preamble and PCS control blocks, which NICs strip before capture. Only the simulator and the docs show them.
- **ESUN header**: keep it in our Lua dissector behind Decode As / a preference until IEEE assigns the EtherType.

Steps:
1. Prototype each gap in `wireshark/sue.lua` and check it against `pcaps/golden/`, where every field value is known.
2. Before any C work, open a Wireshark issue describing the UEC 1.1 additions, and mention the original authors so the work is coordinated with them.
3. Port to C as extensions of the existing dissectors, as three small MRs in this order: (a) RODL + Unified Local SES, (b) UFH + CRC over UFH, (c) CC_Update in MAC control. Each MR includes a golden capture for `test/captures/` and a field-by-field note citing the spec figure.
4. Track review comments and any spec ambiguities they raise in `docs/findings/wireshark.md`.

Rules: public specs only, personal time and identity (no tool attribution). Check the employer's open-source contribution policy before step 2. Nothing is posted upstream (issue or MR) without explicit approval.

**Deliverable:** a merged MR, or MRs under review, for (a)–(c), plus `docs/findings/wireshark.md`.

### M2: Link-layer simulator: LLR + CBFC (2 weeks)
- DES topology: two endpoints and one switch, with link models for propagation delay, bit error rate (BER, injected as frame corruption), and link down.
- LLR per UEC §5.1: replay buffer, LLR_ACK/LLR_NACK, the INIT handshake, and timers.
- CBFC per UEC §5.2: cyclic counters, credit size, CF_Update messages, and resilience to lost credit messages.
- Experiments:
  - How deep must the replay buffer be, given BER and cable length?
  - What credit size is enough to stay at line rate?
  - LLR on vs off: how many end-to-end retransmissions remain?
  - What happens to credit accounting when CBFC and LLR run together?

**Deliverable:** `docs/experiments/llr-cbfc.md` with plots. *Status: first cut done on a single link (E1–E5); switch topology and a second VC are next.*

### M3: SUE-T endpoint in the simulator (2 weeks)
- Per-{dstXPU, TC} transmit queues, packing, a 256 B maximum transaction size, and 2–4 traffic classes.
- RODL with PSNs, plus both ACK modes: Delivery ACK and Operational ACK.
- Load balancing across ports (SUE-T §7.6).
- Workloads: an all-to-all and an all-reduce made of 256 B load/stores. Metrics: goodput efficiency (bytes of header per byte of payload) and completion-time tail.

**Deliverable:** a comparison of wire efficiency with RoCEv2 at the same payload sizes, matching SUE-T §7.2.3. *Status: first cut done, [docs/experiments/suet-endpoint.md](docs/experiments/suet-endpoint.md) (T1–T6); switch pipeline latency and 4 TCs are next.*

### M4: netns emulator (2–3 weeks)
- A user-space switch over AF_PACKET (Python first; move to Rust or C if packets per second limits it) that does ESUN forwarding, LLR, and CBFC.
- Endpoints as user-space SUE-T processes. The real frames on the veths are captured with tcpdump and decoded by the M1 dissector.
- Fault injection: corruption at a set BER, link down/up, dropped credit messages, a stuck receiver.
- Check that the emulator reproduces the simulator's failure behaviour qualitatively.

**Deliverable:** `docs/experiments/emulator.md`. *Status: first cut done: `emu/` (lab, switch, link end, endpoint, analyser), nine scenarios against the simulator's, captures the dissector decodes. Loads, delivery ACKs, ESUN on the endpoints and a faster data path are next.*

### M5: Multi-plane and the three-way comparison (2 weeks)
- Each SUE-T instance has 4 ports connected to 4 switch planes. Scenarios: kill a plane, flap a link, add congestion, starve credits.
- Run the same scenarios through the MRC (srv6-mrc-emulator) and MetaRoCE (metaroce-simulator) models.

**Deliverable:** `docs/where-should-retry-live.md`, the main write-up of the project. *Status: done in the simulator (four XPUs × four planes, five recovery designs with the MRC and MetaRoCE rules ported from metaroce-simulator's models, six faults, a bit-error-rate sweep, and a lossy fabric with drop-tail or trimming) and in the M4 emulator with four planes on real frames. Not yet: congestion in the emulator, adaptive transport timers, the viewer's planes picture.*

### M6: Programmable switch (1–2 weeks)
- A P4 program on bmv2 that parses the ESUN header / UFH and forwards on it, with TC-to-queue mapping.
- Notes on how this maps to SAI, including UEC §7.6 SAI extensions for LLR and CBFC.

### M7 (later): UALoE, then native UALink
- Carry UALink-style transactions over the M4 transport and compare them with SUE-T's Unified Local mapping.
- Native UALink: a flit-level simulator for an efficiency and behaviour comparison.

## Planned layout
```
specs/          reference PDFs (git-ignored) + README
docs/           delta-table, experiments/, findings/
sue/layers/     Scapy layers
wireshark/      Lua dissector
sim/            discrete-event engine + models (link, LLR, CBFC, SUE-T endpoint, switch)
emu/            netns/veth lab, user-space switch, fault injection
p4/             bmv2 ESUN switch
pcaps/golden/   reference captures
```

## Open questions
- [x] ESUN header vs UEC UFH: separate designs. ESUN keeps 48-bit MACs and adds a 4-byte EH; UFH overlays the MACs. See specs/README.md.
- [x] Over ESUN, which bytes does the UET CRC cover? **Decision D3:** from the DA, EH CoS/ECN/TTL masked. See docs/findings/m1-decisions.md. (M1)
- [x] `psn_state` split when syn=0 (UFH_16): **D5**, {clear_psn_offset(12), rev_cack_psn_lsb(12)}. Hidden-PSN placement in the CRC: **D6**. CRC trailer byte order: **D8**, big-endian until a real test vector says otherwise. (M1)
- [x] ESUN EtherType (EH-ET) is unassigned (ESUN 1.0 §5.1). As of 2026-11-14 no public deployment, product, test tool or IETF draft uses a value (searched Keysight, Arista, Broadcom TH-Ultra, Meta Tahan, IETF SUNH). **Decision:** `ESUN_ETHERTYPE = 0x88B5` (IEEE 802 local experimental), one config value shared by the Scapy layer, Lua dissector and user-space switch. Recheck when ESUN 1.1 is released. (M1)
- [x] What follows the ESUN header? Nothing in the frame says. SUE-T §7: "When using ESUN, the presence of the UEC transport is inferred by network wide configuration." **Decision:** a second config value `ESUN_PAYLOAD = rodl` (default), so the dissector decodes EH → RODL → SES without an in-band marker. (M1)
- [ ] Do SUE-T load balancing and the ESUN flow label work together? The flow label must stay constant per PDC to keep ordering. (M0/M5)
- [x] SUE-T §7.6 balances each *packed group* across ports, but RODL needs one path per PDC. **M3 T5:** per-group balancing is safe only across equal-delay planes; with one plane 17 m longer, reorders become NACKs and Go-Back-N (efficiency 26 % vs 88 %). Balance across PDCs, or only across identical paths. See docs/delta-table.md open item 8; M5 adds the plane-failure case.
- [x] LLR is "optional" in ESUN. What does SUE-T assume when LLR is off? **M2 E3:** every corrupted frame becomes an end-to-end loss for RODL Go-Back-N (or a dead PDC in SUE-lite); "lossless" at real error rates needs LLR or transport retransmission. See docs/experiments/llr-cbfc.md.
- [x] Should the user-space switch use AF_PACKET or AF_XDP? **M4:** AF_PACKET. The emulator moves 410 packets/s end to end and the time is in the Python endpoints (0.46 ms to build a packet, 0.28 ms to parse and verify one), not in the socket; AF_XDP would not change that, a C data path would. See docs/experiments/emulator.md.
- [ ] Wireshark CRC over UFH_16: the PSN is not on the wire. Track expected PSN per {src, dst, PDCID} conversation, and mark the CRC "unverified" after a gap rather than "bad"? Decide with the maintainers in M1b.

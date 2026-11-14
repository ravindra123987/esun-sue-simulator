# Delta table: scale-up (SUE-T / ESUN / UEC link) vs what we already built

M0 deliverable. Each row is one mechanism or field: what it does, where the spec defines it, what plays that role in **RoCEv2** and in our scale-out work (**MRC** = srv6-mrc-emulator, **MetaRoCE** = metaroce-simulator), and the problem it solves. The last column says which milestone has to build it.

Spec shorthand: **ST** = SUE-T Base 1.0.0, **UEC** = Ultra Ethernet 1.1, **ESUN** = OCP ESUN 1.0, **RM** = Broadcom SUE RM104.

> Status: first draft written from the spec reading for the explainer. Rows marked ⚠ have a spec gap or inconsistency; see [Open items](#open-items).

## 1. Framing and addressing

| Mechanism | What it does | Spec | RoCEv2 | MRC / MetaRoCE | Problem it solves | Build in |
|---|---|---|---|---|---|---|
| **UFH_16** | Packs 16-bit dst/src addresses and DSCP/ECN into the 12 B MAC DA/SA area. The freed 44 "opaque" bits carry transport (RODL) fields. EtherType 0xE790. | UEC §5.4 | Eth 14 + IPv4 20 + UDP 8 = 42 B | Same IP/UDP stack; MRC adds an SRv6 header (more bytes) | Header overhead: Ethernet + transport in **16 B** vs 54 B (Eth+IP+UDP+BTH) | M1 |
| **ESUN header (EH)** | Keeps 48-bit MACs and adds a 4 B header after a new EtherType: Rev, F, CoS(3), ECN(2), flow label(16), TTL(4), UD(2). Replaces the IP header. | ESUN §5.1–5.2 | IP header (DSCP, ECN, TTL) + UDP src port for entropy | Entropy: MRC uses SRv6 entropy values (EVs); MetaRoCE uses the UDP source port per port pair | Drop 20–40 B of IP while keeping ECN, CoS, load-balancing entropy and loop protection | M1 |
| ⚠ **EH EtherType** | Identifies the ESUN header. **Unassigned.** | ESUN §5.1 | 0x0800 / 0x86DD | — | — | M1: configurable, default 0x88B5 |
| **Static DA forwarding** | Switches forward on configured DAs. No learning, aging or flooding; unknown DA → drop. | ESUN §5 | IP routing (ECMP) | Routed fabric (BGP/static); MRC steers with SRv6 segments | Deterministic, low-latency forwarding without L3 lookups | M4, M6 |
| **Flow label + F bit** | When F=1, switches hash {DA, SA, flow label} so a flow always takes the same path. | ESUN §5.2 | UDP src port into ECMP hash | MRC: EV picks plane + path explicitly. MetaRoCE: port pair → plane, src port → path | Entropy for load balancing, while keeping per-flow order (RODL needs in-order) | M1, M5 |
| **EH-TTL** | Hop limit, decremented per switch. FCS recomputed. | ESUN §5.2 | IP TTL | IP TTL | Loop protection in multi-tier scale-up | M4 |
| **Traffic class → CoS / DSCP** | 2–4 TCs (minimum 2); requests and responses on different TCs. | ST Table 1, §7.3; ESUN EH-CoS | DSCP/PCP → priority (PFC class) | One lossy class + trimming (MRC); RoCE class (MetaRoCE) | Request/response deadlock avoidance on a lossless fabric | M3 |

## 2. Transport: reliability and connections (PDS / RODL)

| Mechanism | What it does | Spec | RoCEv2 | MRC / MetaRoCE | Problem it solves | Build in |
|---|---|---|---|---|---|---|
| **PDC** | A bidirectional connection between two FEPs, set up on demand with `syn`. A pool can be smaller than the number of peers ("reserved PDCs" for static use). | UEC §3.5.8; ST §7.5, §7.5.1 | RC QP (one-directional pair, set up out of band) | MetaRoCE: RC QPs on port pairs. MRC: connectionless UDP/UD + per-EV state | Connection state for 16K XPUs without one QP per peer | M3 |
| **RODL** | Reliable ordered delivery for local networks: one path per PDC, Go-Back-N, optional retransmission. | UEC §3.5.7.3, §3.5.22 | RC Go-Back-N (PSN, NAK sequence error) | MetaRoCE: RC Go-Back-N + RTO + repath. MRC: per-EV loss tracking, NACK fast retransmit on another EV | Ordered delivery with tiny per-connection state (no bitmaps, no SACK) | M3 |
| **PSN folded into CRC** | Over UFH_16 the 32-bit PSN is not sent once the PDC is up. Both ends feed it into the UET CRC; a mismatch means corruption *or* a gap. | UEC §3.5.7.3, §3.5.26.1 | 24-bit PSN in BTH | PSN on the wire | Saves 4 B per packet; one check for integrity and sequence | M1, M3 |
| ⚠ **psn_state field** | 24 bits split across UFH opaque bits. syn=1: PSN = {0x00, psn_state}. syn=0: clear-PSN offset + reverse CACK bits. | UEC Fig 3-68 | — | — | Carries setup and ACK state without extra bytes | M1 |
| **Piggybacked ACK (cack)** | Cumulative ACK for the reverse direction rides in RODL request headers (flag `cack`). | UEC §3.5.22.1.2 | Separate ACK packets (coalesced) | Separate ACKs. MetaRoCE: ACK plane follows the RxFlow pair (our ACK-plane finding) | No ACK packets under bidirectional traffic | M3 |
| **Delivery ACK vs Operational ACK** | Delivery: ACK = delivered; responses travel as full commands. Operational: ACK = done; the source generates the response from stored state. | ST §7.1.1, §7.1.2, §7.2.3 | ACK = delivered; RDMA write has no response | ACK = delivered | Operational ACK: > 90% vs < 80% wire efficiency, paid for with state | M3 |
| **No-retransmission RODL (SUE-lite)** | Any loss → the PDC is closed in error (close command). | UEC §3.5.22.1.1; ST §7.8 | Always retransmits | Always retransmits | Removes TX hold buffers: smallest silicon | M3, M5 |
| **No congestion control** | RODL supports no NSCC, no trimming; relies on lossless + one hop. | UEC §3.5.22 | DCQCN | MRC: trimming + EV demotion. MetaRoCE: RCN (gamma) | Simplicity: one-hop fabric congests only at egress | M5 (compare) |
| ⚠ **Port mapping / failover** | §6 step 6 maps a packet to a port by {dstXPU, TC}. §7.6 adds optional load balancing that assigns each *packed group* to a port by available bandwidth. Moving a connection to another port when a port fails is **future work** (§7.5). | ST §6, §7.5, §7.6 | One port per QP; bonding is outside the spec | MRC: sprays over planes, demotes bad EVs in ms. MetaRoCE: RTO-driven pair move | — (gap) | **M5: main experiment** |

## 3. Semantic layer (SES, Unified Local)

| Mechanism | What it does | Spec | RoCEv2 | MRC / MetaRoCE | Problem it solves | Build in |
|---|---|---|---|---|---|---|
| **SES request (ac=0), 12 B** | opcode, jobid, length, 60-bit address. Load/store/atomic, ≤ 256 B per transaction in SUE-T. | UEC §3.4.3.3 | BTH 12 + RETH 16 (write), per message | MetaRoCE: RDMA verbs. MRC: test payload | Memory semantics (load/store) instead of messages | M1 |
| **Address compression (ac=1), 8 B** | Next command's address = previous + 32-bit signed offset. | UEC §3.4.3.3 | — | — | 4 B saved per packed command | M1 |
| **Packing (mm bit)** | Up to 16 CMD_PDUs per frame, each 4 B aligned; work-conserving scheduler (never waits). | ST §7.3, §7.4 | One message per packet sequence; no packing | No packing | Small transactions waste headers; packing gives > 90% efficiency under load | M1, M3 |
| ⚠ **SES response, 4 B** | return_code, payload_length; responses packed in request order. | UEC Table 3-19 (ST §7.2.1 says 8 B) | ACK / read response | — | Response with no per-command ID | M1 |
| **jobid** | 8-bit job/VM isolation, kept in PDC state, checked on receive. | ST §7.2.1 | P_Key / Q_Key | — | Multi-tenant isolation in shared memory | M3 |
| **AXI mapping** | AxID ↔ PDCID (not sent), AxADDR → address, AxUSER → extension header. | ST §8.4 | Verbs API | Verbs (MetaRoCE) | Plugs directly into the XPU's on-chip bus | M7 (optional) |

## 4. Link layer

| Mechanism | What it does | Spec | RoCEv2 | MRC / MetaRoCE | Problem it solves | Build in |
|---|---|---|---|---|---|---|
| **LLR** | Per-link Go-Back-N in the MAC: 20-bit seq in the preamble, replay buffer, ACK/NACK as control ordered sets, replay timer, FLUSH on give-up. | UEC §5.1 | None (FEC only; loss goes to the transport) | None: MRC and MetaRoCE recover end to end | Fix bit errors in ~1 link RTT (hundreds of ns) instead of a fabric RTT + timeout | **M2** |
| **Replay buffer ≤ BDP** | `outstanding_data_max` should equal the link bandwidth-delay product, because PFC/pause don't stop replays. | UEC §5.1, Table 5-9 | — | — | Keeps PFC correct with LLR | M2 |
| **Poisoned FCS** | A frame known bad upstream is forwarded with a poisoned FCS: dropped downstream, but no replay. | UEC §5.1.2 | — (cut-through stomps CRC) | — | Error propagation in cut-through without useless replays | M2 |
| **CBFC** | Sender holds credits (CreditSize bytes each) for the receiver's buffer, per VC (≤ 32). Cyclic CC/CF counters; CF_Update (8 B CtlOS) returns credits, CC_Update (64 B frame) repairs leaks. | UEC §5.2 | PFC (XOFF/XON) | MRC: lossy + trimming. MetaRoCE: PFC/ECN class | Lossless without PFC's headroom problem; more lossless classes per buffer | **M2** |
| **PFC** | XOFF/XON per priority. Required by ESUN; optional alternative to CBFC in SUE-T. | IEEE 802.1Qbb; ESUN §7 | Same | MetaRoCE lab uses PFC/ECN; MRC avoids it | Lossless baseline | M2 |
| **LLR + CBFC interaction** | Discard window / replay window; nine rules so each frame's credits count exactly once (CC_Update must be LLR-eligible). | UEC §5.2.9 | — | — | Prevents buffer overflow when replays and credit accounting overlap | M2 (experiment 4) |
| **Link negotiation** | Agrees LLR/CBFC capability per link. | UEC §5.3 | LLDP/DCBX for PFC | — | Bring-up | M4 |

## 5. Integrity

| Mechanism | What it does | Spec | RoCEv2 | MRC / MetaRoCE | Problem it solves | Build in |
|---|---|---|---|---|---|---|
| **UET CRC** | CRC32C (Castagnoli) trailer before the FCS. UDP/IP: from src IP, UDP checksum = 0. UFH_16: from byte 0, dscp/ecn masked, expected PSN appended, pad to 56 B. Mandatory over UFH_16. | UEC §3.5.26 | ICRC (CRC32, masks variant fields) | MRC: real ICRC (our PR #11). MetaRoCE: ICRC | End-to-end protection; switch-internal corruption | M1 |
| ⚠ **UET CRC over ESUN** | Coverage start and masked EH fields are undefined. | — | — | — | — | M1: decide + document |
| ⚠ **CRC trailer byte order** | Spec says network order; iSCSI/most code write little-endian. | UEC §3.5.26 | ICRC is little-endian | — | — | M1: pin with a test vector |

## 6. Timing budget

| Item | Value | Spec | Scale-out reference | Used for |
|---|---|---|---|---|
| Bridge NOC ↔ Ethernet (TX+RX) | < 100 ns | RM App A | — | sim default |
| MAC + PHY (TX+RX) | < 100 ns | RM App A | — | sim default |
| Switch | < 250 ns | RM App A | Hundreds of ns to µs, multi-tier | sim default |
| Cable | 3.5–4.96 ns/m | RM App A | same | sim default |
| One way XPU → XPU, 1 hop | 478–549 ns | RM App A (⚠ two totals wrong) | — | sanity check |
| Target RTT | < 2 µs (1500 B packet, single hop) | ST Table 1 | Tens of µs (MRC/MetaRoCE labs) | M3 metric |

## Open items

Answered (see plan.md open questions):
- ESUN header vs UFH: separate designs. ESUN keeps MACs + 4 B EH; UFH overlays the MACs.
- ESUN EtherType: unassigned → configurable, default 0x88B5.
- Transport after the EH: implied by configuration (ST §7) → `ESUN_PAYLOAD = rodl`.

Still open:
1. **UET CRC over ESUN**: where coverage starts, and which EH fields are masked. Proposal: start at DA; mask CoS, ECN, TTL; keep the flow label.
2. **Entropy field over ESUN**: is the 2 B UET entropy field present after the EtherType? Proposal: no; the flow label replaces it.
3. **psn_state bit split when syn=0** (UFH_16): read UEC §3.5.25.8–9 again before writing the Scapy layer.
4. **SES response size**: 4 B (UEC) vs 8 B (SUE-T text). Follow UEC.
5. **ACK size over UFH_16**: 20 B (Fig 3-120) vs 2 B PDS ACK (Fig 3-123).
6. **CRC trailer and hidden-PSN byte order**.
7. **LLR optional on ESUN hosts**: with no host LLR, a bit error on the host link goes straight to RODL (or kills the PDC in SUE-lite). Quantify in M2/M5.
8. **Per-group port load balancing vs RODL order** (new finding): ST §7.6 lets SUE-T put each packed group of a {dstXPU, TC} queue on a different port, but RODL (UEC §3.5.7.2–3) requires one path per PDC so packets arrive in order. If two ports reach different switches or queues, packets of one PDC can reorder, and the receiver will treat that as loss (Go-Back-N, or a fatal PDC without retransmission). Possible readings: (a) balancing only applies across PDCs, never within one; (b) all ports of an instance reach the same switch with in-order behaviour. §6 step 6 (map by {dstXPU, TC}) supports (a). Model both in M5 and measure the reordering cost.
9. **Flow label vs port choice** (ESUN): the flow label must stay constant per PDC. Check it never disagrees with the port choice (M5).

## What this means for M5

The scale-out designs we built treat loss as normal and recover end to end across planes (MRC in milliseconds by demoting EVs; MetaRoCE by RTO-driven pair moves). Scale-up makes loss abnormal (lossless + LLR) and has **no** cross-port failover in SUE-T 1.0. So the comparison splits into two fault classes:

| Fault | Scale-up answer | Scale-out answer |
|---|---|---|
| Bit errors on a link | LLR, ~1 link RTT, invisible to transport | End-to-end retransmit (MRC fast NACK, MetaRoCE RTO/NAK) |
| Congestion | Credits/PFC backpressure (no drops, HoL risk) | Trimming/ECN, spraying (MRC); RCN (MetaRoCE) |
| Link or plane down | LLR FLUSH → RODL Go-Back-N on the same port, or PDC fatal. Failover not specified | MRC demotes the plane and keeps spraying; MetaRoCE moves the pair |

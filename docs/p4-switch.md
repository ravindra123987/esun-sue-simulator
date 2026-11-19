# M6: a P4 switch for SUE-T over UFH_16 and ESUN

[p4/esun_switch.p4](../p4/esun_switch.p4) is a single-hop scale-up switch written in P4-16 for the v1model architecture and run in bmv2 `simple_switch`. It parses UFH_16 and ESUN, forwards on them, maps traffic classes to queues, decrements the ESUN TTL, marks ECN and keeps link-local frames off the fabric. `tools/run_m6.py` compiles it, puts it in the M4 lab in place of the Python switch, checks it frame by frame, and runs SUE-T traffic through it on one and four planes. The second half of this page maps each behaviour to SAI, the API a SONiC switch would be programmed through, including the UEC 1.1 §7.6 additions for LLR and CBFC.

## What the program does

| Behaviour | How | From |
|---|---|---|
| Recognise UFH_16 | First DA octet v=0, w=1, z=y=0, x=1 (mask 0xCE = 0x42) and EtherType 0xE790, read with `lookahead` before any header is extracted | UEC 1.1 §5.4.3, Table 5-40 |
| Forward UFH_16 | Exact match on the 16-bit destination container (DA bytes 4–5): `ufh_fwd` | Fig 3-120, decision D11 |
| Forward ESUN and other Ethernet | Exact match on the MAC DA: `l2_fwd`, a static table; unknown DA dropped, never flooded, nothing learned | ESUN 1.0 §5 |
| ESUN TTL | Decremented per hop; a frame arriving with TTL ≤ 1 is dropped | ESUN 1.0 §5.2 |
| Link-local frames | EtherType 0x8808 (MAC control: CBFC CC_Update, PAUSE) consumed, not forwarded | UEC §5.2.6.2, IEEE 802.3 Clause 31 |
| Traffic class to queue | UFH_16 dscp (`tc_ufh`) or ESUN CoS (`tc_esun`) sets the v1model priority; one queue per priority (`--priority-queues 8`) | SUE-T §7.3 (requests and responses on separate TCs) |
| ECN | At egress, ECT becomes CE when the queue depth reaches `ecn_threshold` (register; 0 = off) | RFC 3168 semantics on the UFH_16 ecn / ESUN EH-ECN bits |
| Counters | Packets per queue, drops by reason (no route, TTL, MAC control, parse), CE marks | — |

The switch rewrites only fields the UET CRC leaves out of its coverage: UFH_16 dscp/ecn (byte 7, UEC §3.5.26.1) and ESUN CoS, ECN and TTL (project decision D3). It never touches the CRC, so the end-to-end CRC must still verify after it; that is checked below, on frames that crossed the switch.

What a P4 pipeline cannot do: **LLR and CBFC.** Both live below the MAC client, in the MAC and the PCS: the LLR sequence number rides in the preamble, ACK/NACK and CF_Update are control ordered sets the PCS inserts between frames, and CBFC gates the MAC's transmit. A P4 program sees frames after all that has happened. In the lab, the bmv2 links therefore run without LLR and CBFC, on plain frames (`PortCfg(shim=False)`, endpoint `--no-shim`), like a NIC next to a switch that has neither. On a real switch these are MAC features configured through SAI (below).

## Checks (frame by frame, through bmv2)

`emu/p4check.py` opens a packet socket inside every XPU namespace, sends frames built by `sue/frame.py` from one XPU, and records which XPUs receive what. Thirteen checks, all passing ([p4-results.json](experiments/p4-results.json)):

| Check | Tests |
|---|---|
| UFH_16 request forwarded by destination id, bytes unchanged, UET CRC (with the hidden PSN) good | Fig 3-120 overlay; the switch does not touch covered bytes |
| UFH_16 to an unknown destination dropped, drop counter +1 | static forwarding, no flooding |
| ESUN forwarded by DA, TTL 15 → 14 | ESUN §5.2 |
| ESUN UET CRC still good after the TTL rewrite | decision D3 on a real pipeline |
| ESUN with TTL 1 dropped | ESUN §5.2 |
| CC_Update (MAC control) not forwarded | link-local |
| Ethernet frame with an unknown DA not flooded | ESUN §5 |
| UDP/IP SUE-T frame forwarded by DA, unchanged | SUE-T §8.3, third header stack |
| dscp 0 → queue 0, dscp 1 → queue 1, ESUN CoS 3 → queue 3 | TC mapping |
| UFH_16 ECT → CE, CRC still good | byte 7 masked in the UET CRC |
| ESUN ECT → CE, CRC still good | D3 masks EH-ECN |
| Non-ECT left unmarked | ECN semantics |
| UFH_16 ACK (PDS type 7) forwarded and CRC good | ACKs share the overlay |

The two CRC checks are the useful ones: decisions D3 (CRC over ESUN masks CoS, ECN and TTL) and the UFH_16 masking rule were made on paper in M1; here a switch rewrites exactly those fields and the receiver's CRC still verifies.

## SUE-T traffic through bmv2

The M4/M5 endpoints, four XPUs, through one bmv2 instance per plane (plain links, no LLR, no CBFC):

| Run | Result | bmv2 counters |
|---|---|---|
| 1 plane, pinned RODL, 256 KB per peer | all 12 288 stores in 0.37 s, no retransmission | 1 536 packets on queue 0 (requests), 82 on queue 1 (ACKs), no drops |
| 4 planes, spray + SACK, 1 MB per peer | all 49 152 stores in 1.81 s; 1 548 / 1 548 / 1 548 / 1 547 packets per plane | requests on queue 0, ACKs on queue 1 on every plane |
| 4 planes, spray, plane 1 down at 0.5 s | all 49 152 in 2.61 s, 11 timeouts, plane 1 marked bad 7 times, 0 failed | plane 1 carried 494 requests before it died |
| 4 planes, pinned, plane 1 down at 0.5 s | did not finish in 90 s; 256 stores failed | — |

These repeat the M5 result on a third switch implementation: pinned connections cannot leave a dead plane, sprayed ones lose one timeout. The ACK count per queue also shows what TC separation buys: with traffic both ways (four-plane runs) the ACKs and requests share each link roughly half and half, and a strict-priority scheduler would keep ACKs from waiting behind 2 KB requests. bmv2's priority queueing is strict, but at the rates the lab reaches (a few thousand packets per second) its queues never build, so this run shows the mapping, not its benefit.

## Mapping to SAI

A switch running SONiC is programmed through SAI. For each behaviour above, what SAI already has, what UEC 1.1 adds, and what is missing. Identifiers are marked by where they come from: **SAI** = long-standing objects and attributes in the SAI headers; **SAI master** = read in the current headers (`inc/saivirtualchannel.h`, `inc/saiqosmap.h`, `inc/saibuffer.h`, `inc/saiport.h`); **proposal** = in an SAI proposal document still "In review" (`doc/LLR/SAI-Link_Layer_Retry.md`, `doc/CBFC/SAI-Credit_Based_Flow_Control.md`, `doc/SAI-Proposal-Packet-Trimming.md`), so the names may change.

### Forwarding

| P4 | SAI | Gap |
|---|---|---|
| `l2_fwd` static DA → port, no learning, no flooding (ESUN) | **SAI**: FDB entries of type `SAI_FDB_ENTRY_TYPE_STATIC`; learning off per port with `SAI_PORT_ATTR_FDB_LEARNING_MODE = SAI_PORT_FDB_LEARNING_MODE_DISABLE`; no flooding with `SAI_VLAN_ATTR_UNKNOWN_UNICAST_FLOOD_CONTROL_TYPE = SAI_VLAN_FLOOD_CONTROL_TYPE_NONE` | None for the lookup. But the ASIC must accept the ESUN EtherType and skip the 4-byte EH; there is no SAI object for a new L2 header |
| `ufh_fwd` on the 16-bit destination container | Not an FDB lookup: the first four DA bytes carry PDS fields that change per packet. It can be expressed as an **SAI** ACL: table field `SAI_ACL_TABLE_ATTR_FIELD_DST_MAC`, entry `SAI_ACL_ENTRY_ATTR_FIELD_DST_MAC` with mask `00:00:00:00:ff:ff` (plus the first-octet pattern), action `SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT` to the port | Forwarding through ACL redirects scales with the ACL TCAM, not the FDB; a UFH-aware lookup is not in SAI or in the UEC §7.6 additions |
| ESUN TTL decrement and drop at expiry | — | No SAI action rewrites a TTL in an L2 header; it needs ASIC support for the ESUN EH |
| MAC control (0x8808) consumed | Handled by the MAC (IEEE 802.3 Clause 31); CBFC CC_Update counted by the proposal's `SAI_PORT_STAT_CBFC_NUM_CC_UPDATE_MESSAGES_RX` (**proposal**) | — |

### Traffic class, queues and virtual channels

| P4 | SAI | Gap |
|---|---|---|
| UFH_16 dscp → queue | The UFH_16 "dscp" is byte 7 of the frame (inside the SA), not an IP DSCP, so `SAI_QOS_MAP_TYPE_DSCP_TO_TC` cannot see it. **SAI** UDF (`SAI_OBJECT_TYPE_UDF`, a UDF group on offset 7) in an ACL with `SAI_ACL_ENTRY_ATTR_ACTION_SET_TC`, then `SAI_QOS_MAP_TYPE_TC_TO_QUEUE` | A native map would need a new QoS map type |
| ESUN CoS → queue | The same: UDF on the EH byte + ACL `SET_TC`, then TC → queue | The ESUN EH has no SAI parser support |
| TC → CBFC virtual channel | **SAI master**: `SAI_QOS_MAP_TYPE_TC_TO_VC` (0x10), `SAI_QOS_MAP_TYPE_QUEUE_TO_VC` (0x11), `SAI_QOS_MAP_TYPE_DOT1P_DEI_TO_TC` (0x0f), bound by the **proposal**'s `SAI_PORT_ATTR_QOS_TC_TO_VC_MAP` / `SAI_PORT_ATTR_QOS_QUEUE_TO_VC_MAP` | — (what SUE-T needs: one lossless VC per TC, M3) |

### LLR (UEC §5.1; §7.6.1.1 "new attributes and statistics on the port, and a Port LLR profile")

| Model parameter (sim/mac.py, emu/port.py) | SAI |
|---|---|
| `outstanding_data_max`, `outstanding_seq_max` | `SAI_PORT_LLR_PROFILE_ATTR_OUTSTANDING_BYTES_MAX`, `..._OUTSTANDING_FRAMES_MAX` (**proposal**) |
| `replay_timer`, `replay_ct_max`, `data_age` | `..._REPLAY_TIMER_MAX`, `..._REPLAY_COUNT_MAX`, `..._DATA_AGE_TIMEOUT` (**proposal**) |
| `ctlos_spacing` | `..._CTLOS_TARGET_SPACING` (**proposal**, default 2048 bytes, as in our model) |
| re-INIT after FLUSH (`re_init`) | `..._RE_INIT_ON_FLUSH` (**proposal**) |
| what INIT / FLUSH do to traffic (our model: block) | `..._INIT_LLR_FRAME_ACTION`, `..._FLUSH_LLR_FRAME_ACTION` with `sai_llr_frame_action_t` = `SAI_LLR_FRAME_ACTION_DISCARD` / `_BLOCK` / `_BEST_EFFORT` (enum in **SAI master**) |
| `llr.enabled` | `SAI_PORT_ATTR_LLR_MODE_LOCAL`, `SAI_PORT_ATTR_LLR_MODE_REMOTE`, profile bound with `SAI_PORT_ATTR_LLR_PROFILE` (**proposal**) |
| TX state (ADVANCE / REPLAY / INIT / FLUSH), RX state (SEND_ACKS / SEND_NACK / NACK_SENT) | `sai_port_llr_tx_status_t` = `SAI_PORT_LLR_TX_STATUS_OFF/_INIT/_ADVANCE/_REPLAY/_FLUSH`, `sai_port_llr_rx_status_t` = `SAI_PORT_LLR_RX_STATUS_OFF/_SEND_ACKS/_SEND_NACK/_NACK_SENT` (**SAI master**) — the same states our model implements, which is a useful cross-check of M2 |
| counters (replayed, NACKs, bad, duplicates, flushes) | `SAI_PORT_STAT_LLR_TX_REPLAY`, `..._TX_NACK_CTL_OS`, `..._RX_BAD`, `..._RX_DUPLICATE_SEQ`, `..._RX_MISSING_SEQ` and more (**proposal**); `SAI_PORT_ERROR_STATUS_LLR_TX_FLUSH` (**SAI master**) |

### CBFC (UEC §5.2; §7.6.1.2 "virtual channel, credit profile, credit pool")

| Model parameter | SAI |
|---|---|
| one lossless VC per TC (`CBFCCfg.vcs`) | `SAI_OBJECT_TYPE_VIRTUAL_CHANNEL`-style object with `SAI_VIRTUAL_CHANNEL_ATTR_PORT`, `_INDEX` (0–31), `_CBFC_SENDER_ENABLE`, `_CBFC_RECEIVER_ENABLE`, `_CBFC_SENDER_CREDIT_PROFILE` (null = best effort) (**SAI master**, `saivirtualchannel.h`) |
| receiver buffer per VC (`total_credits`) | credit pool `SAI_CBFC_CREDIT_POOL_ATTR_SIZE` and profile `SAI_CBFC_CREDIT_PROFILE_ATTR_RESERVED_CREDIT_SIZE` with static or dynamic shared thresholds (**SAI master**) |
| `credit_size`, `pkt_ovhd` | `SAI_PORT_ATTR_CBFC_SENDER_CREDIT_SIZE`, `..._RECEIVER_CREDIT_SIZE`, `..._SENDER_PACKET_OVERHEAD`, `..._RECEIVER_PACKET_OVERHEAD` (**proposal**) |
| `cf_min_ns`, `cf_max_ns`, `cc_interval_ns` | `SAI_PORT_ATTR_CBFC_CF_MIN_SPACING`, `..._CF_MAX_SPACING`, `..._CC_MESSAGE_TIMER` (**proposal**) |
| credits used / consumed / freed | `SAI_VIRTUAL_CHANNEL_STAT_SENDER_CREDITS_USED`, `..._CONSUMED`, `..._FREED`, `..._RECEIVER_CREDITS_CONSUMED`, `..._FREED` (**SAI master**) |
| bringing a lossless VC up or down safely | `SAI_QUEUE_ATTR_PKT_ENQUEUE_ENABLE`, `SAI_QUEUE_ATTR_PKT_DEQUEUE_ENABLE` (**proposal**) |

### Trimming and ECN (M5b)

| Model | SAI | Gap |
|---|---|---|
| trim a frame that does not fit, serve the header first (`Fabric(trim=True)`) | **SAI master**: `SAI_BUFFER_PROFILE_ATTR_PACKET_ADMISSION_FAIL_ACTION = SAI_BUFFER_PROFILE_PACKET_ADMISSION_FAIL_ACTION_DROP_AND_TRIM` (also `_DROP_AND_TRIM_TO_SENDER`); the trimmed packet's queue and DSCP set by switch attributes (`sai_packet_trim_queue_resolution_mode_t`, `sai_packet_trim_dscp_resolution_mode_t`) | Trimming is defined for IP packets: the trimmed packet is re-marked with an IP DSCP. A UFH_16 or ESUN frame has no IP header, so the "this was trimmed" signal has nowhere standard to go |
| ECN marking on queue depth | **SAI** WRED profile, `SAI_WRED_ATTR_ECN_MARK_MODE` | Marks the IP ECN field only; the UFH_16 ecn bits and the ESUN EH-ECN need ASIC support |

### What SAI does not cover for this fabric

1. A UFH_16-aware forwarding lookup (today: ACL redirects on a masked DA).
2. Parsing the ESUN EH: TTL decrement, CoS and ECN as first-class fields.
3. Trimming and ECN for non-IP scale-up frames.

The UEC §7.6 additions cover the link layer (LLR, CBFC, CSIG telemetry) and leave forwarding and QoS classification to the existing pipeline, which assumes IP or 802.1Q fields. For SUE-T over UDP/IP all of the above works with today's SAI; for UFH_16 and ESUN, the pipeline half is the gap.

## Decisions you can overturn

| # | Choice | What we do | The alternative |
|---|---|---|---|
| M6-1 | Architecture | v1model on bmv2 | PSA, or TNA for Tofino (none of the behaviours need more than v1model) |
| M6-2 | TTL expiry | Drop a frame that arrives with TTL ≤ 1 (decrement would reach 0) | Drop only at 0, forward at 1 (ESUN §5.2 says to decrement; the boundary is ours) |
| M6-3 | UFH_16 forwarding key | The full 16-bit container | The low 12 bits only (dst_addr), treating the top nibble as reserved |
| M6-4 | Queue mapping | dscp / CoS value = priority; requests TC 0, ACKs TC 1 | A table that puts ACKs above requests explicitly, or a WRR scheduler |
| M6-5 | ECN threshold | A register, off by default, depth in packets | A per-queue threshold in bytes, or a RED-like ramp |
| M6-6 | Links in the lab | Plain frames, no LLR, no CBFC (bmv2 has no MAC) | The Python link layer in front of bmv2 (a shim process per port) |

## How to run it

In the VM, as root, with Docker and the `p4lang/p4c` image (it ships `p4c` and bmv2 `simple_switch`, amd64 only, so it runs under Rosetta on an Apple-silicon Mac):

```
limactl shell clab
cd /Users/<you>/ws/personal/esun-sue-simulator
sudo docker pull p4lang/p4c:latest
sudo env PYTHONPATH=$PWD PYTHONDONTWRITEBYTECODE=1 EMU_PYTHON=$HOME/esun-venv/bin/python \
    $HOME/esun-venv/bin/python tools/run_m6.py --out $HOME/m6-out --compile-to $HOME/p4build
```

`p4/build/esun_switch.json` is the compiled program the lab loads (committed, so bmv2 runs without compiling first); `tests/test_p4.py` checks it against the Scapy layers and checks the recorded bmv2 results. Lab details: `emu.lab.Lab(switch="bmv2")` starts one `simple_switch` per plane inside the plane's namespace (`docker run --network host --pid host -v /var/run/netns:/var/run/netns ... ip netns exec swP simple_switch`), loads the tables through `simple_switch_CLI`, and reads the counters at the end of a run.

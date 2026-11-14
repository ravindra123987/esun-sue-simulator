# M1 decisions and spec findings

Choices the specs leave open, which the Scapy layers (`sue/`), the dissector (`wireshark/sue.lua`) and the golden pcaps all follow. Each one is a constant in `sue/consts.py` or a dissector preference, so it can change when the spec does. An independent review of commit 83cf93d (2026-11-14) challenged several of them; its points are folded in below.

## Decisions

| # | Question | Decision | Basis | Where |
|---|---|---|---|---|
| D1 | ESUN EtherType (EH-ET) | `0x88B5` (IEEE 802 local experimental) | ESUN 1.0 §5.1: "pending assignment"; no public implementation uses a value (checked 2026-11-14) | `consts.ESUN_ETHERTYPE`, pref `sue.esun_ethertype` |
| D2 | What follows the ESUN header | RODL general header (12 B), **no** 2-byte `pds.entropy` field | SUE-T §8.3: the transport is "inferred by network wide configuration"; SUE-T Fig 9 draws ESUN followed directly by RODL. UEC §3.5.25.8 / Fig 3-119 puts `pds.entropy` "immediately after the UET EtherType" for RODL over traditional Ethernet, but ESUN has no UET EtherType and its flow label already provides entropy | `consts.ESUN_PAYLOAD` |
| D3 | UET CRC over ESUN | From the MAC DA; EH CoS, ECN (byte 14 & 0xE0) and TTL (byte 17 & 0x0F) masked; flow label kept; nothing appended | Mirrors the IP rule (skip fields switches rewrite). **Weak:** a VLAN tag added or removed in flight breaks it, and SUE-T Fig 9 / ESUN Fig (p11) draw the CRC as part of the transport PDU. Alternative to adopt when ESUN work resumes: Roff = start of the RODL header | `crc.esun_crc` |
| D4 | Minimum-size padding over ESUN | Pad to 56 B before the CRC (as UFH_16) | UEC §3.5.26.1 only defines it for UFH_16. **Conflict:** SUE-T Figs 9 and 10 (p24) draw `UET CRC | pad | FCS` (pad after the CRC). For UFH_16, UEC overrides that ("CRC always directly before the FCS"); for ESUN nothing does. Revisit with D3 | `frame._pad_to_min` |
| D5 | `psn_state` when syn=0 (UFH_16) | `psn_state[23:12]` = clear_psn_offset (12-bit signed), `[11:0]` = rev_cack_psn_lsb | UEC §3.5.22 item 4b (p421): "{pds.psn_state.clear_psn_offset, pds.psn_state.rev_cack_psn_lsb}; each field is 12 bits"; also §3.5.12.4.4 | `ufh.psn_state_syn0` |
| D6 | Where the hidden PSN goes in the CRC input when the frame is padded | **After** the pad, right before the CRC position | Fig 3-122 marks "crc_end for RODL" 4 bytes past the normal CRC end. **Ambiguous:** §3.5.26.1 step 2 says the PSN is appended "after the SES headers and payload", which read literally is before the pad, and Fig 3-122 draws no pad. Both readings are implemented; they differ only for padded frames (goldens 01, 03, 09–12 syn/short frames) | `consts.PSN_AFTER_PAD`, pref `sue.psn_before_pad` |
| D7 | Hidden PSN for non-RODL types over UFH_16 (ACK, NACK, CP) | Not appended | Fig 3-122: "crc end for all other PDS types" is the normal end | `frame.build_ufh16_ack` |
| D8 | Byte order of the UET CRC trailer | Big-endian | For: UEC "network byte order"; Wireshark `packet-uet.c` reads the trailer with `ENC_BIG_ENDIAN` (Keysight/Rivos), and our `crc32c` reproduces all 16 IPv4 frames of its `uet-generated-crc-encaps.pcap` that way (`tests/test_external_vectors.py`). Against: UEC's next sentence, "x³¹ term in the left-most bit of the first octet", is copied from IEEE 802.3 §3.2.9, where it describes the little-endian, LSB-first FCS; iSCSI (RFC 3720, cited by UEC) also stores CRC32C little-endian. The Wireshark capture is generated, not from hardware, so it shows agreement between tools, not silicon. Open until a hardware capture exists | `consts.CRC_BYTE_ORDER`, pref `sue.crc_le` |
| D9 | Byte order of the hidden PSN | Big-endian | Not stated; network order is the default elsewhere | `consts.PSN_BYTE_ORDER` |
| D10 | Payload carried by a request | Writes and vendor opcodes 0x30–0x3E carry `request_length` bytes. Atomics (0x03, 0x04) carry a 4-byte atomic header (after the extension header) and then `request_length` bytes of operands. Reads, no-ops and other codes carry none | UEC §3.4.3.5, Fig 3-20 / 3-22: "Payload for all atomic operations follow the atomic header". The atomic header is carried opaquely (not decoded) | `ses.request_wire_bytes`, `ses.atomic_hdr_bytes` |
| D11 | UFH 16-bit address container | `{dst_rsv(4), dst_addr(12)}` treated as one 16-bit address (the XPU id). The dissector's PDC key ignores the top nibble of the source ("src_addr / entropy") | Fig 3-120 labels | `ufh.UFH16RODL.dst/src`, `sue.lua` key |
| D12 | ACK `ack_psn` field (UFH_16) | Encoded as `ack_psn_offset`, a signed 16-bit offset from `cack_psn` | UEC §3.5.11.4.5 and Table 3-52; Table 3-45 names the field `ack_psn_offset / probe_opaque` (Fig 3-120 just says "ack_psn") | `frame.build_ufh16_ack`, `UFH16Ack.ack_psn` |
| D13 | Frames in pcaps | No Ethernet FCS | Normal capture format | all |

## Spec findings

1. **Fig 3-123 example is below the Ethernet minimum.** The left example (RODL read over UFH_32) adds up to 14 + 4 + 12 + 20 + 4 + 4 = 58 B, though every frame is padded to 64 B. Its PDS request is drawn as 4 B, while §3.5.25.8 says RODL over UFH_32 uses the 12 B header.
2. **ACK over UFH_16: 20 B or 2 B?** Fig 3-120 draws a 20 B ACK; Fig 3-123 (right) draws "PDS ACK: 2 B". Both reach 64 B with padding. We follow Fig 3-120.
3. **Padding wording.** §3.4.3.3 says "no padding before the UET CRC" (alignment padding of the last message); §3.5.26.1 adds padding before the CRC to reach 56 B (minimum size). Both are true; see D6 for the consequence.
4. **ACK field naming.** Fig 3-120 labels the field "ack_psn"; it is `ack_psn_offset` (D12). Easy to misencode.
5. **Hidden-PSN placement** is ambiguous for padded frames (D6).
6. **SUE-T vs UEC sizes.** SUE-T §6 (p12) calls the RODL header "8 bytes" (UEC: 12 B general; the compressed form over UFH_16 is folded into 16 B). SUE-T §7.2.1 (p17) says "UET_HDR_RESPONSE_LCL uses 8 bytes" (UEC: 4 B, Fig 3-28).
7. **SUE-T response opcode.** SUE-T uses a single response opcode, 0x2 (UET_RESPONSE_W_DATA) with payload_length = 0 for stores; UEC Fig 3-123 uses UET_RESPONSE (0x1). The goldens follow UEC; both decode.
8. **CRC byte order** (D8): UEC states it two ways.
9. **Wireshark** (`packet-uet.c`, UEC 1.0.1) decodes none of the UEC 1.1 frames; tshark 4.6.9 shows the UDP case as "Data". This is the M1b target.

## Review findings and what changed

| Review item | Outcome |
|---|---|
| A1 atomics framed 4 B short | Fixed in Python and Lua; golden 12 + test |
| A2 ACK ack_psn is an offset | Fixed (D12); Table 3-52 examples are tests |
| A3 CRC byte order | Kept big-endian, rationale rewritten with both sides (D8) |
| B1 hidden PSN before/after pad | Both readings implemented (D6) |
| B2/B3 ESUN CRC coverage and pad position | Recorded as weak/conflicting (D3, D4); revisit with ESUN work (not upstream-bound) |
| B4 pds.entropy over ESUN | Recorded (D2) |
| B5 psn_state citation | Fixed (D5) |
| B6 SUE-T size/opcode conflicts | Recorded (findings 6, 7) |
| C1 Lua errors on truncated input | Fixed by the rewrite (bounds checks, guarded dissection); fuzz test |
| C2 PSN tracking after retx/corruption | Fixed: CRC-based resync window (goldens 10, 11) |
| C3 PDC key includes the entropy nibble | Fixed (D11) |
| C4 snaplen, FCS, VLAN/IPv6, prefs | Snaplen → "not in capture"; Ethernet dissector now handles FCS (no more `wtap_encap` takeover); UDP CRC uses the IP/UDP header ranges (VLAN-safe; IPv6 → Unverified, not Bad); prefs re-register |
| C5 Python decode guards | Fixed (length check, EtherType check) |
| D1 tests blind to runtime Lua errors | `-V` check over all goldens + fuzz test |
| D2 Lua fields not compared | Every golden frame compares dst, src, spdcid, targets, cack_psn, ack_psn with Python |
| D3 missing tests | RODL general bytes, regeneration check |
| E nits | Full return-code table, UET_NO_RESPONSE, clear_psn_offset −1, 16-message limit, opcode 0x3F aligned, RODL syn split |

## Not covered yet

- UFH_32, NACK and control packets over UFH_16.
- Decoding the atomic header fields and the rendezvous extension.
- UET directly over IP (entropy header), and IPv6 CRC coverage.

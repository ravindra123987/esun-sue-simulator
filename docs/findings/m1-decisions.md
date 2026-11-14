# M1 decisions and spec findings

Choices the specs leave open, which the Scapy layers (`sue/`), the dissector (`wireshark/sue.lua`) and the golden pcaps all follow. Each one is a single constant in `sue/consts.py` or a dissector preference, so it can change when the spec does.

## Decisions

| # | Question | Decision | Basis | Where |
|---|---|---|---|---|
| D1 | ESUN EtherType (EH-ET) | `0x88B5` (IEEE 802 local experimental) | ESUN 1.0 §5.1 says "pending assignment"; no public implementation uses a value (checked 2026-11-14) | `consts.ESUN_ETHERTYPE`, Lua pref `sue.esun_ethertype` |
| D2 | What follows the ESUN header | RODL general header (12 B) | SUE-T §8.3: inferred by network-wide configuration | `consts.ESUN_PAYLOAD` |
| D3 | UET CRC over ESUN | Cover from the MAC DA; mask EH CoS, ECN (byte 14 & 0xE0) and TTL (byte 17 & 0x0F); keep the flow label; nothing appended (RODL general carries the PSN) | Mirrors the IP rule (skip fields switches rewrite) | `crc.esun_crc` |
| D4 | Minimum-size padding over ESUN | Same as UFH_16: pad to 56 B before the CRC | UEC §3.5.26.1 defines it for UFH_16 only | `frame._pad_to_min` |
| D5 | `psn_state` when syn=0 (UFH_16) | `psn_state[23:12]` = clear_psn_offset (12-bit signed), `psn_state[11:0]` = rev_cack_psn_lsb | Table 3-42 lists `{clear_psn_offset, rev_cack_psn_lsb}` in that order; §3.5.12.4.4 says rev_cack_psn_lsb is 12 bits over UFH_16, leaving 12 for clear_psn_offset | `ufh.psn_state_syn0` |
| D6 | Where the hidden PSN goes in the CRC input | After any minimum-size padding, right before the CRC position | Fig 3-122 marks "crc_end for RODL" 4 bytes past the normal CRC end, adjacent to the UET CRC | `crc.ufh16_crc` |
| D7 | Hidden PSN for non-RODL types over UFH_16 (ACK, NACK, CP) | Not appended | Fig 3-122: "crc end for all other PDS types" is the normal end | `frame.build_ufh16_ack` |
| D8 | Byte order of the UET CRC trailer | Big-endian | UEC §3.5.26: "network byte order, x³¹ term in the left-most bit of the first octet". iSCSI writes CRC32C little-endian, so this needs a real test vector | `consts.CRC_BYTE_ORDER`, Lua pref `sue.crc_le` |
| D9 | Byte order of the hidden PSN | Big-endian | Not stated; network order is the default elsewhere | `consts.PSN_BYTE_ORDER` |
| D10 | Payload carried by a request | Writes and vendor opcodes carry `request_length` bytes; reads and no-ops carry none; atomics are carried as opaque `request_length` bytes for now | Reads return data in the response. The atomic header (Fig 3-20) is not decoded in M1 | `ses.request_wire_bytes` |
| D11 | UFH 16-bit address container | `{dst_rsv(4), dst_addr(12)}` treated as one 16-bit address (the XPU id) | Fig 3-120 labels the nibble "dest_addr / rsv" and "src_addr / entropy" | `ufh.UFH16RODL.dst/src` |
| D12 | Frames in pcaps | No Ethernet FCS | Normal capture format | all |

## Spec findings from M1

1. **Fig 3-123 example is below the Ethernet minimum.** The left example (RODL read over UFH_32) adds up to 14 + 4 + 12 + 20 + 4 + 4 = 58 B, but the rule two paragraphs earlier pads every frame to 64 B. Its PDS request is also drawn as 4 B, while §3.5.25.8 says RODL over UFH_32 uses the 12 B header.
2. **ACK over UFH_16: 20 B or 2 B?** Fig 3-120 draws a 20 B ACK (with ack_psn and cack_psn). The right example in Fig 3-123 draws "PDS ACK: 2 B". Both reach 64 B with padding, so the frame size doesn't tell them apart. We follow Fig 3-120.
3. **Padding wording.** §3.4.3.3 says "no padding before the UET CRC" (meaning the 4-byte alignment padding of the last message), while §3.5.26.1 adds padding before the CRC to reach 56 B. Both are true; the first is about alignment, the second about minimum size.
4. **rev_cack_psn_lsb width is only in prose.** Table 3-42 gives psn_state as 24 bits without the split; the 12-bit width is only stated in §3.5.12.4.4 (see D5).
5. **Wireshark** (`packet-uet.c`, UEC 1.0.1) decodes none of these frames; tshark 4.6.9 shows the UDP case as "Data". This is the M1b contribution target.

## Not covered yet

- UFH_32 (multi-hop variant), NACK and control packets over UFH_16.
- The atomic header (Fig 3-20) and the rendezvous extension.
- UET entropy header for UET directly over IP (no UDP).

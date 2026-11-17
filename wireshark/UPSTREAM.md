# Porting sue.lua into Wireshark (M1b)

How the Lua prototype maps onto a C change to `epan/dissectors/packet-uet.c` (and `packet-macctrl.c` for CBFC). Nothing here has been posted upstream.

## Where things stand upstream (checked 2026-11-14)

- `packet-uet.c` was merged 2025-12-18 (MR !22094, Keysight + Rivos), written against UEC 1.0.1, maintained since (last change 2026-11-13).
- It registers on `udp.port` 4793 and `ip.proto` (decode-as), handles PDS types 1–14, the standard SES headers, TSS, and the UET CRC over IP. Its CRC check uses `tvb_get_ds_tvb()` + `tvb_raw_offset()` to reach the IP header and reads the trailer with `ENC_BIG_ENDIAN`.
- Test: `test/suite_dissection.py::TestDissectUltraEthernet::test_uet_crc` with `test/captures/uet-generated-crc-encaps.pcap` (48 frames, all good CRCs). Our `sue/crc.py` reproduces all 16 IPv4 frames in that file (`tests/test_external_vectors.py`).
- No open MR or issue mentions UEC 1.1, RODL, UFH or Unified Local.

## Design choices for the C port

| Topic | Lua prototype | C port |
|---|---|---|
| UFH hook | `ethertype` 0xE790; UFH bits re-read from `eth.dst` / `eth.src` field ranges | `dissector_add_uint("ethertype", ETHERTYPE_UET, uet_ufh_handle)`; read DA/SA via `tvb_get_ds_tvb(tvb)` at `tvb_raw_offset(tvb) - 14` (same technique the IP CRC already uses). Check `pinfo->dl_dst` is AT_ETHER first. Add `ETHERTYPE_UET` to `etypes.h` |
| UFH recognition | byte 0: v=0, SLAP AAI (z=y=0), x=1; w=1 → UFH_16 | Same; w=0 (UFH_32) → expert "not decoded" until implemented |
| Address columns | `cols.src/dst = "ufh:0001"` | `set_address(&pinfo->src, AT_STRINGZ, ...)` or a small UFH address type, so conversations/endpoints work |
| PDS type 15 | `sue.pds.type` table | add `UET_PDS_TYPE_RODL_REQ 15` to the existing value_strings; dispatch to `dissect_pds_rodl()` (general) and `dissect_pds_rodl_ufh16()` |
| RODL flags | separate masked fields | new `hf_uet_pds_flags_cack`, `hf_uet_pds_flags_rsvd_rodl`; reuse `hf_uet_pds_flags_retx/ar/syn` |
| SES LCL | `sue.ses.lcl.*` | new `dissect_ses_req_lcl()` / `dissect_ses_rsp_lcl()` on `next_hdr` 0x07 / 0x08, reusing `hf_uet_ses_opcode`, `..._ver`, `..._dc`, `..._ie`, `..._jobid`, `..._return_code`; new hf for ac, mm, rle, ehl, address (FT_UINT64 mask 0x0FFFFFFFFFFFFFFF), address_offset (FT_INT32), generated target address |
| CRC over UFH_16 | mask byte 7, append PSN after padding (RODL only) | `crc32c_calculate_no_swap()` over the ds tvb from the UFH start, a zeroed copy of byte 7, then the 4 PSN bytes; `proto_tree_add_checksum(..., ENC_BIG_ENDIAN, ...)` |
| Hidden PSN | Lua tables keyed by {src, dst, spdcid}; per-frame result cached | `wmem_map` in file scope keyed by {UFH src, UFH dst, spdcid}; per-frame result via `p_add_proto_data(wmem_file_scope(), ...)` so revisits are stable; reset in a `register_init_routine` |
| PSN resync | try ±window from the expected PSN on mismatch; register reuse makes it cheap | same (save the CRC register before the PSN bytes); preference `uet.rodl_psn_window`; expert infos in the `PI_SEQUENCE` group |
| Unknown PSN | status "Unverified" + preference `assume_psn` | `PROTO_CHECKSUM_NOT_PRESENT`-style unverified status; keep the preference |
| ESUN | Lua only, EtherType preference | **not upstream** until IEEE assigns EH-ET (Wireshark won't register a made-up EtherType); could be offered as a decode-as later |
| CBFC CC_Update | decoded in Lua (inside the emulator's 0x88B6 link-layer shim, M4) | `packet-macctrl.c`: opcode 0xFFFE (extension), CID FA-7A-CB, msg type 1/2, 16 × 20-bit S_VC_CC |

## Field names

The Lua names are the C names with `sue.` for `uet.`, so the port is mechanical:

| Lua | C (existing → reuse, new → add) |
|---|---|
| `sue.pds.type`, `sue.pds.nh`, `sue.pds.flags.retx/ar/syn`, `sue.pds.psn`, `sue.pds.spdcid`, `sue.pds.dpdcid`, `sue.pds.psn_offset`, `sue.pds.clear_psn_offset`, `sue.pds.ack_psn`, `sue.pds.cack_psn` | existing `uet.pds.*` |
| `sue.ses.opcode`, `sue.ses.ver`, `sue.ses.dc`, `sue.ses.ie`, `sue.ses.jobid`, `sue.ses.return_code` | existing `uet.ses.*` (check value_strings for LCL opcodes) |
| `sue.crc`, `sue.crc.status` | existing `uet.crc`, `uet.crc.status` |
| `sue.ufh.*`, `sue.pds.rodl.*`, `sue.pds.flags.cack`, `sue.pds.pdc_info`, `sue.ses.lcl.*`, `sue.ses.rsp.*`, `sue.pds.rodl.expected_psn`, `sue.pds.rodl.psn_gap` | new |

## MR plan

Each MR is small, has a test capture under `test/captures/` and a test in `test/suite_dissection.py`, and cites the UEC 1.1 figure for every field.

1. **RODL + Unified Local SES over UDP/IP.** pds.type 15 general header, next_hdr 0x07/0x08, packing. Capture: `pcaps/golden/08-udp-rodl-two-stores.pcap`. Existing CRC code already covers it.
2. **UFH_16.** EtherType 0xE790 registration, compressed RODL request and ACK, CRC over UFH_16 with the hidden PSN, PSN tracking + resync, preferences. Captures: golden 01–06, 09–11. Test: all CRC statuses as in `golden.json` (Good everywhere except the deliberate bit flip).
3. **CBFC CC_Update** in `packet-macctrl.c`. Real CC_Update frames are in the emulator's captures (`pcaps/emu/*.pcap`, inside the 0x88B6 shim; M4); a bare golden capture is one `emu.shim.cc_update_frame()` call away.

Before MR 1: open an issue describing the plan, link the UEC 1.1 sections, and mention the `packet-uet.c` authors. Draft in [docs/upstream/wireshark-issue-draft.md](../docs/upstream/wireshark-issue-draft.md).

## Open questions for the maintainers

- The hidden PSN makes CRC verification depend on earlier frames. Is a per-PDC tracker with a resync window acceptable, or should UFH_16 syn=0 frames only verify when the user supplies the PSN?
- UFH frames look like Ethernet frames with locally administered MACs. Should the Ethernet dissector learn UFH (so its own tree shows UFH fields instead of MACs), or is a UET subtree under EtherType 0xE790 enough?
- Prefer the UFH address as a new address type (for Conversations/Endpoints), or keep it as fields only?

## Rules

Personal time and identity, public specs only. Check the employer's open-source policy first. Nothing is posted (issue or MR) without explicit approval.

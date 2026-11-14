# sue.lua

A Wireshark Lua dissector for what the built-in `packet-uet.c` (UEC 1.0.1) does not decode yet: UFH_16, RODL, the Unified Local SES headers, the ESUN header, and the UET CRC in all three layouts. It is the prototype for the M1b upstream contribution.

## Use

```
# one-off
tshark -X lua_script:wireshark/sue.lua -r pcaps/golden/02-ufh16-rodl-two-stores.pcap -V

# permanently: copy into the personal Lua plugins folder
#   macOS/Linux: ~/.local/lib/wireshark/plugins/
```

## How it hooks in

Structured like the planned C change to `packet-uet.c` (see [UPSTREAM.md](UPSTREAM.md)):

- **UFH_16** is registered on EtherType 0xE790. The Ethernet dissector still runs (so FCS handling, VLANs and its preferences apply); `sue.lua` re-reads the UFH bits from the `eth.dst` / `eth.src` field ranges and recognises UFH from the first DA octet (v=0, SLAP AAI, local). The Source/Destination columns show the UFH addresses (`ufh:0001`).
- **ESUN** is registered on the EtherType preference (default 0x88B5).
- **RODL over UDP** is registered on UDP port 4793 and only claims PDS type 15; newer Wireshark builds with `packet-uet.c` handle the other types.
- Field names mirror `packet-uet.c` (`sue.pds.type` ↔ `uet.pds.type`), and bit fields use masks, so Wireshark highlights individual bits.
- Every frame is dissected under `pcall` with explicit bounds checks: truncated or inconsistent frames get a "Malformed" expert item, never a Lua error.

## Preferences

| Preference | Default | Purpose |
|---|---|---|
| `sue.esun_ethertype` | 0x88B5 | ESUN EH-ET is unassigned |
| `sue.udp_port` | 4793 | UET over UDP |
| `sue.assume_psn` | (empty) | PSN for a syn=0 frame whose PDC had no syn=1 in the capture |
| `sue.psn_window` | 64 | How far from the expected PSN to search on a CRC mismatch (0 = off) |
| `sue.psn_before_pad` | false | Put the hidden PSN right after the SES payload instead of after the padding (m1-decisions D6) |
| `sue.crc_le` | false | Read the UET CRC little-endian instead of big-endian (D8) |

## The hidden PSN

Over UFH_16 a syn=0 RODL frame does not carry its PSN; it is folded into the UET CRC. The dissector keeps the expected PSN per {source address (without the entropy nibble), destination, source PDCID}, starting from the last syn=1 frame:

- **Good**: the CRC matches the expected PSN.
- **Good + gap N**: it matches PSN = expected + N. N > 0 means frames were lost (expert warning); N < 0 means a Go-Back-N retransmission (expert note). Tracking resynchronises.
- **Bad**: no PSN within the window matches: corruption.
- **Unverified**: no syn=1 was seen and `sue.assume_psn` is not set, or the frame was cut by the snap length.

## Display filters

`sue.pds.type == 15`, `sue.ses.opcode == 1`, `sue.crc.status == 1` (bad CRC), `sue.pds.rodl.psn_gap > 0` (lost frames), `sue.esun.flow_label`, `sue.ses.lcl.target`, `_ws.expert.group == "Sequence"`.

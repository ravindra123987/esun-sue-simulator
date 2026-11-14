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

- UFH_16 reuses the MAC DA/SA bytes, so the Ethernet dissector would show garbage addresses. `sue.lua` registers on `wtap_encap` for Ethernet, recognises UFH_16 from the first DA octet (v=0, w=1, SLAP AAI, local) plus EtherType 0xE790, and decodes the whole frame itself. Every other frame goes to the stock `eth_withoutfcs` dissector.
- ESUN is registered on the EtherType preference (default 0x88B5).
- RODL over UDP is registered on UDP port 4793. Newer Wireshark builds with `packet-uet.c` also claim 4793; the Lua registration overrides it.

## Preferences

| Preference | Default | Purpose |
|---|---|---|
| `sue.esun_ethertype` | 0x88B5 | ESUN EH-ET is unassigned |
| `sue.udp_port` | 4793 | UET over UDP |
| `sue.assume_psn` | (empty) | PSN to use for a syn=0 frame when no syn=1 was seen for its PDC |
| `sue.crc_le` | false | Read the UET CRC little-endian (iSCSI style) instead of big-endian |

## UET CRC status

- **Good / Bad**: computed and compared.
- **Unverified**: a syn=0 RODL frame over UFH_16 whose PSN is unknown. The PSN is never on the wire, so the dissector tracks the expected PSN per {src, dst, spdcid}, starting from the last syn=1 frame. After a lost frame the tracked value is off by one and later frames show Bad; this is the open question for the upstream version.

## Display filters

`sue.pds.type == 15`, `sue.ses.opcode == 1`, `sue.crc.status == 1` (bad CRC), `sue.esun.flow_label`, `sue.ses.target`.

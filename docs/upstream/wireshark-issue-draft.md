# DRAFT: Wireshark issue (not posted)

**Status:** draft for review. Do not post until approved, and until the employer open-source policy has been checked.
**Where:** https://gitlab.com/wireshark/wireshark/-/issues (label: "dissector", "enhancement")

---

**Title:** UET: support UEC 1.1 Unified Local profile (RODL, UFH_16, LCL semantic headers)

**Body:**

The UET dissector (`packet-uet.c`, MR !22094) follows UE Specification 1.0.1. UE Specification 1.1 (released 2026-10-12, ultraethernet.org) adds a "Unified Local" profile for scale-up fabrics that the dissector does not decode yet. It is also the transport of the OCP SUE-T base specification 1.0.0 (2026-10-08).

What's new in 1.1 that a capture would contain:

1. **PDS type 15, RODL request** (UE 1.1 §3.5.10.5, Figure 3-67): a 12-byte header with a `cack` flag that switches a 16-bit field between `clear_psn_offset` and the reverse-direction CACK PSN.
2. **Unified Local semantic headers** (§3.4.3.3, Figures 3-17, 3-19, 3-28): `next_hdr` 0x07 `UET_HDR_REQUEST_LCL` (12-byte form with a 60-bit address, and an 8-byte address-compressed form chained by a 32-bit offset) and 0x08 `UET_HDR_RESPONSE_DATA_LCL` (4 bytes). Several requests are packed into one packet with an `mm` (more messages) bit and 4-byte alignment.
3. **UFH_16** (§5.4, Figures 3-68, 3-120): a header that overlays the MAC DA/SA with 16-bit addresses and the PDS fields, followed by EtherType 0xE790. Over UFH_16 the PSN is not sent after connection setup; it is folded into the UET CRC (§3.5.26.1: dscp/ecn masked, the expected PSN appended at the end of the CRC input).

I have a Lua prototype that decodes all three, plus a set of hand-built captures checked against the spec figures and worked examples (Table 3-14 address offsets, Figure 3-123 padding). The CRC code reproduces `test/captures/uet-generated-crc-encaps.pcap` for IPv4. I'd like to port it to `packet-uet.c` in two MRs:

- MR 1: RODL + LCL semantic headers (reachable over UDP 4793 today).
- MR 2: UFH_16 on EtherType 0xE790, including CRC verification with the hidden PSN.

Questions before I start:

- For UFH_16, verifying the CRC needs the PSN, which only the first (syn=1) packet of a connection carries. My prototype tracks the expected PSN per {src, dst, source PDC id} and, on a mismatch, tries nearby PSNs, which also reveals lost packets and Go-Back-N retransmissions. Is that acceptable here, or would you prefer verification only when the user supplies a starting PSN in a preference?
- UFH frames are Ethernet frames whose "MAC addresses" are UFH fields. Is a UET subtree under EtherType 0xE790 the right place, or should the Ethernet dissector be taught about UFH?

@alexbadea (and co-authors of !22094): happy to coordinate if you already have 1.1 work in progress.

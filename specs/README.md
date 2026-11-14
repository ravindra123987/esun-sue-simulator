# Specs

These are local reference copies of public specs, downloaded on 2026-11-13. The PDFs are git-ignored and are not redistributed; get them again from the source URLs below.

| File | What it is | Version / date | Source |
|---|---|---|---|
| `sue-t-base-spec-v1.0.0.pdf` | **SUE-T**: Scale-Up Ethernet Transport, the endpoint transport (OCP) | 1.0.0, effective 2026-10-08 (Broadcom + Arista), 33 pp | <https://www.opencompute.org/wp-content/uploads/2026/10/Scale-Up-Ethernet-Transport-SUE-T-Base-Specification-v1.0.0.pdf> |
| `broadcom-sue-framework-rm104.pdf` | Broadcom's original **SUE** framework spec (includes SUE-Lite), the seed for SUE-T | Scale-Ethernet-RM104, 2025-09-26, 34 pp | <https://docs.broadcom.com/doc/scale-up-ethernet-framework> |
| `uec-spec-1.1.pdf` | **Ultra Ethernet Specification 1.1**. SUE-T reference [2]: RODL, Unified Local profile, UET CRC, LLR, CBFC, UFH | 1.1, released 2026-10-12, 764 pp, CC BY-ND 4.0 | <https://ultraethernet.org/specification> |
| `uec-spec-1.1-release-notes.pdf` | What changed from 1.0.3 to 1.1 (Unified Local / RODL are new in 1.1) | 1.1 | same page |
| `esun-network-operator-requirements-rev1.0.pdf` | **ESUN 1.0**: "OCP ESUN – Network Operator Requirements – Base Specification Rev 1.0" (Meta + Microsoft). 4-byte ESUN header, PFC/CBFC/LLR requirements | 1.0, effective 2026-02-09, 16 pp | <https://www.opencompute.org/documents/ocp-esun-network-operator-requirements-base-specification-rev-1-0-final-pdf> (downloaded manually) |
| `esun-1.0-overview-ieee-2026-04.pdf` | ESUN 1.0 overview slides (Meta/Microsoft) presented to IEEE 802.1/802.3 | April 2026, 16 slides | <https://www.ieee802.org/3/minutes/may26/incoming/> |

## Still to download manually (Cloudflare blocks scripted downloads)

Open these in a browser and save them here:

- [x] **ESUN 1.0 spec**, downloaded 2026-11-13 (see table).
- [ ] *(optional)* The OCP copy of the SUE spec (2025-08-01). It is older than the Broadcom RM104 copy we have, so download it only if you need the OCP-contributed text.
  <https://www.opencompute.org/documents/ocp-sue-spec-final-pdf-1/>
- [ ] *(optional)* AMBA AXI4 spec (SUE-T §8.4.2 maps onto it): <https://developer.arm.com/documentation/ihi0022/latest>

## How the documents relate

```
 XPU (GPU/accelerator)
   │  AXI4 / signal command interface        ← SUE-T §8
 ┌─┴──────────────────────────────────┐
 │ SUE-T  (endpoint transport)        │  queues per {dstXPU,TC}, packing, ACK modes,
 │                                    │  load balancing                ← SUE-T §6–7
 │   uses UEC 1.1 "Unified Local"     │  SES headers                   ← UEC §3.4.3.3
 │   + RODL reliable ordered delivery │  PDS RODL, PSN, ACK/NACK       ← UEC §3.5.7.3, §3.5.25.8–9
 │   + UET CRC                        │                                ← UEC §3.5.26
 └─┬──────────────────────────────────┘
   │  ESUN header / UFH (L2/L3 framing)      ← ESUN 1.0 spec; UEC §5.4 (UFH)
 ┌─┴──────────────────────────────────┐
 │ Ethernet link: LLR (optional),     │  ← UEC §5.1 LLR, §5.2 CBFC, §5.3 link negotiation
 │ PFC or CBFC                        │
 └────────────────────────────────────┘
```

## ESUN header vs UFH (answered from ESUN 1.0 §5.1–5.2)

They are **separate** designs. Both drop the IP header, in different ways:

| | ESUN | UFH_16 (UEC §5.4) |
|---|---|---|
| MAC addresses | Standard 48-bit DA/SA. Switches forward on statically configured DAs: no learning, no flooding of unknown DAs | Overlaid: 16-bit address containers inside DA/SA, SLAP bits mark the frame as UFH |
| Extra header | 4-byte EH after a new EtherType (EH-ET, **value pending assignment**) | None. Fields live in DA/SA opaque bits, EtherType 0xE790 = UET |
| L2+L3+RODL bytes | 6+6+2+4 = 18, + RODL 12 = **30 B** | **16 B** (RODL folded into the opaque bits) |
| Multi-hop | Yes: EH-TTL, EH-ECN, flow label | Optimized for a single hop (UFH_32 for multi-hop) |

ESUN header layout (32 bits, network order):
`Rev(2) | F(1) | EH-CoS(3) | EH-ECN(2) | Flow label(16) | TTL(4) | UD(2) | RSVD(2)`

- **F**: flow label is valid, so switches hash {DA, SA, flow label} and forward deterministically.
- **EH-CoS**: 3-bit CoS, like 802.1p, replacing DSCP and VLAN. It takes precedence over 802.1Q or CBFC CoS.
- **TTL**: decremented per hop, dropped at 0. Rewriting TTL or ECN means the FCS must be recomputed.
- **UD**: end-to-end bits for the transport.

Requirements (ESUN §7): PFC required. CBFC and LLR are required on switches, optional on hosts. EH-ECN, EH-CoS, F + flow label and EH-TTL are required. Security is MACsec only; ESUN is not IPsec-compatible.

Gaps for the emulator:
- UET CRC coverage over ESUN is undefined: UEC starts it at the IP source address or at UFH.
- It's unclear whether the 2-byte UET entropy field follows EH-ET.
- ESUN cites UEC 1.0.2, while SUE-T cites UEC 1.1.
- EH-ET has no value yet, and as of 2026-11-14 no public implementation uses one. The transport after the EH is set by fabric-wide configuration (SUE-T §7). The emulator uses 0x88B5 + `ESUN_PAYLOAD=rodl` (see plan.md open questions).

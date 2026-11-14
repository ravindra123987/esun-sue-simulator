"""UFH_16 with the PDS header folded into its opaque bits (UEC 1.1 §5.4, Fig 3-68, Fig 3-120).

RODL request over UFH_16, 16 bytes (Fig 3-68 / 3-120):
  byte 0-3   flags(4) da_encode(4) | type(5) next_hdr(4) retx ar syn | dpdcid(12)
  byte 4-7   dst_rsv(4) dst_addr(12) | psn_state_hi(4) sa_encode(4) | dscp(6) ecn(2)
  byte 8-11  psn_state_mid(4) spdcid(12) | src_entropy(4) src_addr(12)
  byte 12-15 EtherType 0xE790 | psn_state_low(16)

ACK over UFH_16, 20 bytes (Fig 3-120):
  byte 0-3   flags(4) da_encode(4) | type(5) next_hdr(4) flags(7) | dpdcid[11:4](8)
  byte 4-7   dst_rsv(4) dst_addr(12) | rsvd(4) sa_encode(4) | dscp(6) ecn(2)
  byte 8-11  dpdcid[3:0](4) spdcid(12) | src_entropy(4) src_addr(12)
  byte 12-15 EtherType 0xE790 | ack_psn_offset / probe_opaque(16, signed; ACK_PSN = CACK_PSN + offset, §3.5.11.4.5)
  byte 16-19 cack_psn(32)

ufh.flags = [v, w, rsvd, rsvd]; da/sa_encode = [z, y, x, m] (Table 5-40).
The 16-bit address container is {dst_rsv(4), dst_addr(12)}: the figure labels
the top nibble "dest_addr / rsv" and, for the source, "src_addr / entropy".
"""

from scapy.fields import BitEnumField, BitField, XShortField
from scapy.packet import Packet

from .. import consts as C
from .ses import ses_class_for


class UFH16RODL(Packet):
    name = "UFH_16 + RODL request"
    fields_desc = [
        BitField("v", C.UFH_V, 1),
        BitField("w", C.UFH_W_16, 1),
        BitField("rr", 0, 2),
        BitField("da_encode", C.UFH_ENCODE_UNICAST, 4),
        BitEnumField("type", C.PDS_TYPE_RODL, 5, C.PDS_TYPE),
        BitEnumField("next_hdr", C.NH_REQUEST_LCL, 4, C.NEXT_HDR),
        BitField("retx", 0, 1),
        BitField("ar", 0, 1),
        BitField("syn", 0, 1),
        BitField("dpdcid", 0, 12),          # syn=1: {pdc_info(2), psn_offset(10)}
        BitField("dst_rsv", 0, 4),
        BitField("dst_addr", 0, 12),
        BitField("psn_state_hi", 0, 4),
        BitField("sa_encode", C.UFH_ENCODE_UNICAST, 4),
        BitField("dscp", 0, 6),
        BitField("ecn", 0, 2),
        BitField("psn_state_mid", 0, 4),
        BitField("spdcid", 0, 12),
        BitField("src_entropy", 0, 4),
        BitField("src_addr", 0, 12),
        XShortField("ethertype", C.ETHERTYPE_UET),
        BitField("psn_state_low", 0, 16),
    ]

    # --- derived views ---------------------------------------------------
    @property
    def psn_state(self) -> int:
        return (self.psn_state_hi << 20) | (self.psn_state_mid << 16) | self.psn_state_low

    @property
    def explicit_psn(self) -> int | None:
        """PSN carried on the wire, only when syn=1: PSN = {0x00, psn_state}."""
        return self.psn_state if self.syn else None

    @property
    def clear_psn_offset(self) -> int:
        """syn=0: upper 12 bits of psn_state, signed (DECISION, see m1-decisions.md)."""
        v = self.psn_state >> 12
        return v - (1 << 12) if v & 0x800 else v

    @property
    def rev_cack_psn_lsb(self) -> int:
        """syn=0: lower 12 bits of psn_state (UEC §3.5.12.4.4: 12 bits over UFH_16)."""
        return self.psn_state & 0xFFF

    @property
    def pdc_info(self) -> int:
        return self.dpdcid >> 10

    @property
    def psn_offset(self) -> int:
        return self.dpdcid & 0x3FF

    @property
    def dst(self) -> int:
        return (self.dst_rsv << 12) | self.dst_addr

    @property
    def src(self) -> int:
        return (self.src_entropy << 12) | self.src_addr

    def guess_payload_class(self, payload):
        return ses_class_for(self.next_hdr)


def split_psn_state(psn_state: int) -> dict:
    return {"psn_state_hi": (psn_state >> 20) & 0xF,
            "psn_state_mid": (psn_state >> 16) & 0xF,
            "psn_state_low": psn_state & 0xFFFF}


def psn_state_syn0(clear_psn_offset: int, rev_cack_psn_lsb: int) -> int:
    if not -2048 <= clear_psn_offset <= 0:
        raise ValueError("clear_psn_offset must fit 12-bit signed and is never positive (UEC §3.5.11)")
    return ((clear_psn_offset & 0xFFF) << 12) | (rev_cack_psn_lsb & 0xFFF)


class UFH16Ack(Packet):
    name = "UFH_16 + PDS ACK"
    fields_desc = [
        BitField("v", C.UFH_V, 1),
        BitField("w", C.UFH_W_16, 1),
        BitField("rr", 0, 2),
        BitField("da_encode", C.UFH_ENCODE_UNICAST, 4),
        BitEnumField("type", C.PDS_TYPE_ACK, 5, C.PDS_TYPE),
        BitEnumField("next_hdr", C.NH_NONE, 4, C.NEXT_HDR),
        BitField("flags", 0, 7),
        BitField("dpdcid_hi", 0, 8),
        BitField("dst_rsv", 0, 4),
        BitField("dst_addr", 0, 12),
        BitField("rsvd", 0, 4),
        BitField("sa_encode", C.UFH_ENCODE_UNICAST, 4),
        BitField("dscp", 0, 6),
        BitField("ecn", 0, 2),
        BitField("dpdcid_lo", 0, 4),
        BitField("spdcid", 0, 12),
        BitField("src_entropy", 0, 4),
        BitField("src_addr", 0, 12),
        XShortField("ethertype", C.ETHERTYPE_UET),
        BitField("ack_psn_offset_raw", 0, 16),
        BitField("cack_psn", 0, 32),
    ]

    @property
    def dpdcid(self) -> int:
        return (self.dpdcid_hi << 4) | self.dpdcid_lo

    @property
    def dst(self) -> int:
        return (self.dst_rsv << 12) | self.dst_addr

    @property
    def src(self) -> int:
        return (self.src_entropy << 12) | self.src_addr

    @property
    def ack_psn_offset(self) -> int:
        v = self.ack_psn_offset_raw
        return v - (1 << 16) if v & 0x8000 else v

    @property
    def ack_psn(self) -> int:
        """ACK_PSN = CACK_PSN + sign-extended ack_psn_offset (UEC Table 3-52)."""
        return (self.cack_psn + self.ack_psn_offset) & 0xFFFFFFFF

    def guess_payload_class(self, payload):
        return ses_class_for(self.next_hdr)


def is_ufh(frame: bytes) -> bool:
    """UFH is recognised by the first DA octet: v=0, z=y=0, x=1 (§5.4.3)."""
    if len(frame) < 14:
        return False
    b0 = frame[0]
    return (b0 & 0x80) == 0 and (b0 & 0x0E) == 0x02


def is_ufh16(frame: bytes) -> bool:
    return is_ufh(frame) and bool(frame[0] & 0x40)

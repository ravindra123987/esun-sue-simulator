"""RODL request, general format (UEC 1.1 §3.5.10.5, Fig 3-67, Table 3-41), 12 bytes.

  type(5) next_hdr(4) flags(7) | clear_psn_offset or rev_cack_psn_lsb(16)
  psn(32)
  spdcid(16) | dpdcid or {pdc_info(4), psn_offset(12)}(16)

flags = [rsvd, cack, retx, ar, syn, rsvd, rsvd] (Table 3-55). cack=1 means the
16-bit field carries the reverse-direction CACK_PSN low bits instead of
clear_psn_offset. Used over Ethernet/ESUN, UFH_32 and UDP/IP.
"""

from scapy.fields import BitEnumField, BitField
from scapy.packet import Packet

from .. import consts as C
from .ses import ses_class_for


class RODL(Packet):
    name = "PDS RODL request"
    fields_desc = [
        BitEnumField("type", C.PDS_TYPE_RODL, 5, C.PDS_TYPE),
        BitEnumField("next_hdr", C.NH_REQUEST_LCL, 4, C.NEXT_HDR),
        BitField("rsvd0", 0, 1),
        BitField("cack", 0, 1),
        BitField("retx", 0, 1),
        BitField("ar", 0, 1),
        BitField("syn", 0, 1),
        BitField("rsvd1", 0, 2),
        BitField("psn16", 0, 16),     # clear_psn_offset (cack=0) / rev_cack_psn_lsb (cack=1)
        BitField("psn", 0, 32),
        BitField("spdcid", 0, 16),
        BitField("dpdcid", 0, 16),
    ]

    @property
    def clear_psn_offset(self) -> int | None:
        if self.cack:
            return None
        v = self.psn16
        return v - (1 << 16) if v & 0x8000 else v

    @property
    def rev_cack_psn_lsb(self) -> int | None:
        return self.psn16 if self.cack else None

    @property
    def pdc_info(self) -> int | None:
        return self.dpdcid >> 12 if self.syn else None

    @property
    def psn_offset(self) -> int | None:
        return self.dpdcid & 0xFFF if self.syn else None

    def guess_payload_class(self, payload):
        return ses_class_for(self.next_hdr)

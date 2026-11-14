"""ESUN header (OCP ESUN 1.0 §5.2), 4 bytes after DA, SA and EH-EtherType.

  Rev(2) F(1) EH-CoS(3) EH-ECN(2) | FlowLabel(16) | TTL(4) UD(2) RSVD(2)

The EtherType is unassigned (ESUN §5.1); we use consts.ESUN_ETHERTYPE.
The EH has no next-header field. Per SUE-T §8.3 the payload type is set by
configuration; we bind the RODL general header (consts.ESUN_PAYLOAD).
"""

from scapy.fields import BitField
from scapy.packet import Packet

from .pds import RODL


class ESUN(Packet):
    name = "ESUN header"
    fields_desc = [
        BitField("rev", 0, 2),
        BitField("f", 1, 1),
        BitField("cos", 0, 3),
        BitField("ecn", 0, 2),
        BitField("flow_label", 0, 16),
        BitField("ttl", 15, 4),
        BitField("ud", 0, 2),
        BitField("rsvd", 0, 2),
    ]

    def guess_payload_class(self, payload):
        return RODL

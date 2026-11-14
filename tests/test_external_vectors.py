"""Check sue/crc.py against third-party UET frames (run tools/fetch_vectors.sh first).

Wireshark's test/captures/uet-generated-crc-encaps.pcap was produced by other
people's code and is verified by packet-uet.c, which reads the trailer
big-endian. Matching it pins the CRC32C algorithm, the IPv4 coverage start,
the zeroed UDP checksum and the trailer byte order (m1-decisions.md D8).
"""

from pathlib import Path

import pytest
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.utils import rdpcap

from sue import consts as C
from sue.crc import crc32c

VEC = Path(__file__).resolve().parent / "vectors" / "uet-generated-crc-encaps.pcap"


@pytest.mark.skipif(not VEC.exists(), reason="run tools/fetch_vectors.sh")
def test_wireshark_uet_ipv4_crcs():
    checked = 0
    for pkt in rdpcap(str(VEC)):
        raw = bytes(pkt)
        layers, layer = [], Ether(raw)
        while layer and layer.name != "NoPayload":
            layers.append(layer)
            layer = layer.payload
        ip = [x for x in layers if isinstance(x, (IP, IPv6))][-1]   # innermost IP carries UET
        if isinstance(ip, IPv6):
            continue                         # IPv6 coverage: not implemented in sue/ yet
        start = len(raw) - len(bytes(ip))
        ipb = raw[start:start + ip.len]
        m = bytearray(ipb[12:])              # from the IPv4 source address
        if isinstance(ip.payload, UDP) and ip.payload.dport == C.UDP_PORT_UET:
            cs = ip.ihl * 4 + 6 - 12
            m[cs:cs + 2] = b"\x00\x00"       # UDP checksum counts as zero
        wire = int.from_bytes(ipb[-4:], C.CRC_BYTE_ORDER)
        assert crc32c(bytes(m[:-4])) == wire
        checked += 1
    assert checked == 16                     # 2 plain + 6 tunnelled, with and without UDP

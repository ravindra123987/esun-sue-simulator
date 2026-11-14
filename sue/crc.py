"""UET CRC (UEC 1.1 §3.5.26): CRC32C with three coverage rules.

- IPv4/UDP: coverage starts at the IPv4 source address; the UDP checksum counts as 0.
- UFH_16: coverage starts at byte 0; dscp+ecn (byte 7) count as 0; for RODL
  requests the 32-bit expected PSN is appended at "crc_end" (Fig 3-122), i.e.
  after any minimum-size padding, right where the CRC sits.
- ESUN: not defined by any spec. DECISION: cover from the MAC DA, mask EH CoS,
  ECN and TTL (switches may rewrite them), keep the flow label. RODL over ESUN
  uses the general header, which carries the PSN, so nothing is appended.
"""

from . import consts as C

_POLY_REFLECTED = 0x82F63B78   # 0x1EDC6F41 reflected


def _table():
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ _POLY_REFLECTED if c & 1 else c >> 1
        t.append(c)
    return t


_T = _table()


def crc32c(data: bytes, crc: int = 0) -> int:
    """CRC32C (Castagnoli): init 0xFFFFFFFF, reflected, final complement."""
    c = crc ^ 0xFFFFFFFF
    for b in data:
        c = _T[(c ^ b) & 0xFF] ^ (c >> 8)
    return c ^ 0xFFFFFFFF


def crc_bytes(value: int) -> bytes:
    return value.to_bytes(4, C.CRC_BYTE_ORDER)


def ufh16_crc(body: bytes, psn: int | None, payload_end: int | None = None) -> int:
    """CRC over a UFH_16 frame body (UFH header .. last pad byte, no CRC, no FCS).

    psn: the 32-bit PSN to append (RODL requests). None for other PDS types (ACK, NACK, CP).
    payload_end: offset where the SES payload ends and minimum-size padding starts.
      Only used when consts.PSN_AFTER_PAD is False (the PSN then goes before the pad).
    """
    m = bytearray(body)
    m[C.UFH16_TC_BYTE] = 0                       # mask dscp + ecn
    if psn is not None:
        p = (psn & 0xFFFFFFFF).to_bytes(4, C.PSN_BYTE_ORDER)
        if C.PSN_AFTER_PAD or payload_end is None:
            m += p
        else:
            m[payload_end:payload_end] = p
    return crc32c(bytes(m))


def ipv4_udp_crc(frame: bytes, l2_len: int = 14) -> int:
    """CRC over an Ethernet/IPv4/UDP/UET frame (no CRC trailer, no FCS)."""
    ip = l2_len
    ihl = (frame[ip] & 0x0F) * 4
    m = bytearray(frame[ip + 12:])               # Roff = IPv4 source address
    udp_csum = ip + ihl + 6 - (ip + 12)
    m[udp_csum:udp_csum + 2] = b"\x00\x00"
    return crc32c(bytes(m))


ESUN_EH_OFFSET = 14


def esun_crc(frame: bytes) -> int:
    """CRC over an ESUN frame from the MAC DA (project DECISION, see module doc)."""
    m = bytearray(frame)
    eh = ESUN_EH_OFFSET
    m[eh] &= 0xE0          # keep Rev(2)+F(1); mask CoS(3)+ECN(2)
    m[eh + 3] &= 0x0F      # mask TTL(4); keep UD(2)+RSVD(2)
    return crc32c(bytes(m))

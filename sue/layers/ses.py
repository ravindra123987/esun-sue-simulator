"""Unified Local semantic (SES) headers, UEC 1.1 §3.4.3.3 and Table 3-19.

UET_HDR_REQUEST_LCL, ac=0 (Fig 3-17, 12 B):
    ac(1) mm(1) opcode(6) ver(2) dc(1) ie(1) jobid(8) request_length(12)
    rle(2) ehl(2) address(60)
UET_HDR_REQUEST_LCL, ac=1 (Fig 3-19, 8 B):
    ac(1) mm(1) opcode(6) ver(2) dc(1) ie(1) jobid(8) request_length(12)
    address_offset(32, two's complement, relative to the previous target address)
UET_HDR_RESPONSE_DATA_LCL (Fig 3-28, 4 B):
    rsv(1) mm(1) opcode(6) ver(2) return_code(6) ehl(2) payload_length(14)

Each header is followed by an optional extension header (4/8/16 B from ehl;
ac=1 inherits ehl from the previous ac=0 header), then its payload, zero-padded
to a 4-byte boundary. mm=1 means another SES header follows.
"""

from scapy.fields import BitEnumField, BitField, StrLenField
from scapy.packet import Packet, Raw

from .. import consts as C


def pad4(n: int) -> int:
    return (4 - n % 4) % 4


def request_wire_bytes(opcode: int, length: int) -> int:
    """Payload bytes after the SES header (+ extension header + atomic header).

    Writes and vendor opcodes (0x30-0x3E) carry `length` bytes. Atomics carry
    `length` bytes of operands after a 4-byte atomic header (§3.4.3.5).
    Reads and no-ops carry none (read data returns in the response).
    """
    if opcode in (C.OP_WRITE, C.OP_ATOMIC, C.OP_FETCHING_ATOMIC) or opcode in C.VENDOR_OPCODES:
        return length
    return 0


def atomic_hdr_bytes(opcode: int) -> int:
    return C.ATOMIC_HDR_LEN if opcode in (C.OP_ATOMIC, C.OP_FETCHING_ATOMIC) else 0


def _inherited_ehl(pkt) -> int:
    p = pkt.underlayer
    while p is not None:
        if isinstance(p, SESReqLcl0):
            return p.ehl
        p = p.underlayer
    return 0


def _next_request(payload: bytes):
    return SESReqLcl1 if payload and payload[0] & 0x80 else SESReqLcl0


class _SESBase(Packet):
    def default_payload_class(self, payload):
        return Raw


class SESReqLcl0(_SESBase):
    name = "UET SES Request LCL (ac=0)"
    fields_desc = [
        BitField("ac", 0, 1),
        BitField("mm", 0, 1),
        BitEnumField("opcode", C.OP_WRITE, 6, C.REQ_OPCODE),
        BitField("ver", 0, 2),
        BitField("dc", 0, 1),
        BitField("ie", 0, 1),
        BitField("jobid", 0, 8),
        BitField("request_length", 0, 12),
        BitField("rle", 0, 2),
        BitField("ehl", 0, 2),
        BitField("address", 0, 60),
        StrLenField("ext", b"", length_from=lambda p: C.EHL_BYTES[p.ehl]),
        StrLenField("atomic", b"", length_from=lambda p: atomic_hdr_bytes(p.opcode)),
        StrLenField("data", b"", length_from=lambda p: request_wire_bytes(p.opcode, p.length)),
        StrLenField("pad", b"", length_from=lambda p: pad4(request_wire_bytes(p.opcode, p.length))),
    ]

    @property
    def length(self) -> int:
        return (self.rle << 12) | self.request_length

    def guess_payload_class(self, payload):
        return _next_request(payload) if self.mm else Raw


class SESReqLcl1(_SESBase):
    name = "UET SES Request LCL (ac=1)"
    fields_desc = [
        BitField("ac", 1, 1),
        BitField("mm", 0, 1),
        BitEnumField("opcode", C.OP_WRITE, 6, C.REQ_OPCODE),
        BitField("ver", 0, 2),
        BitField("dc", 0, 1),
        BitField("ie", 0, 1),
        BitField("jobid", 0, 8),
        BitField("request_length", 0, 12),
        BitField("address_offset_raw", 0, 32),
        StrLenField("ext", b"", length_from=lambda p: C.EHL_BYTES[_inherited_ehl(p)]),
        StrLenField("atomic", b"", length_from=lambda p: atomic_hdr_bytes(p.opcode)),
        StrLenField("data", b"", length_from=lambda p: request_wire_bytes(p.opcode, p.request_length)),
        StrLenField("pad", b"", length_from=lambda p: pad4(request_wire_bytes(p.opcode, p.request_length))),
    ]

    @property
    def length(self) -> int:
        return self.request_length

    @property
    def address_offset(self) -> int:
        v = self.address_offset_raw
        return v - (1 << 32) if v & 0x80000000 else v

    def guess_payload_class(self, payload):
        return _next_request(payload) if self.mm else Raw


class SESRespLcl(_SESBase):
    name = "UET SES Response LCL"
    fields_desc = [
        BitField("rsv", 0, 1),
        BitField("mm", 0, 1),
        BitEnumField("opcode", C.RSP_DEFAULT_RESPONSE, 6, C.RSP_OPCODE),
        BitField("ver", 0, 2),
        BitEnumField("return_code", C.RC_OK, 6, C.RETURN_CODE),
        BitField("ehl", 0, 2),
        BitField("payload_length", 0, 14),
        StrLenField("ext", b"", length_from=lambda p: C.EHL_BYTES[p.ehl]),
        StrLenField("data", b"", length_from=lambda p: p.payload_length),
        StrLenField("pad", b"", length_from=lambda p: pad4(p.payload_length)),
    ]

    def guess_payload_class(self, payload):
        return SESRespLcl if self.mm else Raw


def ses_class_for(next_hdr: int):
    if next_hdr == C.NH_REQUEST_LCL:
        return SESReqLcl0
    if next_hdr == C.NH_RESPONSE_DATA_LCL:
        return SESRespLcl
    return Raw


def target_addresses(first) -> list[int]:
    """Resolve the chained target addresses of a packed request (Table 3-14)."""
    out, addr, p = [], 0, first
    while isinstance(p, (SESReqLcl0, SESReqLcl1)):
        if isinstance(p, SESReqLcl0):
            addr = p.address
        else:
            addr = (addr + p.address_offset) & ((1 << 60) - 1)
        out.append(addr)
        p = p.payload
    return out

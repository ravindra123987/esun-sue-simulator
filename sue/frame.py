"""Build and decode whole SUE-T frames: headers + packed SES messages + padding + UET CRC.

Frames are returned without the Ethernet FCS, as in a normal pcap.
"""

from dataclasses import dataclass, field

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw

from . import consts as C
from . import crc as K
from .layers import ESUN, RODL, SESReqLcl0, SESReqLcl1, SESRespLcl, UFH16Ack, UFH16RODL
from .layers import is_ufh16, psn_state_syn0, split_psn_state
from .layers.ses import pad4, request_wire_bytes


# --------------------------------------------------------------------------
# SES messages
# --------------------------------------------------------------------------
@dataclass
class Req:
    """One XPU command (CMD_PDU). For reads, `length` is the number of bytes requested."""
    opcode: int
    address: int
    data: bytes = b""
    length: int | None = None
    jobid: int = 0
    dc: int = 0
    ehl: int = 0
    ext: bytes = b""

    def __post_init__(self):
        if self.length is None:
            self.length = len(self.data)
        if request_wire_bytes(self.opcode, self.length) != len(self.data):
            raise ValueError(f"opcode {self.opcode:#x} with length {self.length} needs "
                             f"{request_wire_bytes(self.opcode, self.length)} data bytes, got {len(self.data)}")
        if len(self.ext) != C.EHL_BYTES[self.ehl]:
            raise ValueError("ext length must match ehl")
        if not 0 <= self.length < (1 << 14):
            raise ValueError("request length is 14 bits")


@dataclass
class Rsp:
    opcode: int = C.RSP_DEFAULT_RESPONSE
    return_code: int = C.RC_OK
    data: bytes = b""
    ehl: int = 0
    ext: bytes = b""


def pack_requests(reqs: list[Req], compress: bool = True) -> list[Packet]:
    """SES headers for a packed request (UEC §3.4.3.3).

    The first header is ac=0. A later header uses ac=1 when compression is on,
    its ehl equals the one inherited from the last ac=0 header, the offset fits
    32-bit two's complement and the length fits 12 bits.
    """
    out, prev_addr, inherited_ehl = [], None, 0
    for i, r in enumerate(reqs):
        mm = 1 if i < len(reqs) - 1 else 0
        pad = b"\x00" * pad4(len(r.data))
        off = None if prev_addr is None else r.address - prev_addr
        if (compress and off is not None and -(1 << 31) <= off < (1 << 31)
                and r.length < (1 << 12) and r.ehl == inherited_ehl):
            h = SESReqLcl1(mm=mm, opcode=r.opcode, dc=r.dc, jobid=r.jobid, request_length=r.length,
                           address_offset_raw=off & 0xFFFFFFFF, ext=r.ext, data=r.data, pad=pad)
        else:
            h = SESReqLcl0(mm=mm, opcode=r.opcode, dc=r.dc, jobid=r.jobid,
                           request_length=r.length & 0xFFF, rle=r.length >> 12, ehl=r.ehl,
                           address=r.address, ext=r.ext, data=r.data, pad=pad)
            inherited_ehl = r.ehl
        out.append(h)
        prev_addr = r.address
    return out


def pack_responses(rsps: list[Rsp]) -> list[Packet]:
    return [SESRespLcl(mm=1 if i < len(rsps) - 1 else 0, opcode=r.opcode, return_code=r.return_code,
                       ehl=r.ehl, payload_length=len(r.data), ext=r.ext, data=r.data,
                       pad=b"\x00" * pad4(len(r.data)))
            for i, r in enumerate(rsps)]


def _ses_bytes(msgs: list[Packet]) -> bytes:
    return b"".join(bytes(m) for m in msgs)


def _pad_to_min(body: bytes) -> bytes:
    return body + b"\x00" * max(0, C.MIN_BODY_BEFORE_CRC - len(body))


# --------------------------------------------------------------------------
# UFH_16
# --------------------------------------------------------------------------
@dataclass
class PDC:
    """The state a sender needs for one RODL PDC over UFH_16."""
    dst: int                 # 16-bit destination address container (e.g. dst XPU id)
    src: int
    spdcid: int
    dpdcid: int
    psn: int
    dscp: int = 0
    ecn: int = 0
    clear_psn_offset: int = 0
    rev_cack_psn_lsb: int = 0
    extra: dict = field(default_factory=dict)


def ufh16_rodl_header(pdc: PDC, next_hdr: int, syn: int = 0, ar: int = 0, retx: int = 0,
                      pdc_info: int = 0) -> UFH16RODL:
    if syn:
        psn_state = pdc.psn & 0xFFFFFF          # PSN = {0x00, psn_state} (Table 3-42)
        if pdc.psn >> 24:
            raise ValueError("with syn=1 the PSN must fit 24 bits")
        dpd = ((pdc_info & 0x3) << 10) | (pdc.extra.get("psn_offset", 0) & 0x3FF)
    else:
        psn_state = psn_state_syn0(pdc.clear_psn_offset, pdc.rev_cack_psn_lsb)
        dpd = pdc.dpdcid
    return UFH16RODL(next_hdr=next_hdr, retx=retx, ar=ar, syn=syn, dpdcid=dpd,
                     dst_rsv=pdc.dst >> 12, dst_addr=pdc.dst & 0xFFF,
                     dscp=pdc.dscp, ecn=pdc.ecn, spdcid=pdc.spdcid,
                     src_entropy=pdc.src >> 12, src_addr=pdc.src & 0xFFF,
                     **split_psn_state(psn_state))


def build_ufh16_rodl(pdc: PDC, msgs: list[Packet], next_hdr: int = C.NH_REQUEST_LCL, **kw) -> bytes:
    body = _pad_to_min(bytes(ufh16_rodl_header(pdc, next_hdr, **kw)) + _ses_bytes(msgs))
    return body + K.crc_bytes(K.ufh16_crc(body, pdc.psn))


def build_ufh16_ack(dst: int, src: int, spdcid: int, dpdcid: int, ack_psn: int, cack_psn: int,
                    msgs: list[Packet] | None = None, dscp: int = 0, flags: int = 0) -> bytes:
    msgs = msgs or []
    hdr = UFH16Ack(next_hdr=C.NH_RESPONSE_DATA_LCL if msgs else C.NH_NONE, flags=flags,
                   dpdcid_hi=dpdcid >> 4, dpdcid_lo=dpdcid & 0xF, dst_rsv=dst >> 12, dst_addr=dst & 0xFFF,
                   dscp=dscp, spdcid=spdcid, src_entropy=src >> 12, src_addr=src & 0xFFF,
                   ack_psn=ack_psn & 0xFFFF, cack_psn=cack_psn & 0xFFFFFFFF)
    body = _pad_to_min(bytes(hdr) + _ses_bytes(msgs))
    return body + K.crc_bytes(K.ufh16_crc(body, None))     # no PSN for non-RODL types (Fig 3-122)


# --------------------------------------------------------------------------
# ESUN and UDP/IPv4 (RODL general header)
# --------------------------------------------------------------------------
def rodl_header(psn: int, spdcid: int, dpdcid: int, next_hdr: int = C.NH_REQUEST_LCL,
                cack: int = 0, psn16: int = 0, syn: int = 0, ar: int = 0, retx: int = 0) -> RODL:
    return RODL(next_hdr=next_hdr, cack=cack, retx=retx, ar=ar, syn=syn, psn16=psn16 & 0xFFFF,
                psn=psn & 0xFFFFFFFF, spdcid=spdcid, dpdcid=dpdcid)


def build_esun_rodl(dst_mac: str, src_mac: str, rodl: RODL, msgs: list[Packet],
                    cos: int = 0, flow_label: int = 0, ttl: int = 15, ecn: int = 0) -> bytes:
    pkt = Ether(dst=dst_mac, src=src_mac, type=C.ESUN_ETHERTYPE) / \
        ESUN(cos=cos, ecn=ecn, flow_label=flow_label, ttl=ttl) / rodl
    body = _pad_to_min(bytes(pkt) + _ses_bytes(msgs))
    return body + K.crc_bytes(K.esun_crc(body))


def build_udp_rodl(dst_mac: str, src_mac: str, dst_ip: str, src_ip: str, sport: int,
                   rodl: RODL, msgs: list[Packet], dscp: int = 0) -> bytes:
    ses = _ses_bytes(msgs)
    # Lengths must include the CRC trailer, so build with a placeholder first.
    pkt = Ether(dst=dst_mac, src=src_mac) / IP(dst=dst_ip, src=src_ip, tos=dscp << 2, flags="DF") / \
        UDP(sport=sport, dport=C.UDP_PORT_UET) / rodl / Raw(ses + b"\x00" * C.UET_CRC_LEN)
    raw = bytearray(bytes(pkt))
    pkt[UDP].chksum = 0                                   # UDP checksum 0 (allowed for IPv4)
    raw = bytearray(bytes(pkt))
    body = bytes(raw[:-C.UET_CRC_LEN])
    return body + K.crc_bytes(K.ipv4_udp_crc(body))


# --------------------------------------------------------------------------
# Decode
# --------------------------------------------------------------------------
@dataclass
class Decoded:
    kind: str                      # "ufh16-rodl" | "ufh16-ack" | "esun" | "udp" | "other"
    pkt: Packet
    crc_wire: int | None
    crc_calc: int | None
    crc_ok: bool | None            # None = cannot verify (e.g. RODL syn=0 without an expected PSN)

    @property
    def ses(self) -> list[Packet]:
        out, p = [], self.pkt
        while p is not None and not isinstance(p, Raw) and p.name != "NoPayload":
            if isinstance(p, (SESReqLcl0, SESReqLcl1, SESRespLcl)):
                out.append(p)
            p = p.payload if p.payload else None
        return out


def decode(frame: bytes, expected_psn: int | None = None) -> Decoded:
    """Decode a frame (without FCS) and verify its UET CRC where possible.

    For a RODL request over UFH_16 with syn=0 the PSN is not on the wire, so
    the caller must pass the receiver's expected PSN to verify the CRC.
    """
    body, wire = frame[:-C.UET_CRC_LEN], int.from_bytes(frame[-C.UET_CRC_LEN:], C.CRC_BYTE_ORDER)
    if is_ufh16(frame):
        ptype = frame[1] >> 3
        if ptype == C.PDS_TYPE_RODL:
            pkt = UFH16RODL(body)
            psn = pkt.explicit_psn if pkt.syn else expected_psn
            calc = None if psn is None else K.ufh16_crc(body, psn)
            return Decoded("ufh16-rodl", pkt, wire, calc, None if calc is None else calc == wire)
        if ptype == C.PDS_TYPE_ACK:
            pkt = UFH16Ack(body)
            calc = K.ufh16_crc(body, None)
            return Decoded("ufh16-ack", pkt, wire, calc, calc == wire)
        return Decoded("other", Raw(frame), None, None, None)
    eth = Ether(body)
    if eth.type == C.ESUN_ETHERTYPE:
        calc = K.esun_crc(body)
        return Decoded("esun", eth, wire, calc, calc == wire)
    if eth.haslayer(UDP) and eth[UDP].dport == C.UDP_PORT_UET:
        calc = K.ipv4_udp_crc(body)
        return Decoded("udp", eth, wire, calc, calc == wire)
    return Decoded("other", Ether(frame), None, None, None)

"""What the link layer puts on a veth that a real link keeps out of the frame (decision E1).

On a real UE link the LLR sequence number rides in the preamble (UEC §5.1.3) and LLR
ACK/NACK/INIT/INIT_ECHO and CBFC CF_Update are control ordered sets (CtlOS) the PCS inserts
between or inside frames (§5.1.3.1.1, §5.2.6.1). A veth has neither a preamble nor a PCS, and
a packet socket does not deliver the FCS. So the emulator wraps every link-layer unit in a
frame of its own:

    outer Ethernet (link-partner MACs, EtherType 0x88B6 = IEEE local experimental)
    shim, 8 bytes:
        byte 0     CtlOS message type, the D1 value of UEC Table 5-8 / 5-20:
                   0x00 = an LLR frame (data or CC_Update) follows
                   0x01 LLR_ACK  0x02 LLR_NACK  0x03 LLR_INIT  0x04 LLR_INIT_ECHO  0x10 CF_Update
        bytes 1-3  frame_seq (20 bits, right aligned) for a frame; ack_nack_seq / init_seq for LLR CtlOS
        bytes 4-7  CRC-32 of the inner frame: the FCS the packet socket does not give us (0 for CtlOS)
    then either the inner frame (a UFH_16 / ESUN frame as sue/frame.py builds it, without FCS,
    or a 60 B CC_Update MAC control frame per Table 5-22) or the CtlOS data bytes D2..D7
    exactly as Table 5-8 (LLR) or Table 5-21 (CF_Update) lay them out.

Nothing here is a protocol proposal: it is a capture-visible stand-in so that the dissector,
tcpdump and the write-up can show the link layer working. A real NIC would show none of it.
"""

import struct
import zlib

ETHERTYPE_SHIM = 0x88B6
SHIM_LEN = 8
SEQ_MOD = 1 << 20

T_FRAME, T_ACK, T_NACK, T_INIT, T_INIT_ECHO, T_CF = 0x00, 0x01, 0x02, 0x03, 0x04, 0x10
TYPE_NAME = {T_FRAME: "FRAME", T_ACK: "LLR_ACK", T_NACK: "LLR_NACK", T_INIT: "LLR_INIT",
             T_INIT_ECHO: "LLR_INIT_ECHO", T_CF: "CF_UPDATE"}

# CC_Update MAC control frame (UEC §5.2.6.2, Table 5-22)
CC_DA = bytes.fromhex("0180c2000001")
ETHERTYPE_MACCTRL = 0x8808
CC_OPCODE = 0xFFFE
CC_CID = bytes.fromhex("fa7acb")
CC_MSG_VC0_15, CC_MSG_VC16_31 = 0x01, 0x02
CC_FRAME_LEN = 60                      # 64 B with the FCS


def mac_bytes(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", ""))


def mac_str(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def _outer(dst: bytes, src: bytes, mtype: int, seq: int, crc: int) -> bytes:
    return dst + src + struct.pack("!H", ETHERTYPE_SHIM) + bytes([mtype]) + (seq & 0xFFFFF).to_bytes(3, "big") \
        + struct.pack("!I", crc & 0xFFFFFFFF)


def wrap_frame(dst: bytes, src: bytes, seq: int, inner: bytes) -> bytes:
    """An LLR-eligible frame: seq in the shim, CRC-32 of the inner bytes as the FCS stand-in."""
    return _outer(dst, src, T_FRAME, seq, zlib.crc32(inner)) + inner


def llr_ctlos(dst: bytes, src: bytes, mtype: int, seq: int, init_data: int = 0) -> bytes:
    """LLR_ACK / LLR_NACK / LLR_INIT / LLR_INIT_ECHO as Table 5-8 lays D2..D7 out:
    D2 = seq[19:12], D3 = seq[11:4], D4 = {seq[3:0], O-code 0x6}, D5..D6 = init_data, D7 = 0."""
    seq &= 0xFFFFF
    d2d7 = bytes([(seq >> 12) & 0xFF, (seq >> 4) & 0xFF, ((seq & 0xF) << 4) | 0x6,
                  (init_data >> 8) & 0xFF, init_data & 0xFF, 0])
    body = _outer(dst, src, mtype, seq, 0) + d2d7
    return body + b"\x00" * max(0, CC_FRAME_LEN - len(body))


def cf_update(dst: bytes, src: bytes, vc1: int, cf1: int, vc2: int, cf2: int) -> bytes:
    """CF_Update CtlOS data D2..D7 per Table 5-21: {vc_index(5), count(15)} twice, O-code 0x6 in D4[3:0]."""
    a = ((vc1 & 0x1F) << 15) | (cf1 & 0x7FFF)          # 20 bits: D2, D3, D4[7:4]
    b = ((vc2 & 0x1F) << 15) | (cf2 & 0x7FFF)
    d2d7 = bytes([(a >> 12) & 0xFF, (a >> 4) & 0xFF, ((a & 0xF) << 4) | 0x6,
                  (b >> 12) & 0xFF, (b >> 4) & 0xFF, (b & 0xF) << 4])
    body = _outer(dst, src, T_CF, 0, 0) + d2d7
    return body + b"\x00" * max(0, CC_FRAME_LEN - len(body))


def cc_update_frame(src: bytes, counters: dict, msg_type: int = CC_MSG_VC0_15, dst: bytes = CC_DA) -> bytes:
    """A CC_Update MAC control frame (Table 5-22): 16 S_VC_CC values of 20 bits, VC[0..15]."""
    base = 0 if msg_type == CC_MSG_VC0_15 else 16
    bits = 0
    for i in range(16):
        bits = (bits << 20) | (counters.get(base + i, 0) & 0xFFFFF)
    data = bits.to_bytes(40, "big")
    return dst + src + struct.pack("!HH", ETHERTYPE_MACCTRL, CC_OPCODE) + CC_CID + bytes([msg_type]) + data


def is_cc_update(inner: bytes) -> bool:
    return (len(inner) >= CC_FRAME_LEN and inner[12:14] == struct.pack("!H", ETHERTYPE_MACCTRL)
            and inner[14:16] == struct.pack("!H", CC_OPCODE) and inner[16:19] == CC_CID)


def parse_cc_update(inner: bytes) -> dict:
    base = 0 if inner[19] == CC_MSG_VC0_15 else 16
    bits = int.from_bytes(inner[20:60], "big")
    return {base + i: (bits >> (20 * (15 - i))) & 0xFFFFF for i in range(16)}


class Unit:
    """One decoded link-layer unit from the wire."""
    __slots__ = ("mtype", "seq", "crc_ok", "inner", "init_data", "cf", "dst", "src")

    def __init__(self, mtype, seq, crc_ok, inner, init_data, cf, dst, src):
        self.mtype, self.seq, self.crc_ok, self.inner = mtype, seq, crc_ok, inner
        self.init_data, self.cf, self.dst, self.src = init_data, cf, dst, src

    @property
    def is_frame(self):
        return self.mtype == T_FRAME

    @property
    def name(self):
        return TYPE_NAME.get(self.mtype, f"type {self.mtype:#x}")


def unwrap(raw: bytes):
    """Decode a wire unit; None if it is not one of ours."""
    if len(raw) < 14 + SHIM_LEN or raw[12:14] != struct.pack("!H", ETHERTYPE_SHIM):
        return None
    dst, src = raw[:6], raw[6:12]
    mtype = raw[14]
    seq = int.from_bytes(raw[15:18], "big") & 0xFFFFF
    crc = struct.unpack("!I", raw[18:22])[0]
    body = raw[22:]
    if mtype == T_FRAME:
        return Unit(mtype, seq, zlib.crc32(body) == crc, body, 0, None, dst, src)
    if mtype == T_CF:
        a = (body[0] << 12) | (body[1] << 4) | (body[2] >> 4)
        b = (body[3] << 12) | (body[4] << 4) | (body[5] >> 4)
        cf = {(a >> 15) & 0x1F: a & 0x7FFF, (b >> 15) & 0x1F: b & 0x7FFF}
        return Unit(mtype, 0, True, b"", 0, cf, dst, src)
    if mtype in (T_ACK, T_NACK, T_INIT, T_INIT_ECHO):
        s = (body[0] << 12) | (body[1] << 4) | (body[2] >> 4)
        return Unit(mtype, s, True, b"", (body[3] << 8) | body[4], None, dst, src)
    return None


def seq_add(a, n):
    return (a + n) % SEQ_MOD


def seq_diff(a, b):
    d = (a - b) % SEQ_MOD
    return d - SEQ_MOD if d >= SEQ_MOD // 2 else d

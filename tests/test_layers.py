"""Field-level checks against the UEC 1.1 / ESUN 1.0 figures and worked examples."""

import pytest
from scapy.layers.inet import IP, UDP

from sue import consts as C
from sue import crc as K
from sue.frame import (PDC, Req, Rsp, build_esun_rodl, build_ufh16_ack, build_ufh16_rodl,
                       build_udp_rodl, decode, pack_requests, pack_responses, rodl_header)
from sue.layers import (ESUN, RODL, SESReqLcl0, SESReqLcl1, SESRespLcl, UFH16Ack, UFH16RODL,
                        is_ufh16, psn_state_syn0, target_addresses)


# --- CRC ---------------------------------------------------------------------
def test_crc32c_check_value():
    assert K.crc32c(b"123456789") == 0xE3069283


def test_crc32c_rfc3720_vectors():
    # RFC 3720 B.4: 32 bytes of zeros / ones
    assert K.crc32c(b"\x00" * 32) == 0x8A9136AA
    assert K.crc32c(b"\xff" * 32) == 0x62A8AB43


# --- UFH_16 + RODL header (Fig 3-68 / 3-120) ----------------------------------
def test_ufh16_rodl_header_layout():
    h = UFH16RODL(next_hdr=C.NH_REQUEST_LCL, ar=1, dpdcid=0xABC, dst_rsv=0x1, dst_addr=0x234,
                  dscp=26, ecn=1, spdcid=0x567, src_entropy=0x8, src_addr=0x9AB,
                  psn_state_hi=0xC, psn_state_mid=0xD, psn_state_low=0xEF01)
    b = bytes(h)
    assert len(b) == C.UFH16_HDR_LEN == 16
    assert b[0] == 0x42                      # v=0 w=1 rr=00 | z=0 y=0 x=1 m=0
    assert b[1] >> 3 == C.PDS_TYPE_RODL      # type in the top 5 bits of byte 1
    assert ((b[1] & 0x7) << 1 | b[2] >> 7) == C.NH_REQUEST_LCL
    assert (b[2] >> 4) & 0x7 == 0b010        # retx ar syn
    assert ((b[2] & 0xF) << 8 | b[3]) == 0xABC
    assert b[4:6] == bytes([0x12, 0x34])     # {dst_rsv, dst_addr}
    assert b[6] == 0xC2                      # psn_state_hi | sa_encode
    assert b[7] == (26 << 2) | 1             # dscp | ecn
    assert b[8:10] == bytes([0xD5, 0x67])    # psn_state_mid | spdcid
    assert b[10:12] == bytes([0x89, 0xAB])   # {src_entropy, src_addr}
    assert b[12:14] == b"\xe7\x90"
    assert b[14:16] == b"\xef\x01"
    assert is_ufh16(b + b"\x00" * 4)
    r = UFH16RODL(b)
    assert r.psn_state == 0xCDEF01 and r.dst == 0x1234 and r.src == 0x89AB


def test_psn_state_syn0_split():
    s = psn_state_syn0(-3, 0x456)
    assert s == (0xFFD << 12) | 0x456
    h = UFH16RODL(psn_state_hi=s >> 20, psn_state_mid=(s >> 16) & 0xF, psn_state_low=s & 0xFFFF)
    assert h.clear_psn_offset == -3 and h.rev_cack_psn_lsb == 0x456
    with pytest.raises(ValueError):
        psn_state_syn0(5, 0)                 # CLEAR_PSN is never above PSN


def test_ufh16_ack_layout():
    a = UFH16Ack(dpdcid_hi=0xAB, dpdcid_lo=0xC, ack_psn_offset_raw=0x1234, cack_psn=0xDEADBEEF)
    b = bytes(a)
    assert len(b) == 20 and b[0] == 0x42 and b[1] >> 3 == C.PDS_TYPE_ACK
    assert b[12:14] == b"\xe7\x90" and b[14:16] == b"\x12\x34" and b[16:20] == b"\xde\xad\xbe\xef"
    assert UFH16Ack(b).dpdcid == 0xABC


@pytest.mark.parametrize("off,cack,ack", [(0x0024, 0x62231120, 0x62231144), (0xFFDC, 0x62231120, 0x622310FC),
                                          (0x0010, 0xFFFFFFF3, 0x00000003), (0xFEE2, 0x00000079, 0xFFFFFF5B)])
def test_ack_psn_offset_table_3_52(off, cack, ack):
    a = UFH16Ack(ack_psn_offset_raw=off, cack_psn=cack)
    assert a.ack_psn == ack
    f = build_ufh16_ack(dst=1, src=2, spdcid=3, dpdcid=4, ack_psn=ack, cack_psn=cack)
    assert UFH16Ack(f[:20]).ack_psn_offset_raw == off


def test_rodl_general_header_bytes():
    # flags = [rsvd, cack, retx, ar, syn, rsvd(2)] after type(5)=15 and next_hdr(4)=7
    assert bytes(RODL())[:2] == b"\x7b\x80"
    assert bytes(RODL(cack=1))[:2] == b"\x7b\xa0"
    assert bytes(RODL(retx=1))[:2] == b"\x7b\x90"
    assert bytes(RODL(ar=1))[:2] == b"\x7b\x88"
    assert bytes(RODL(syn=1))[:2] == b"\x7b\x84"
    r = rodl_header(psn=0x01020304, spdcid=0x0A0B, dpdcid=0x0C0D)
    b = bytes(r)
    assert len(b) == 12 and b[2:4] == b"\xff\xff" and b[4:8] == b"\x01\x02\x03\x04"
    assert b[8:12] == b"\x0a\x0b\x0c\x0d" and r.clear_psn_offset == -1
    s = RODL(syn=1, dpdcid=0x1ABC)
    assert (s.pdc_info, s.psn_offset) == (1, 0xABC)


# --- SES Unified Local (§3.4.3.3) ----------------------------------------------
def test_ses_header_sizes():
    assert len(bytes(SESReqLcl0(opcode=C.OP_READ))) == 12
    assert len(bytes(SESReqLcl1(opcode=C.OP_READ))) == 8
    assert len(bytes(SESRespLcl())) == 4


def test_address_compression_table_3_14():
    addrs = [0x0000_0002_0010_3400, 0x0000_0002_0010_3500, 0x0000_0002_0010_3200, 0x0000_0002_0200_0000]
    hdrs = pack_requests([Req(C.OP_READ, a, length=64) for a in addrs])
    assert [h.ac for h in hdrs] == [0, 1, 1, 1]
    assert [h.mm for h in hdrs] == [1, 1, 1, 0]
    assert [h.address_offset_raw for h in hdrs[1:]] == [0x0000_0100, 0xFFFF_FD00, 0x01EF_CE00]
    first = SESReqLcl0(b"".join(bytes(h) for h in hdrs))
    assert target_addresses(first) == addrs


def test_packed_write_padding_53_bytes():
    # "if ses.request_length is 53 bytes, the next SES header starts 56 bytes after
    #  the start of the previous message's payload" (§3.4.3.3)
    hdrs = pack_requests([Req(C.OP_WRITE, 0x1000, b"\xaa" * 53), Req(C.OP_WRITE, 0x1100, b"\xbb" * 64)])
    raw = b"".join(bytes(h) for h in hdrs)
    assert raw[12 + 53:12 + 56] == b"\x00\x00\x00"
    assert raw[12 + 56] & 0x80                # next header is ac=1
    p = SESReqLcl0(raw)
    assert p.data == b"\xaa" * 53 and p[SESReqLcl1].data == b"\xbb" * 64


def test_ac1_inherits_ehl_and_ehl_change_forces_ac0():
    reqs = [Req(C.OP_WRITE, 0x2000, b"\x01" * 8, ehl=1, ext=b"EXT1"),
            Req(C.OP_WRITE, 0x2008, b"\x02" * 8, ehl=1, ext=b"EXT2"),
            Req(C.OP_WRITE, 0x2010, b"\x03" * 8, ehl=0)]
    hdrs = pack_requests(reqs)
    assert [h.ac for h in hdrs] == [0, 1, 0]
    p = SESReqLcl0(b"".join(bytes(h) for h in hdrs))
    assert p[SESReqLcl1].ext == b"EXT2"      # parsed using the inherited ehl
    assert p[SESReqLcl1].payload.ext == b"" and p[SESReqLcl1].payload.data == b"\x03" * 8


def test_long_request_uses_rle_and_ac0():
    hdrs = pack_requests([Req(C.OP_READ, 0, length=100), Req(C.OP_READ, 0x10000, length=5000)])
    assert hdrs[1].ac == 0 and hdrs[1].rle == 1 and hdrs[1].request_length == 5000 - 4096
    assert hdrs[1].length == 5000


def test_atomic_has_4B_header_before_operands():
    # §3.4.3.5 / Fig 3-20: [SES 12][ext][atomic hdr 4][operands], request_length counts operands only
    reqs = [Req(C.OP_ATOMIC, 0x8000, b"\x01" * 8, atomic=b"\xA1\xA2\xA3\xA4"),
            Req(C.OP_WRITE, 0x8040, b"\x02" * 16)]
    raw = b"".join(bytes(h) for h in pack_requests(reqs))
    assert len(raw) == 12 + 4 + 8 + 8 + 16
    assert raw[12:16] == b"\xA1\xA2\xA3\xA4"
    p = SESReqLcl0(raw)
    assert p.atomic == b"\xA1\xA2\xA3\xA4" and p.data == b"\x01" * 8
    assert p[SESReqLcl1].opcode == C.OP_WRITE and p[SESReqLcl1].data == b"\x02" * 16
    with pytest.raises(ValueError):
        Req(C.OP_ATOMIC, 0, b"\x00" * 8)          # missing atomic header


def test_pack_limit_16():
    with pytest.raises(ValueError):
        pack_requests([Req(C.OP_READ, i * 64, length=64) for i in range(17)])


def test_read_carries_no_data_and_response_does():
    with pytest.raises(ValueError):
        Req(C.OP_READ, 0, b"\x00" * 4)
    rsp = pack_responses([Rsp(C.RSP_RESPONSE_W_DATA, data=b"\x11" * 6), Rsp()])
    raw = b"".join(bytes(r) for r in rsp)
    assert len(raw) == 4 + 6 + 2 + 4
    p = SESRespLcl(raw)
    assert p.data == b"\x11" * 6 and p.mm == 1 and p.payload.return_code == C.RC_OK


# --- Whole frames + UET CRC -------------------------------------------------------
PDC0 = PDC(dst=0x0102, src=0x0201, spdcid=0x011, dpdcid=0x022, psn=1042, dscp=10)


def two_stores():
    return pack_requests([Req(C.OP_WRITE, 0x2_0010_3400, b"\xab" * 256),
                          Req(C.OP_WRITE, 0x2_0010_3500, b"\xcd" * 256)])


def test_two_256B_stores_frame_size():
    f = build_ufh16_rodl(PDC0, two_stores())
    assert len(f) + 4 == 556                  # + FCS: matches SUE-T example in the field guide


def test_ufh16_crc_checks_sequence():
    f = build_ufh16_rodl(PDC0, two_stores())
    assert decode(f, expected_psn=1042).crc_ok is True
    assert decode(f, expected_psn=1043).crc_ok is False   # a gap looks like corruption
    assert decode(f).crc_ok is None                       # syn=0, PSN unknown


def test_ufh16_crc_masks_tc_only():
    f = bytearray(build_ufh16_rodl(PDC0, two_stores()))
    g = bytearray(f); g[C.UFH16_TC_BYTE] ^= 0xFF          # a switch rewrote dscp/ecn
    assert decode(bytes(g), expected_psn=1042).crc_ok is True
    h = bytearray(f); h[4] ^= 0x01                        # dst_addr corrupted
    assert decode(bytes(h), expected_psn=1042).crc_ok is False


def test_ufh16_syn_carries_psn_and_short_frame_is_padded():
    pdc = PDC(dst=1, src=2, spdcid=3, dpdcid=0, psn=0x00ABCDEF, extra={"psn_offset": 0})
    f = build_ufh16_rodl(pdc, pack_requests([Req(C.OP_READ, 0x40, length=64)]), syn=1)
    assert len(f) == 60                                   # 16+12, padded to 56, + CRC
    d = decode(f)
    assert d.pkt.explicit_psn == 0xABCDEF and d.crc_ok is True


def test_ack_with_four_responses_is_64B():
    # UEC Fig 3-123 (right): ACK over UFH_16 + 3 x UET_RESPONSE RC_OK + 1 x RC_BAD_ADDR + pad = 64 B with FCS
    rsps = pack_responses([Rsp(C.RSP_RESPONSE)] * 3 + [Rsp(C.RSP_RESPONSE, return_code=C.RC_BAD_ADDR)])
    f = build_ufh16_ack(dst=2, src=1, spdcid=0x22, dpdcid=0x11, ack_psn=1042, cack_psn=1042, msgs=rsps)
    assert len(f) + 4 == 64
    d = decode(f)
    assert d.kind == "ufh16-ack" and d.crc_ok is True and len(d.ses) == 4
    assert [m.return_code for m in d.ses] == [C.RC_OK] * 3 + [0x1D]
    assert d.pkt.ack_psn == 1042 and d.pkt.ack_psn_offset == 0


def test_esun_frame_and_crc_masks():
    rodl = rodl_header(psn=7, spdcid=0x11, dpdcid=0x22)
    f = build_esun_rodl("02:00:00:00:00:02", "02:00:00:00:00:01", rodl, two_stores(),
                        cos=3, flow_label=0xBEEF, ttl=7)
    d = decode(f)
    assert d.kind == "esun" and d.crc_ok is True
    eh = d.pkt[ESUN]
    assert (eh.cos, eh.flow_label, eh.ttl, eh.f) == (3, 0xBEEF, 7, 1)
    assert f[12:14] == C.ESUN_ETHERTYPE.to_bytes(2, "big") and len(bytes(eh)) - len(eh.payload) == 4
    assert d.pkt[RODL].psn == 7 and len(d.ses) == 2
    g = bytearray(f); g[17] = (g[17] & 0x0F) | 0x30       # TTL decremented by a switch
    assert decode(bytes(g)).crc_ok is True
    h = bytearray(f); h[15] ^= 0xFF                       # flow label corrupted
    assert decode(bytes(h)).crc_ok is False


def test_udp_frame_and_crc_ignores_ttl():
    rodl = rodl_header(psn=99, spdcid=1, dpdcid=2)
    f = build_udp_rodl("02:00:00:00:00:02", "02:00:00:00:00:01", "10.0.0.2", "10.0.0.1",
                       sport=0xC001, rodl=rodl, msgs=two_stores())
    d = decode(f)
    assert d.kind == "udp" and d.crc_ok is True
    assert d.pkt[UDP].chksum == 0 and d.pkt[IP].len == len(f) - 14
    g = bytearray(f); g[14 + 8] -= 1                      # IP TTL changed by a router
    assert decode(bytes(g)).crc_ok is True


def test_psn_placement_readings_differ_only_when_padded(monkeypatch):
    short = PDC(dst=1, src=2, spdcid=3, dpdcid=4, psn=77)
    msgs = pack_requests([Req(C.OP_READ, 0x40, length=64)])
    after = build_ufh16_rodl(short, msgs)                     # padded frame, default: PSN after pad
    monkeypatch.setattr(C, "PSN_AFTER_PAD", False)
    before = build_ufh16_rodl(short, msgs)
    assert after[:-4] == before[:-4] and after[-4:] != before[-4:]
    assert decode(before, expected_psn=77).crc_ok is True
    big = build_ufh16_rodl(PDC0, two_stores())                # not padded: both readings agree
    monkeypatch.setattr(C, "PSN_AFTER_PAD", True)
    assert build_ufh16_rodl(PDC0, two_stores()) == big


def test_decode_guards():
    assert decode(b"\x42" * 10).kind == "other"
    f = bytearray(build_ufh16_rodl(PDC0, two_stores()))
    f[12:14] = b"\x08\x00"                                    # UFH-looking DA but not EtherType 0xE790
    assert decode(bytes(f)).kind != "ufh16-rodl"

"""sim/wire.py byte accounting must match the real frames sue/frame.py builds (M1)."""

import pytest

from sim import wire
from sue import consts as C
from sue.frame import PDC, Req, Rsp, build_esun_rodl, build_udp_rodl, build_ufh16_ack, build_ufh16_rodl, \
    pack_requests, pack_responses, rodl_header

pdc = PDC(dst=7, src=3, spdcid=1, dpdcid=2, psn=100)


def stores(n, size=256, ehl=0):
    return [Req(C.OP_WRITE, 0x1000 + i * size, data=bytes(size), ehl=ehl, ext=bytes(C.EHL_BYTES[ehl])) for i in range(n)]


@pytest.mark.parametrize("n", [1, 2, 4, 8, 16])
def test_packed_stores_over_ufh16(n):
    frame = build_ufh16_rodl(pdc, pack_requests(stores(n)))
    assert len(frame) + wire.FCS == wire.packet_bytes("ufh16", "req", wire.ses_requests([256] * n))


@pytest.mark.parametrize("ehl", [0, 1, 3])
def test_extension_header_and_compression_are_counted(ehl):
    frame = build_ufh16_rodl(pdc, pack_requests(stores(3, ehl=ehl)))
    assert len(frame) + wire.FCS == wire.packet_bytes("ufh16", "req", wire.ses_requests([256] * 3, ehl))
    frame = build_ufh16_rodl(pdc, pack_requests(stores(3, ehl=ehl), compress=False))
    assert len(frame) + wire.FCS == wire.packet_bytes("ufh16", "req", wire.ses_requests([256] * 3, ehl, compress=False))


def test_loads_and_tiny_packets_pad_to_64():
    loads = [Req(C.OP_READ, 0x2000 + 256 * i, length=256) for i in range(2)]
    frame = build_ufh16_rodl(pdc, pack_requests(loads))
    assert len(frame) + wire.FCS == wire.packet_bytes("ufh16", "req", wire.ses_requests([0, 0])) == 64


def test_ack_packets_with_and_without_data():
    bare = build_ufh16_ack(7, 3, 1, 2, ack_psn=100, cack_psn=100)
    assert len(bare) + wire.FCS == wire.packet_bytes("ufh16", "ack", 0) == 64
    data = build_ufh16_ack(7, 3, 1, 2, 100, 100, msgs=pack_responses([Rsp(C.RSP_RESPONSE_W_DATA, data=bytes(256))] * 3))
    assert len(data) + wire.FCS == wire.packet_bytes("ufh16", "ack", wire.ses_responses([256] * 3))


def test_esun_and_udp_stacks():
    msgs = pack_requests(stores(2))
    esun = build_esun_rodl("02:00:00:00:00:07", "02:00:00:00:00:03", rodl_header(100, 1, 2), msgs)
    assert len(esun) + wire.FCS == wire.packet_bytes("esun", "req", wire.ses_requests([256, 256]))
    udp = build_udp_rodl("02:00:00:00:00:07", "02:00:00:00:00:03", "10.0.0.7", "10.0.0.3", 4000, rodl_header(100, 1, 2), msgs)
    assert len(udp) + wire.FCS == wire.packet_bytes("udp", "req", wire.ses_requests([256, 256]))


def test_spec_efficiency_claims_come_out_of_the_accounting():
    """SUE-T §7.1.2: > 90 % with two or more packed CMD_PDUs over UFH_16 and operational ACKs,
    < 80 % with delivery ACKs and a 16-byte response command."""
    op2 = wire.transaction_bytes("ufh16", "operational", 2, piggyback=True)
    dl2 = wire.transaction_bytes("ufh16", "delivery", 2)                   # response packet needs its own ACK
    dl2p = wire.transaction_bytes("ufh16", "delivery", 2, piggyback=True)
    assert op2["frame_eff"] > 0.90 > 0.80 > dl2["frame_eff"]
    assert dl2["frame_eff"] < dl2p["frame_eff"] < op2["frame_eff"]
    roce = wire.roce_transaction_bytes("store", 256)
    assert roce["frame_eff"] < dl2["frame_eff"]
    assert roce["fwd"] == 14 + 20 + 8 + 12 + 16 + 256 + 4 + 4

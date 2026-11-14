"""Write the golden pcaps in pcaps/golden/ and an expectations file golden.json.

Every frame is built from the layers in sue/, decoded again, and its CRC
verified before it is written. Run:  .venv/bin/python tools/make_golden.py
"""

import json
from pathlib import Path

from scapy.layers.l2 import Ether
from scapy.utils import PcapWriter

from sue import consts as C
from sue.frame import (PDC, Req, Rsp, build_esun_rodl, build_ufh16_ack, build_ufh16_rodl,
                       build_udp_rodl, decode, pack_requests, pack_responses, rodl_header)

OUT = Path(__file__).resolve().parent.parent / "pcaps" / "golden"
MAC_A, MAC_B = "02:00:00:00:00:01", "02:00:00:00:00:02"
XPU_A, XPU_B = 0x0001, 0x0002            # 16-bit UFH address containers = XPU ids
EPOCH = 1_794_614_400                     # 2026-11-14 00:00 UTC


def stores(base=0x2_0010_3400):
    return pack_requests([Req(C.OP_WRITE, base, bytes(range(256))),
                          Req(C.OP_WRITE, base + 0x100, bytes(reversed(range(256))))])


def cases():
    """Yield (file, description, [(frame, expected_psn_or_None, note)])."""
    a2b = PDC(dst=XPU_B, src=XPU_A, spdcid=0x011, dpdcid=0x022, psn=1042, dscp=10)

    syn = PDC(dst=XPU_B, src=XPU_A, spdcid=0x011, dpdcid=0, psn=1000, dscp=10, extra={"psn_offset": 0})
    yield ("01-ufh16-rodl-syn-read", "RODL over UFH_16, syn=1 (PSN on the wire), one 64 B read, padded to 56 B",
           [(build_ufh16_rodl(syn, pack_requests([Req(C.OP_READ, 0x2_0010_3400, length=64)]), syn=1, ar=1),
             1000, "syn=1 read")])

    yield ("02-ufh16-rodl-two-stores", "Two packed 256 B stores (ac=0 then ac=1), syn=0, PSN 1042 hidden in the CRC",
           [(build_ufh16_rodl(a2b, stores()), 1042, "556 B with FCS")])

    t314 = [0x2_0010_3400, 0x2_0010_3500, 0x2_0010_3200, 0x2_0200_0000]
    yield ("03-ufh16-rodl-table-3-14", "Four packed reads using the address offsets of UEC Table 3-14",
           [(build_ufh16_rodl(PDC(**{**a2b.__dict__, "psn": 1043}),
                              pack_requests([Req(C.OP_READ, a, length=64) for a in t314])), 1043,
             "offsets +0x100, -0x300, +0x1EFCE00")])

    ext = pack_requests([Req(C.OP_WRITE, 0x3000, b"\xaa" * 53, ehl=1, ext=b"USR1"),
                         Req(C.OP_WRITE, 0x3040, b"\xbb" * 16, ehl=1, ext=b"USR2"),
                         Req(C.OP_WRITE, 0x3080, b"\xcc" * 8, ehl=0)])
    yield ("04-ufh16-rodl-ext-and-padding", "Extension headers (ehl=1 inherited by ac=1), 53 B payload padded to 56, ehl change forces ac=0",
           [(build_ufh16_rodl(PDC(**{**a2b.__dict__, "psn": 1044}), ext), 1044, "ac=0,1,0")])

    rsps = pack_responses([Rsp(C.RSP_RESPONSE)] * 3 + [Rsp(C.RSP_RESPONSE, return_code=C.RC_BAD_ADDR)])
    yield ("05-ufh16-ack-four-responses", "ACK over UFH_16 with four packed responses, padded: 64 B with FCS (UEC Fig 3-123)",
           [(build_ufh16_ack(dst=XPU_A, src=XPU_B, spdcid=0x022, dpdcid=0x011, ack_psn=1044,
                             cack_psn=1044, msgs=rsps, dscp=12), None, "CRC without PSN")])

    data = pack_responses([Rsp(C.RSP_RESPONSE_W_DATA, data=bytes([0x5A]) * 64),
                           Rsp(C.RSP_RESPONSE_W_DATA, data=bytes([0xA5]) * 64)])
    yield ("06-ufh16-ack-read-data", "ACK over UFH_16 returning two 64 B read responses",
           [(build_ufh16_ack(dst=XPU_A, src=XPU_B, spdcid=0x022, dpdcid=0x011, ack_psn=1043,
                             cack_psn=1043, msgs=data, dscp=12), None, "read data")])

    yield ("07-esun-rodl-two-stores", f"ESUN (EH-ET {C.ESUN_ETHERTYPE:#06x}, local experimental) + RODL general header + two stores",
           [(build_esun_rodl(MAC_B, MAC_A, rodl_header(psn=1042, spdcid=0x011, dpdcid=0x022), stores(),
                             cos=3, flow_label=0xBEEF, ttl=15), 1042, "CRC rule is a project decision")])

    yield ("08-udp-rodl-two-stores", "Ethernet/IPv4/UDP 4793 + RODL general header + two stores",
           [(build_udp_rodl(MAC_B, MAC_A, "10.0.0.2", "10.0.0.1", 0xC011,
                            rodl_header(psn=1042, spdcid=0x011, dpdcid=0x022), stores(), dscp=10),
             1042, "UDP checksum 0")])

    # A short conversation for dissector PSN tracking: setup, two data packets, ACK.
    seq, psn = [], 2000
    p = PDC(dst=XPU_B, src=XPU_A, spdcid=0x033, dpdcid=0, psn=psn, dscp=10, extra={"psn_offset": 0})
    seq.append((build_ufh16_rodl(p, pack_requests([Req(C.OP_WRITE, 0x5000, b"\x01" * 32)]), syn=1), psn, "syn"))
    for i in (1, 2):
        p = PDC(dst=XPU_B, src=XPU_A, spdcid=0x033, dpdcid=0x044, psn=psn + i, dscp=10,
                rev_cack_psn_lsb=0)
        seq.append((build_ufh16_rodl(p, pack_requests([Req(C.OP_WRITE, 0x5000 + 0x40 * i, b"\x02" * 32)])),
                    psn + i, f"PSN {psn + i} hidden"))
    seq.append((build_ufh16_ack(dst=XPU_A, src=XPU_B, spdcid=0x044, dpdcid=0x033, ack_psn=psn + 2,
                                cack_psn=psn + 2, dscp=12), None, "cumulative ACK"))
    # Loss and Go-Back-N: PSN 3002 is lost, the receiver drops 3003/3004, the sender goes back.
    seq10, base = [], 3000
    def w(psn, syn=0, retx=0):
        p = PDC(dst=XPU_B, src=XPU_A, spdcid=0x055, dpdcid=0 if syn else 0x066, psn=psn, dscp=10,
                extra={"psn_offset": 0})
        return build_ufh16_rodl(p, pack_requests([Req(C.OP_WRITE, 0x6000 + 0x40 * (psn - base), bytes([psn & 0xFF]) * 32)]),
                                syn=syn, retx=retx)
    seq10.append((w(base, syn=1), base, "syn", {"psn": base, "gap": 0}))
    seq10.append((w(base + 1), base + 1, "in order", {"psn": base + 1, "gap": 0}))
    seq10.append((w(base + 3), base + 3, "3002 lost: dissector finds PSN 3003 (gap 1)", {"psn": base + 3, "gap": 1}))
    seq10.append((w(base + 4), base + 4, "in order after the gap", {"psn": base + 4, "gap": 0}))
    for k, psn in enumerate((base + 2, base + 3, base + 4)):
        seq10.append((w(psn, retx=1), psn, "Go-Back-N retransmission", {"psn": psn, "gap": -3 if k == 0 else 0}))
    yield ("10-ufh16-loss-and-retx", "PSN 3002 lost; the dissector recovers 3003 from the CRC (gap 1), then the sender goes back to 3002 with retx=1", seq10)

    # Corruption: a payload byte flipped after the CRC was computed. No PSN in the window matches.
    p = PDC(dst=XPU_B, src=XPU_A, spdcid=0x077, dpdcid=0, psn=4000, dscp=10, extra={"psn_offset": 0})
    good0 = build_ufh16_rodl(p, pack_requests([Req(C.OP_WRITE, 0x7000, b"\x11" * 32)]), syn=1)
    p1 = PDC(dst=XPU_B, src=XPU_A, spdcid=0x077, dpdcid=0x088, psn=4001, dscp=10)
    bad = bytearray(build_ufh16_rodl(p1, pack_requests([Req(C.OP_WRITE, 0x7040, b"\x22" * 32)])))
    bad[40] ^= 0x01
    p2 = PDC(dst=XPU_B, src=XPU_A, spdcid=0x077, dpdcid=0x088, psn=4002, dscp=10)
    good2 = build_ufh16_rodl(p2, pack_requests([Req(C.OP_WRITE, 0x7080, b"\x33" * 32)]))
    yield ("11-ufh16-corrupted", "syn PSN 4000, then PSN 4001 with one payload bit flipped (CRC Bad), then PSN 4002 (Good)",
           [(good0, 4000, "syn", {"psn": 4000, "gap": 0}),
            (bytes(bad), 4001, "bit flip at byte 40: CRC Bad", {"crc_status": 1}),
            (good2, 4002, "tracking continues", {"psn": 4002, "gap": 0})])

    # Atomics and an ACK whose ACK_PSN differs from CACK_PSN (signed offset, §3.5.11.4.5).
    p0 = PDC(dst=XPU_B, src=XPU_A, spdcid=0x099, dpdcid=0, psn=5000, dscp=10, extra={"psn_offset": 0})
    p1 = PDC(dst=XPU_B, src=XPU_A, spdcid=0x099, dpdcid=0x0AA, psn=5001, dscp=10)
    atom = pack_requests([Req(C.OP_ATOMIC, 0x9000, (7).to_bytes(8, "big"), atomic=b"\x01\x05\x00\x00"),
                          Req(C.OP_FETCHING_ATOMIC, 0x9008, (1).to_bytes(8, "big"), atomic=b"\x02\x05\x00\x00"),
                          Req(C.OP_WRITE, 0x9040, b"\x44" * 16)])
    yield ("12-ufh16-atomic-and-ack-offset", "Packed atomic + fetching atomic (4 B atomic header each) + write; ACK with ack_psn_offset = -1",
           [(build_ufh16_rodl(p0, pack_requests([Req(C.OP_WRITE, 0x9000, b"\x00" * 8)]), syn=1), 5000, "syn", {"psn": 5000, "gap": 0}),
            (build_ufh16_rodl(p1, atom), 5001, "atomic header before operands", {"psn": 5001, "gap": 0}),
            (build_ufh16_ack(dst=XPU_A, src=XPU_B, spdcid=0x0AA, dpdcid=0x099, ack_psn=5000, cack_psn=5001, dscp=12),
             None, "ACK_PSN 5000 = CACK_PSN 5001 + (-1)")])

    yield ("09-ufh16-conversation", "PDC setup (syn=1, PSN 2000), two syn=0 writes (PSN 2001, 2002 hidden), cumulative ACK", seq)


def fields_of(d) -> dict:
    """Values the dissector test compares against (sue.lua must decode the same)."""
    from sue.layers import RODL, UFH16Ack, UFH16RODL, target_addresses
    from sue.layers.ses import SESReqLcl0
    out = {}
    p = d.pkt
    if isinstance(p, UFH16RODL):
        out.update(dst=p.dst, src=p.src, spdcid=p.spdcid)
    elif isinstance(p, UFH16Ack):
        out.update(dst=p.dst, src=p.src, spdcid=p.spdcid, cack_psn=p.cack_psn, ack_psn=p.ack_psn)
    elif p.haslayer(RODL):
        out.update(spdcid=p[RODL].spdcid)
    if p.haslayer(SESReqLcl0):
        out["targets"] = target_addresses(p[SESReqLcl0])
    return out


def main(out_dir: Path = OUT):
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = []
    for name, desc, frames in cases():
        w = PcapWriter(str(out_dir / f"{name}.pcap"), linktype=1, sync=True)
        entries = []
        for i, item in enumerate(frames):
            frame, psn, note = item[:3]
            expect = item[3] if len(item) > 3 else {}
            d = decode(frame, expected_psn=psn)
            want_ok = expect.get("crc_status", 0) == 0
            if d.crc_ok is not want_ok:
                raise SystemExit(f"{name}: CRC check gave {d.crc_ok}, expected {want_ok} ({note})")
            pkt = Ether(frame)
            assert bytes(pkt) == frame
            pkt.time = EPOCH + i * 50e-6                     # fixed timestamps: stable git diffs
            w.write(pkt)
            entries.append({"kind": d.kind, "len": len(frame), "len_with_fcs": len(frame) + 4,
                            "expected_psn": psn, "uet_crc": f"0x{d.crc_wire:08X}", "note": note,
                            "ses_messages": len(d.ses),
                            "fields": fields_of(d),
                            "dissector": {"crc_status": expect.get("crc_status", 0),
                                          **{k: v for k, v in expect.items() if k != "crc_status"}}})
        w.close()
        manifest.append({"file": f"{name}.pcap", "description": desc, "frames": entries})
        print(f"{name}.pcap  {len(frames)} frame(s)") if out_dir == OUT else None
    manifest.sort(key=lambda c: c["file"])
    (out_dir / "golden.json").write_text(json.dumps({
        "generator": "tools/make_golden.py",
        "decisions": {"esun_ethertype": f"0x{C.ESUN_ETHERTYPE:04X}", "crc_byte_order": C.CRC_BYTE_ORDER,
                      "psn_byte_order": C.PSN_BYTE_ORDER, "fcs": "not included"},
        "captures": manifest}, indent=2) + "\n")


if __name__ == "__main__":
    main()

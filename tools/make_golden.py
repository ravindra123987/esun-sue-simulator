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

    rsps = pack_responses([Rsp(C.RSP_RESPONSE)] * 3 + [Rsp(C.RSP_RESPONSE, return_code=C.RC_NO_MATCH)])
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
    yield ("09-ufh16-conversation", "PDC setup (syn=1, PSN 2000), two syn=0 writes (PSN 2001, 2002 hidden), cumulative ACK", seq)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    manifest = []
    for name, desc, frames in cases():
        w = PcapWriter(str(OUT / f"{name}.pcap"), linktype=1, sync=True)
        entries = []
        for i, (frame, psn, note) in enumerate(frames):
            d = decode(frame, expected_psn=psn)
            if d.crc_ok is not True:
                raise SystemExit(f"{name}: CRC did not verify ({note})")
            pkt = Ether(frame)
            assert bytes(pkt) == frame
            pkt.time = EPOCH + i * 50e-6                     # fixed timestamps: stable git diffs
            w.write(pkt)
            entries.append({"kind": d.kind, "len": len(frame), "len_with_fcs": len(frame) + 4,
                            "expected_psn": psn, "uet_crc": f"0x{d.crc_wire:08X}", "note": note,
                            "ses_messages": len(d.ses)})
        w.close()
        manifest.append({"file": f"{name}.pcap", "description": desc, "frames": entries})
        print(f"{name}.pcap  {len(frames)} frame(s)")
    (OUT / "golden.json").write_text(json.dumps({
        "generator": "tools/make_golden.py",
        "decisions": {"esun_ethertype": f"0x{C.ESUN_ETHERTYPE:04X}", "crc_byte_order": C.CRC_BYTE_ORDER,
                      "psn_byte_order": C.PSN_BYTE_ORDER, "fcs": "not included"},
        "captures": manifest}, indent=2) + "\n")


if __name__ == "__main__":
    main()

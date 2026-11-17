"""What a capture of one emulated link shows: LLR units, replays, bad frames, CC_Updates, SUE-T packets.

    python -m emu.analyze out/clean/link1.pcap [...]

Runs anywhere scapy is (no root): the pcaps come back from the VM with the results.
"""

import json
import sys
from collections import Counter

from scapy.utils import RawPcapReader

from sue import consts as C
from sue.frame import decode
from sue.layers import is_ufh16

from . import shim as S


def analyze(path: str) -> dict:
    c = Counter()
    seen = {"xpu": set(), "sw": set()}
    t0 = t1 = None
    psn = {}                                        # per (src, dst): expected PSN for the CRC/PSN trick
    for raw, meta in RawPcapReader(path):
        ts = meta.sec + meta.usec / 1e6 if hasattr(meta, "usec") else meta.tshigh * 2 ** 32 + meta.tslow
        t0 = ts if t0 is None else t0
        t1 = ts
        u = S.unwrap(bytes(raw))
        if u is None:
            c["other"] += 1
            continue
        side = "xpu" if u.src[:2] == b"\x02\xa0" else "sw"
        c[f"{side}_units"] += 1
        if not u.is_frame:
            c[f"{side}_{u.name.lower()}"] += 1
            continue
        c[f"{side}_frames"] += 1
        c[f"{side}_bytes"] += len(u.inner)
        if not u.crc_ok:
            c[f"{side}_bad"] += 1
        if u.seq in seen[side]:
            c[f"{side}_replayed"] += 1
        seen[side].add(u.seq)
        if S.is_cc_update(u.inner):
            c[f"{side}_cc_update"] += 1
            continue
        if not u.crc_ok:
            continue
        if is_ufh16(u.inner) and u.inner[12:14] == b"\xe7\x90" and (u.inner[1] >> 3) == C.PDS_TYPE_NACK:
            c["nack_pkts"] += 1                     # RODL NACK: PDS type 10 in the ACK layout (sue/frame.py decodes ACKs only)
            continue
        d = decode(u.inner, expected_psn=None)
        if d.kind == "ufh16-rodl":
            key = (d.pkt.src, d.pkt.dst)
            exp = d.pkt.explicit_psn if d.pkt.syn else psn.get(key)
            dd = decode(u.inner, expected_psn=exp) if exp is not None else d
            c["rodl_req"] += 1
            c["rodl_syn"] += d.pkt.syn
            c["rodl_retx_flag"] += d.pkt.retx
            c["rodl_crc_ok"] += 1 if dd.crc_ok else 0
            c["rodl_crc_unverified"] += 1 if dd.crc_ok is None else 0
            c["cmd_pdus"] += len(dd.ses)
            if exp is not None:
                psn[key] = exp + 1
        elif d.kind == "ufh16-ack":
            c["ack_pkts"] += 1
        else:
            c["unknown_inner"] += 1
    out = Counter(dict(sorted(c.items())))         # a Counter: absent keys read as 0
    out["duration_s"] = round((t1 - t0), 3) if t0 is not None else 0.0
    return out


def main(argv=None):
    for p in (argv or sys.argv[1:]):
        print(p)
        print(json.dumps(analyze(p), indent=1))


if __name__ == "__main__":
    main()

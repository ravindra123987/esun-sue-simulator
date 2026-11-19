"""Frame-level checks of the P4 switch (p4/esun_switch.p4) running in bmv2, through the lab's veths.

One process opens a packet socket inside every XPU namespace (os.setns), sends frames built by
sue/frame.py from one XPU and records what arrives where. Each check states the behaviour it tests
and the spec or decision behind it. Needs root on Linux and the lab built with switch="bmv2"; run by
tools/run_m6.py.
"""

import os
import socket
import time

from scapy.layers.l2 import Ether

from sue import consts as C
from sue import crc as K
from sue.frame import (PDC, Req, build_esun_rodl, build_udp_rodl, build_ufh16_ack, build_ufh16_rodl, decode,
                       pack_requests, rodl_header)
from sue.layers import ESUN

from .shim import cc_update_frame


def xmac(i):
    return f"02:a0:00:00:00:{i:02x}"


def open_in_ns(ns, ifname):
    """A raw packet socket created inside network namespace `ns` (it stays there after we switch back)."""
    here = os.open("/proc/self/ns/net", os.O_RDONLY)
    there = os.open(f"/var/run/netns/{ns}", os.O_RDONLY)
    try:
        os.setns(there, os.CLONE_NEWNET)
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        s.bind((ifname, 0))
        s.setblocking(False)
    finally:
        os.setns(here, os.CLONE_NEWNET)
        os.close(here)
        os.close(there)
    return s


def summary(frame: bytes) -> dict:
    """The fields of a frame the switch reads or rewrites, for the packet viewer (M6)."""
    from scapy.layers.inet import IP
    res = {"len": len(frame)}
    if len(frame) >= 16 and frame[12:14] == b"\xe7\x90" and (frame[0] & 0xCE) == 0x42:
        d = decode(frame)
        p = d.pkt
        res.update(kind="UFH_16 " + ("RODL request" if d.kind == "ufh16-rodl" else "ACK"), dst=p.dst, src=p.src, dscp=p.dscp, ecn=p.ecn)
        if d.kind == "ufh16-rodl":
            res.update(syn=p.syn, psn=p.explicit_psn, stores=len(d.ses))
        else:
            res.update(cack_psn=p.cack_psn)
    elif len(frame) >= 18 and frame[12:14] == C.ESUN_ETHERTYPE.to_bytes(2, "big"):
        e = Ether(frame)
        h = e[ESUN]
        res.update(kind="ESUN", da=e.dst, sa=e.src, cos=h.cos, ecn=h.ecn, ttl=h.ttl, flow_label=h.flow_label,
                   crc_ok=int.from_bytes(frame[-4:], C.CRC_BYTE_ORDER) == K.esun_crc(frame[:-4]))
    elif len(frame) >= 14 and frame[12:14] == b"\x88\x08":
        res.update(kind="MAC control (CC_Update)", da=":".join(f"{b:02x}" for b in frame[:6]))
    else:
        e = Ether(frame)
        if e.haslayer(IP):
            res.update(kind="UDP/IP SUE-T", da=e.dst, ip_dst=e[IP].dst)
        else:
            res.update(kind="Ethernet", da=e.dst, ether_type=hex(e.type))
    return res


class Rig:
    def __init__(self, n):
        self.n = n
        self.socks = {i: open_in_ns(f"xpu{i}", "eth0") for i in range(n)}
        self.sent = []                          # every frame sent, in order, with what came out (M6 viewer)

    def drain(self):
        for s in self.socks.values():
            while True:
                try:
                    s.recvfrom(65535)
                except BlockingIOError:
                    break

    def send(self, src, frame, wait=0.6):
        """Send `frame` from XPU `src`; return {xpu: [frames received]} (our own transmission excluded)."""
        self.drain()
        self.socks[src].send(frame)
        got = {i: [] for i in range(self.n)}
        t_end = time.monotonic() + wait
        while time.monotonic() < t_end:
            for i, s in self.socks.items():
                try:
                    data, addr = s.recvfrom(65535)
                except BlockingIOError:
                    continue
                if addr[2] == 4:                  # PACKET_OUTGOING: our own frame
                    continue
                got[i].append(data)
            time.sleep(0.002)
        self.sent.append({"check": None, "src": src, "in": summary(frame),
                          "out": {str(i): summary(v[0][:len(frame)] if len(v[0]) >= len(frame) else v[0]) for i, v in got.items() if v}})
        return got


def ufh_frame(dst, src, dscp=0, ecn=0, psn=7000):
    pdc = PDC(dst=dst, src=src, spdcid=dst, dpdcid=src, psn=psn, dscp=dscp, ecn=ecn)
    msgs = pack_requests([Req(opcode=C.OP_WRITE, address=0x1000 * k, data=bytes([k]) * 256) for k in range(2)])
    return build_ufh16_rodl(pdc, msgs, syn=1), psn


def esun_frame(dst, src, ttl=15, cos=0, ecn=0):
    msgs = pack_requests([Req(opcode=C.OP_WRITE, address=0x2000, data=b"\x5a" * 256)])
    return build_esun_rodl(xmac(dst), xmac(src), rodl_header(psn=42, spdcid=dst, dpdcid=src, syn=1), msgs,
                           cos=cos, ecn=ecn, ttl=ttl, flow_label=0x1234)


def run_checks(n, cli, counters):
    """`cli(cmds)` talks to bmv2 on plane 0; `counters()` reads its counters. Returns a list of results."""
    rig = Rig(n)
    out = []

    def check(name, why, ok, detail=""):
        out.append({"check": name, "why": why, "ok": bool(ok), "detail": detail})
        for s_ in rig.sent:
            if s_["check"] is None:
                s_["check"] = name                  # the frames this check sent

    def only(got, i):
        return [k for k, v in got.items() if v] == [i]

    # 1. UFH_16 forwarded on the destination XPU id, bytes untouched, CRC (with the hidden PSN) good
    f, psn = ufh_frame(dst=2, src=0)
    got = rig.send(0, f)
    rx = got[2][0] if got[2] else b""
    check("ufh16 forwarded by destination id", "UEC §5.4.3: the DA overlay carries the 16-bit destination (Fig 3-120)",
          only(got, 2) and rx[:len(f)] == f and decode(rx[:len(f)], expected_psn=psn).crc_ok,
          f"received at {[k for k, v in got.items() if v]}")

    # 2. unknown destination: dropped, not flooded
    c0 = counters()
    f, _ = ufh_frame(dst=9, src=0)
    got = rig.send(0, f)
    c1 = counters()
    check("ufh16 unknown destination dropped", "ESUN §5: static forwarding, no flooding",
          not any(got.values()) and c1["drops"]["no_route"] == c0["drops"]["no_route"] + 1)

    # 3. ESUN: forwarded by DA, TTL decremented, UET CRC still good (decision D3 masks TTL)
    f = esun_frame(dst=3, src=1, ttl=15)
    got = rig.send(1, f)
    rx = got[3][0][:len(f)] if got[3] else b""
    ttl = Ether(rx)[ESUN].ttl if rx else None
    check("esun forwarded by DA, TTL decremented", "ESUN §5.2: TTL decremented per hop", only(got, 3) and ttl == 14,
          f"ttl {ttl}")
    check("esun UET CRC survives the TTL rewrite", "decision D3: CRC over ESUN masks TTL, CoS and ECN",
          bool(rx) and int.from_bytes(rx[-4:], C.CRC_BYTE_ORDER) == K.esun_crc(rx[:-4]) and rx[14 + 4:] == f[14 + 4:])

    # 4. TTL expiry
    c0 = counters()
    got = rig.send(1, esun_frame(dst=3, src=1, ttl=1))
    c1 = counters()
    check("esun TTL 1 dropped", "ESUN §5.2: a frame whose TTL would reach 0 is discarded",
          not any(got.values()) and c1["drops"]["ttl"] == c0["drops"]["ttl"] + 1)

    # 5. MAC control (CC_Update) is link-local
    c0 = counters()
    got = rig.send(0, cc_update_frame(bytes.fromhex("02a000000000"), {0: 123}))
    c1 = counters()
    check("CC_Update not forwarded", "UEC §5.2.6.2 / IEEE 802.3 Clause 31: MAC control is consumed by the link partner",
          not any(got.values()) and c1["drops"]["mac_control"] == c0["drops"]["mac_control"] + 1)

    # 6. ESUN with an unknown DA and a live TTL: the DA table misses, nothing is flooded
    c0 = counters()
    got = rig.send(0, esun_frame(dst=0xff, src=0, ttl=15))
    c1 = counters()
    check("unknown DA not flooded", "ESUN §5: no learning, no flooding",
          not any(got.values()) and c1["drops"]["no_route"] == c0["drops"]["no_route"] + 1)

    # 7. UDP/IP SUE-T forwarded by DA, unchanged
    f = build_udp_rodl(xmac(1), xmac(0), "10.0.0.1", "10.0.0.0", 49152, rodl_header(psn=5, spdcid=1, dpdcid=0, syn=1),
                       pack_requests([Req(opcode=C.OP_WRITE, address=0, data=b"\x11" * 64)]))
    got = rig.send(0, f)
    check("UDP/IP SUE-T forwarded by DA", "SUE-T §8.3: the third header stack", only(got, 1) and got[1][0][:len(f)] == f)

    # 8. TC -> queue
    c0 = counters()
    rig.send(0, ufh_frame(dst=1, src=0, dscp=0)[0])
    rig.send(0, ufh_frame(dst=1, src=0, dscp=1)[0])
    rig.send(0, esun_frame(dst=1, src=0, cos=3))
    c1 = counters()
    d = [c1["tc_packets"][q] - c0["tc_packets"][q] for q in range(8)]
    check("TC to queue: dscp 0 -> q0, dscp 1 -> q1, ESUN CoS 3 -> q3", "SUE-T §7.3: requests and responses on separate TCs",
          d[0] == 1 and d[1] == 1 and d[3] == 1 and sum(d) == 3, f"per-queue deltas {d}")

    # 9. ECN marking keeps the CRC good (UFH_16 masks byte 7, ESUN masks EH-ECN)
    cli(["register_write SwEgress.ecn_threshold 0 1"])         # 1 = mark whenever depth >= 0
    f, psn = ufh_frame(dst=3, src=2, ecn=1)
    got = rig.send(2, f)
    rx = got[3][0][:len(f)] if got[3] else b""
    check("ufh16 ECT -> CE, CRC still good", "UEC §3.5.26.1: dscp/ecn byte masked in the UET CRC",
          bool(rx) and rx[7] & 3 == 3 and decode(rx, expected_psn=psn).crc_ok)
    f = esun_frame(dst=0, src=3, ecn=2)
    got = rig.send(3, f)
    rx = got[0][0][:len(f)] if got[0] else b""
    check("esun ECT -> CE, CRC still good", "decision D3", bool(rx) and Ether(rx)[ESUN].ecn == 3 and
          int.from_bytes(rx[-4:], C.CRC_BYTE_ORDER) == K.esun_crc(rx[:-4]))
    f, psn = ufh_frame(dst=3, src=2, ecn=0)
    got = rig.send(2, f)
    rx = got[3][0][:len(f)] if got[3] else b""
    check("non-ECT left alone", "RFC 3168: only ECT packets are marked", bool(rx) and rx[7] & 3 == 0)
    cli(["register_write SwEgress.ecn_threshold 0 0"])

    # 10. a UFH_16 ACK (PDS type 7) is forwarded like a request
    f = build_ufh16_ack(dst=0, src=3, spdcid=0, dpdcid=3, ack_psn=10, cack_psn=10)
    got = rig.send(3, f)
    check("ufh16 ACK forwarded", "Fig 3-120: ACKs share the overlay", only(got, 0) and decode(got[0][0][:len(f)]).crc_ok)
    run_checks.sent = rig.sent
    return out


def parse_bmv2_log(text: str) -> list[dict]:
    """bmv2 --log-console output -> one record per packet: parser states and headers, the program's own tables
    (key, hit or miss, action, parameters), log_msg lines, egress port, dropped or transmitted. log_msg lines
    carry only a thread id; a thread works on one packet at a time, so they belong to its current packet."""
    import re
    pk, cur_by_thread, last_table = {}, {}, None
    lines = text.splitlines()
    i = 0
    head = re.compile(r"\[[^\]]*\] \[bmv2\] \[(\w)\] \[thread (\d+)\](?: \[(\d+)\.\d+\] \[cxt \d+\])? (.*)")
    while i < len(lines):
        m = head.match(lines[i])
        i += 1
        if not m:
            continue
        lvl, thread, pid, msg = m.groups()
        if pid is not None:
            pid = int(pid)
            cur_by_thread[thread] = pid
        else:
            pid = cur_by_thread.get(thread)
        if pid is None:
            continue
        r = pk.setdefault(pid, {"id": pid, "port_in": None, "states": [], "headers": [], "tables": [], "msgs": [],
                                "egress_port": None, "tx_port": None, "dropped": False, "deparsed": []})
        if lvl == "I":
            r["msgs"].append(msg)
            continue
        if msg.startswith("Processing packet received on port"):
            r["port_in"] = int(msg.split()[-1])
        elif msg.startswith("Parser 'parser' entering state"):
            r["states"].append(msg.split("'")[3])
        elif msg.startswith("Extracting header"):
            r["headers"].append(msg.split("'")[1])
        elif msg.startswith("Looking up key:"):
            key = {}
            while i < len(lines) and lines[i].startswith("* "):
                f, _, v = lines[i][2:].partition(":")
                key[f.strip()] = v.strip()
                i += 1
            last_table = {"key": key}
        elif msg.startswith("Table '"):
            name = msg.split("'")[1]
            t = dict(last_table or {"key": {}}, table=name, hit=": hit" in msg)
            if name.startswith(("SwIngress.", "SwEgress.")):
                r["tables"].append(t)
            last_table = t
        elif msg.startswith("Action entry is") and last_table is not None and last_table.get("table", "").startswith(("SwIngress.", "SwEgress.")):
            name, _, params = msg[len("Action entry is "):].partition(" - ")
            last_table["action"] = name.strip()
            last_table["params"] = [x.strip() for x in params.split(",") if x.strip()]
        elif msg.startswith("Egress port is"):
            r["egress_port"] = int(msg.split()[-1])
        elif msg.startswith("Dropping packet"):
            r["dropped"] = True
        elif msg.startswith("Deparsing header"):
            r["deparsed"].append(msg.split("'")[1])
        elif msg.startswith("Transmitting packet"):
            r["tx_port"] = int(msg.split()[-1])
    return [pk[k] for k in sorted(pk)]

"""Byte accounting for SUE-T packets on each header stack, and the RoCEv2 baseline (SUE-T §7.2.3).

Everything the endpoint model (sim/suet.py) and the M3 efficiency tables put on the wire goes
through `packet_bytes`, so the simulator and the analytical numbers cannot disagree. The
SUE-T sizes are checked against real frames built by sue/frame.py in tests/test_wire.py.

Sizes are "frame bytes": DA (or UFH overlay) to FCS inclusive. `on_wire` adds the preamble,
SFD and inter-packet gap (20 B) that every frame also costs on the link.
"""

from .model import PREAMBLE_IPG

FCS = 4
UET_CRC = 4                   # UEC §3.5.26
MIN_BODY = 56                 # pad before the UET CRC so CRC + FCS reach the 64 B minimum (§3.5.26.1)
SES_REQ0 = 12                 # UET_HDR_REQUEST_LCL, ac=0 (Fig 3-17)
SES_REQ1 = 8                  # ac=1: 32-bit address offset (Fig 3-19)
SES_RSP = 4                   # UET_HDR_RESPONSE_DATA_LCL (Fig 3-28; SUE-T §7.2.1 says 8, see m1-decisions finding 6)
EHL = {0: 0, 1: 4, 2: 8, 3: 16}

# header bytes before the SES payload: {stack: {"req": request packet, "ack": PDS ACK packet}}
STACKS = {
    "ufh16": {"req": 16, "ack": 20, "name": "UFH_16 + RODL (compressed, Fig 3-68 / 3-120)"},
    "esun": {"req": 14 + 4 + 12, "ack": 14 + 4 + 12, "name": "Ethernet + ESUN EH + RODL (SUE-T Fig 9)"},
    "udp": {"req": 14 + 20 + 8 + 12, "ack": 14 + 20 + 8 + 12, "name": "Ethernet + IPv4 + UDP + RODL (SUE-T Fig 11)"},
}


def pad4(n: int) -> int:
    return (n + 3) & ~3


def req_hdr_bytes(i: int, ehl: int = 0, compress: bool = True) -> int:
    """SES header of the i-th packed request: the first is always ac=0 (UEC §3.4.3.3)."""
    return (SES_REQ0 if i == 0 or not compress else SES_REQ1) + EHL[ehl]


def ses_requests(payloads, ehl: int = 0, compress: bool = True) -> int:
    """Bytes of n packed request CMD_PDUs with these payload sizes (each payload padded to 4 B)."""
    return sum(req_hdr_bytes(i, ehl, compress) + pad4(p) for i, p in enumerate(payloads))


def ses_responses(payloads, ehl: int = 0) -> int:
    return sum(SES_RSP + EHL[ehl] + pad4(p) for p in payloads)


def packet_bytes(stack: str, kind: str, ses: int) -> int:
    """Frame bytes of a request ("req") or PDS ACK ("ack") packet carrying `ses` bytes of SES."""
    body = max(MIN_BODY, STACKS[stack][kind] + ses)
    return body + UET_CRC + FCS


def on_wire(frame_bytes: int) -> int:
    return frame_bytes + PREAMBLE_IPG


# ---------------------------------------------------------------- RoCEv2 (RC) baseline
ROCE_HDR = 14 + 20 + 8 + 12           # Ethernet + IPv4 + UDP + BTH
RETH, AETH, ICRC = 16, 4, 4


def roce_write(payload: int) -> int:
    """RC RDMA Write, one packet (MTU 4096): Eth/IP/UDP/BTH/RETH + payload + ICRC + FCS."""
    return max(64, ROCE_HDR + RETH + payload + ICRC + FCS)


def roce_ack() -> int:
    return max(64, ROCE_HDR + AETH + ICRC + FCS)


def roce_read_request() -> int:
    return max(64, ROCE_HDR + RETH + ICRC + FCS)


def roce_read_response(payload: int) -> int:
    return max(64, ROCE_HDR + AETH + payload + ICRC + FCS)


# ---------------------------------------------------------------- the §7.2.3 table
def transaction_bytes(stack: str, mode: str, n: int, op: str = "store", size: int = 256, ehl: int = 0,
                      resp_cmd: int = 16, piggyback: bool = False, ack_every: int = 1) -> dict:
    """Bytes a packet of n packed transactions costs in both directions, by ACK mode.

    delivery:    the ACK means delivered; the XPU-level response travels back as a command
                 (SUE-T §7.1.1), `resp_cmd` bytes each, packed in one reverse request packet.
                 Stores: no data. Loads: the data rides in that response command. That reverse
                 packet is itself a RODL packet: its ACK rides in the next forward request header
                 (`piggyback`) or costs a dedicated ACK packet every `ack_every` packets.
    operational: the ACK means done (§7.1.2). Stores need nothing but the ACK, which rides in
                 a reverse request header when there is reverse traffic (`piggyback`), else a
                 dedicated ACK packet every `ack_every` packets. Loads: the data comes back in a
                 dedicated ACK packet as packed SES responses.
    """
    payload = n * size
    fwd = packet_bytes(stack, "req", ses_requests([size if op == "store" else 0] * n, ehl))
    bare_ack = 0 if piggyback else packet_bytes(stack, "ack", 0) / ack_every
    if mode == "delivery":
        rev = packet_bytes(stack, "req", ses_requests([size if op == "load" else 0] * n, ehl=0, compress=False)
                           + (resp_cmd - SES_REQ0) * n) + bare_ack    # resp_cmd bytes per response command
    elif op == "load":
        rev = packet_bytes(stack, "ack", ses_responses([size] * n))
    else:
        rev = bare_ack
    return {"payload": payload, "fwd": fwd, "rev": rev, "frame_eff": payload / (fwd + rev),
            "wire_eff": payload / (on_wire(fwd) + (on_wire(rev) if rev else 0))}


def roce_transaction_bytes(op: str = "store", size: int = 256, ack_every: int = 1) -> dict:
    if op == "store":
        fwd, rev = roce_write(size), roce_ack() / ack_every
    else:
        fwd, rev = roce_read_request(), roce_read_response(size)
    return {"payload": size, "fwd": fwd, "rev": rev, "frame_eff": size / (fwd + rev),
            "wire_eff": size / (on_wire(fwd) + on_wire(rev))}

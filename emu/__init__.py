"""netns emulator (M4): real frames on veths, a user-space switch, SUE-T endpoints, fault injection.

    emu/shim.py      how the link layer's preamble/CtlOS fields appear on a veth (decision E1)
    emu/port.py      one link end in real time: LLR (UEC §5.1) + CBFC (§5.2) on a raw socket
    emu/switch.py    user-space switch: N ports, forwarding on the UFH_16 destination / ESUN DA, VOQ
    emu/endpoint.py  SUE-T endpoint: queues, packing, RODL Go-Back-N or SUE-lite, operational ACKs
    emu/lab.py       namespaces, veths, tcpdump, process launch, fault injection, result collection
    emu/analyze.py   pcap -> counts (LLR control, replays, bad CRC, RODL retx) for the write-up

The emulator is about packets and behaviour; timing belongs to sim/.
"""

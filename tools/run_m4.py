"""M4 experiments: the netns emulator (emu/) under faults, and what its captures show.

Two halves, because the lab needs root on Linux and the analysis needs only scapy:

    # in the VM, as root, repo on PYTHONPATH, EMU_PYTHON = a venv with scapy
    sudo env PYTHONPATH=$PWD PYTHONDONTWRITEBYTECODE=1 EMU_PYTHON=$HOME/esun-venv/bin/python \\
        $HOME/esun-venv/bin/python tools/run_m4.py run --out $HOME/emu-out [--only clean,ber-llr]

    # anywhere, after copying the output directory back
    .venv/bin/python tools/run_m4.py report <emu-out>      # -> docs/experiments/emulator-results.json, tables on stdout
"""

import argparse
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

N = 4
BYTES = 32768
BER = "1e-5"

# name -> (n, switch args, endpoint args, per-xpu endpoint args, faults [(t, fn)], capture, timeout)
SCENARIOS = {
    "clean": dict(n=N, sw=[], ep=["--bytes-per-peer", BYTES]),
    "ber-llr": dict(n=N, sw=["--ber", f"p1={BER}"], ep=["--bytes-per-peer", BYTES], per={1: ["--ber", BER]}),
    "ber-nollr": dict(n=N, sw=["--ber", f"p1={BER}", "--no-llr"], ep=["--bytes-per-peer", BYTES, "--no-llr"], per={1: ["--ber", BER]}),
    "ber-lite": dict(n=N, sw=["--ber", f"p1={BER}", "--no-llr"], ep=["--bytes-per-peer", BYTES, "--no-llr", "--no-retx"], per={1: ["--ber", BER]}),
    "lost-cf": dict(n=N, sw=["--drop-cf", "p1=0.7,p2=0.7"], ep=["--bytes-per-peer", BYTES], per={1: ["--drop-cf", "0.7"], 2: ["--drop-cf", "0.7"]}),
    "stuck-rx": dict(n=N, sw=[], ep=["--bytes-per-peer", str(BYTES * 8)], per={1: ["--stall-at", "0.02", "--stall", "0.5"]}),
    "link-flap": dict(n=N, sw=[], ep=["--bytes-per-peer", str(BYTES * 8)],
                      faults=[(0.4, lambda lab: lab.link(1, False)), (0.6, lambda lab: lab.link(1, True))]),
    "link-outage": dict(n=N, sw=[], ep=["--bytes-per-peer", str(BYTES * 8)],
                        faults=[(0.4, lambda lab: lab.link(1, False)), (1.4, lambda lab: lab.link(1, True))], timeout=90),
    "bench": dict(n=2, sw=[], ep=["--bytes-per-peer", str(4 << 20), "--senders", "0"], capture=False, timeout=120),
}


# ---------------------------------------------------------------------------------------------------------
# M5b: four planes. The simulator's five designs (sim/planes.py) on real frames, with the emulator's
# timers: LLR gives up after 50 ms x 9 = 450 ms, so with LLR the transport timer is 1 s; without it 0.2 s.
PLANES, PB = 4, 1 << 20
FAULT_S = 0.5
# Four ports per Python process quadruple each endpoint's own latency, so the timers scale up again (E2):
# LLR replay timer 200 ms (gives up after 1.8 s), transport timer 4 s with LLR, 1 s without.
REPLAY = ["--replay-timer", "0.2"]
WINDOW = ["--window", "8"]            # CPU-bound receivers: a deep window only adds queueing (E10)
PDESIGNS = {
    "sue-t":    dict(llr=True,  ep=["--path", "pin", "--order", "rodl", "--rto", "4.0", "--max-rtos", "3"]),
    "sue-t+fo": dict(llr=True,  ep=["--path", "failover", "--order", "rodl", "--rto", "4.0", "--rtos-before-move", "1"]),
    "metaroce": dict(llr=False, ep=["--path", "spray", "--order", "rud", "--rto", "1.0", "--rtos-before-move", "3",
                                    "--restore", "timer", "--probe", "20"]),
    "mrc":      dict(llr=False, ep=["--path", "spray", "--order", "rud", "--rto", "1.0", "--rtos-before-move", "1",
                                    "--restore", "probe", "--probe", "1.0"]),
    "mrc+llr":  dict(llr=True,  ep=["--path", "spray", "--order", "rud", "--rto", "4.0", "--rtos-before-move", "1",
                                    "--restore", "probe", "--probe", "1.0"]),
}
PSCENARIOS = {
    "clean": {},
    "plane-kill": dict(faults=[(FAULT_S, lambda lab: lab.plane(1, False))]),
    "plane-flap": dict(faults=[(FAULT_S, lambda lab: lab.plane(1, False)), (FAULT_S + 1.0, lambda lab: lab.plane(1, True))]),
    "remote-link": dict(faults=[(FAULT_S, lambda lab: lab.link(2, False, plane=1))]),
    "plane-ber": dict(sw_plane1=["--ber", ",".join(f"p{i}={BER}" for i in range(N))], ep_extra=["--ber", BER, "--ber-port", "1"]),
}


def run_planes(outdir, only=None, designs=None):
    from emu.lab import run as lab_run
    out = Path(outdir) / "planes"
    out.mkdir(parents=True, exist_ok=True)
    for sc in (only or list(PSCENARIOS)):
        for d in (designs or list(PDESIGNS)):
            spec, dd = PSCENARIOS[sc], PDESIGNS[d]
            sw = REPLAY + ([] if dd["llr"] else ["--no-llr"])
            ep = ["--bytes-per-peer", str(PB)] + REPLAY + WINDOW + dd["ep"] + ([] if dd["llr"] else ["--no-llr"]) + spec.get("ep_extra", [])
            dest = out / f"{sc}__{d}"
            if dest.exists():
                shutil.rmtree(dest)
            res = lab_run(N, dest, sw, ep, faults=spec.get("faults", ()), timeout=60, capture=False, planes=PLANES,
                          per_plane={1: spec.get("sw_plane1", [])})
            xs = [x for x in res["xpus"].values() if x]
            tot = {k: sum(x[k] for x in xs) for k in ("done", "failed", "total", "retx_pkts", "rtos", "moves", "bad_marks",
                                                      "restores", "fatal", "gap_drops", "dup_rx")}
            fin = max((x["finished_s"] or 0) for x in xs) if all(x["finished_s"] for x in xs) else None
            llr = sum(x["port"]["replayed"] for x in xs) + sum(p["replayed"] for s_ in (res["switches"] or {}).values() if s_
                                                               for p in s_["ports"].values())
            print(f"{sc:12s} {d:9s} done {tot['done']}/{tot['total']} failed {tot['failed']} fin {fin} retx {tot['retx_pkts']} "
                  f"rto {tot['rtos']} mv {tot['moves']} bad {tot['bad_marks']} rest {tot['restores']} fatal {tot['fatal']} "
                  f"llr {llr} completed {res['completed']}", flush=True)


def report_planes(outdir):
    out = Path(outdir) / "planes"
    rows = {}
    for d in sorted(out.glob("*__*")):
        f = d / "result.json"
        if not f.exists():
            continue
        sc, des = d.name.split("__")
        r = json.loads(f.read_text())
        xs = [x for x in r["xpus"].values() if x]
        sws = [s_ for s_ in (r.get("switches") or {}).values() if s_]
        a = {k: sum(x[k] for x in xs) for k in ("done", "failed", "total", "retx_pkts", "rtos", "moves", "bad_marks",
                                                "restores", "fatal", "gap_drops", "dup_rx")}
        a["finished_s"] = max(x["finished_s"] for x in xs) if all(x["finished_s"] for x in xs) else None
        a["lat_max_ms"] = max((x["lat_max_ms"] or 0) for x in xs)
        a["llr_replays"] = sum(x["port"]["replayed"] for x in xs) + sum(p["replayed"] for s_ in sws for p in s_["ports"].values())
        a["llr_flushes"] = sum(x["port"]["flushes"] for x in xs) + sum(p["flushes"] for s_ in sws for p in s_["ports"].values())
        a["port_pkts"] = [sum(x["port_pkts"][q] for x in xs) for q in range(PLANES)]
        rows.setdefault(sc, {})[des] = a
    (ROOT / "docs" / "experiments" / "emulator-planes-results.json").write_text(json.dumps(rows, indent=1))
    order = [d for d in PDESIGNS]
    print("| Scenario | " + " | ".join(order) + " |")
    print("|---|" + "---|" * len(order))
    for sc in PSCENARIOS:
        if sc not in rows:
            continue
        cells = []
        for d in order:
            a = rows[sc].get(d)
            if a is None:
                cells.append("not run")
                continue
            fin = f"{a['finished_s']:.2f} s" if a["finished_s"] else "**did not finish**"
            cells.append(f"{fin}, {a['failed']} failed; {a['rtos']} RTO / {a['retx_pkts']} resent / {a['llr_replays']} LLR")
        print(f"| {sc} | " + " | ".join(cells) + " |")
    return rows


# ---------------------------------------------------------------------------------------------------------
# Captures for the packet viewer (docs/viz, M4): two XPUs, XPU 0 -> XPU 1 only, so the path is
# XPU A -> switch -> XPU B and both links of one run are captured (tools/pcap2trace.py reads them).
VIEW = {
    "cap-clean": dict(ep=["--bytes-per-peer", "65536", "--senders", "0"]),
    "cap-ber-hop2": dict(sw=["--ber", "p1=2e-5"], ep=["--bytes-per-peer", "65536", "--senders", "0"], per={1: ["--ber", "2e-5"]}),
    "cap-outage-hop1": dict(ep=["--bytes-per-peer", "524288", "--senders", "0"],
                            faults=[(0.15, lambda lab: lab.link(0, False)), (0.85, lambda lab: lab.link(0, True))]),
    "cap-no-llr": dict(sw=["--ber", "p0=2e-5", "--no-llr"], ep=["--bytes-per-peer", "65536", "--senders", "0", "--no-llr", "--rto", "0.3"],
                       per={0: ["--ber", "2e-5"]}),
}


def run_viewer(outdir):
    from emu.lab import run as lab_run
    out = Path(outdir) / "viewer"
    out.mkdir(parents=True, exist_ok=True)
    for name, sc in VIEW.items():
        d = out / name
        if d.exists():
            shutil.rmtree(d)
        res = lab_run(2, d, sc.get("sw", []), sc.get("ep", []), sc.get("per"), sc.get("faults", ()), timeout=30)
        x0 = res["xpus"]["0"]
        print(f"{name:16s} done {x0['done']}/{x0['total']} failed {x0['failed']} retx {x0['retx_pkts']} rto {x0['rtos']} "
              f"llr replays {x0['port']['replayed']} completed {res['completed']}", flush=True)


def run(outdir, only=None):
    from emu.lab import run as lab_run
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    names = only or list(SCENARIOS)
    for name in names:
        sc = SCENARIOS[name]
        d = out / name
        if d.exists():
            shutil.rmtree(d)
        print(f"== {name}", flush=True)
        res = lab_run(sc["n"], d, sc.get("sw", []), sc.get("ep", []), sc.get("per"), sc.get("faults", ()),
                      timeout=sc.get("timeout", 60), capture=sc.get("capture", True))
        for i, x in res["xpus"].items():
            if x is None:
                print(f"   xpu{i}: no result")
                continue
            p = x["port"]
            print(f"   xpu{i}: done {x['done']}/{x['total']} failed {x['failed']} pkts {x['tx_pkts']} retx {x['retx_pkts']} "
                  f"nack {x['nacks_tx']}/{x['nacks_rx']} rto {x['rtos']} fatal {x['fatal']} fin {x['finished_s']} s | "
                  f"llr replay {p['replayed']} timer {p['timer_replays']} flush {p['flushes']} bad {p['rx_bad']} "
                  f"stalls {p['credit_stalls']} ovf {p['overflow']} tx_err {p['tx_err']} cc_recl {p['cc_reclaimed']}")
        if res["switch"]:
            for n, p in res["switch"]["ports"].items():
                print(f"   sw {n}: tx {p['tx_frames']} replay {p['replayed']} timer {p['timer_replays']} flush {p['flushes']} "
                      f"bad {p['rx_bad']} stalls {p['credit_stalls']} ovf {p['overflow']} tx_err {p['tx_err']} cf_drop {p['cf_dropped']} "
                      f"cc_recl {p['cc_reclaimed']} inits {p['inits']}")
        print(f"   completed: {res['completed']}", flush=True)


def report(outdir):
    from emu.analyze import analyze
    out = Path(outdir)
    results = {}
    for name in SCENARIOS:
        d = out / name
        f = d / "result.json"
        if not f.exists():
            continue
        r = json.loads(f.read_text())
        xs = [x for x in r["xpus"].values() if x]
        sw = r["switch"]["ports"] if r["switch"] else {}
        agg = {k: sum(x[k] for x in xs) for k in ("total", "done", "failed", "tx_pkts", "retx_pkts", "nacks_tx", "rtos", "fatal",
                                                  "dup_rx", "gap_drops", "acks_tx", "piggybacked", "rx_bad_crc", "rx_unknown_psn")}
        agg["finished_s"] = max((x["finished_s"] or 0) for x in xs)
        agg["lat_p50_ms"] = round(max((x["lat_p50_ms"] or 0) for x in xs), 2)
        agg["lat_p99_ms"] = round(max((x["lat_p99_ms"] or 0) for x in xs), 2)
        agg["pack_avg"] = round(sum(x["pack_avg"] * x["tx_pkts"] for x in xs) / max(1, agg["tx_pkts"]), 2)
        ports = list(sw.values()) + [x["port"] for x in xs]
        agg["llr"] = {k: sum(p[k] for p in ports) for k in ("replayed", "timer_replays", "nacks_tx", "flushes", "flush_lost", "rx_bad",
                                                             "rx_dup", "rx_ooo", "credit_stalls", "overflow", "cf_dropped", "cc_reclaimed",
                                                             "tx_err", "inits", "corrupted", "rx_crc_drop")}
        agg["completed"] = r["completed"]
        agg["pcaps"] = {p.stem: analyze(str(p)) for p in sorted(d.glob("link*.pcap"))}
        results[name] = agg
    (ROOT / "docs" / "experiments" / "emulator-results.json").write_text(json.dumps(results, indent=1))

    def row(name, a):
        L = a["llr"]
        return (f"| {name} | {a['done']} / {a['failed']} of {a['total']} | {a['finished_s']:.2f} s | {a['lat_p50_ms']} / {a['lat_p99_ms']} ms | "
                f"{L['rx_bad']} / {L['nacks_tx']} / {L['replayed']} / {L['timer_replays']} / {L['flushes']} | "
                f"{a['gap_drops']} / {a['nacks_tx']} / {a['retx_pkts']} / {a['rtos']} / {a['fatal']} | "
                f"{L['credit_stalls']} / {L['overflow']} / {L['cf_dropped']} / {L['cc_reclaimed']} |")
    print("| Scenario | Stores done / failed | Completion | p50 / p99 latency | LLR: bad / NACK / replayed / timer / FLUSH | "
          "RODL: gaps / NACK / retx / RTO / PDCs closed | CBFC: stalls / overflow / CF lost / CC reclaimed |")
    print("|---|---|---|---|---|---|---|")
    for name, a in results.items():
        print(row(name, a))
    print()
    print("| Scenario | Link | Frames XPU→sw / sw→XPU | Bad CRC | Replayed | LLR ACK / NACK / INIT+ECHO | CF_Update | CC_Update | RODL req (syn, retx) | CMD_PDUs | ACK / NACK pkts | other |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|")
    for name, a in results.items():
        for link, c in a["pcaps"].items():
            g = c.get
            print(f"| {name} | {link} | {g('xpu_frames', 0)} / {g('sw_frames', 0)} | {g('xpu_bad', 0) + g('sw_bad', 0)} | "
                  f"{g('xpu_replayed', 0) + g('sw_replayed', 0)} | {g('xpu_llr_ack', 0) + g('sw_llr_ack', 0)} / {g('xpu_llr_nack', 0) + g('sw_llr_nack', 0)} / "
                  f"{g('xpu_llr_init', 0) + g('sw_llr_init', 0) + g('xpu_llr_init_echo', 0) + g('sw_llr_init_echo', 0)} | "
                  f"{g('xpu_cf_update', 0) + g('sw_cf_update', 0)} | {g('xpu_cc_update', 0) + g('sw_cc_update', 0)} | "
                  f"{g('rodl_req', 0)} ({g('rodl_syn', 0)}, {g('rodl_retx_flag', 0)}) | {g('cmd_pdus', 0)} | {g('ack_pkts', 0)} / {g('nack_pkts', 0)} | {g('other', 0)} |")
    return results


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--out", required=True)
    r.add_argument("--only", default="")
    r.add_argument("--designs", default="", help="--planes only: comma list of designs")
    r.add_argument("--planes", action="store_true", help="the four-plane M5b scenarios instead of the M4 ones")
    r.add_argument("--viewer", action="store_true", help="two-XPU path captures for the packet viewer")
    p = sub.add_parser("report")
    p.add_argument("outdir")
    p.add_argument("--planes", action="store_true")
    a = ap.parse_args(argv)
    only = [s for s in getattr(a, "only", "").split(",") if s] or None
    if a.cmd == "run" and getattr(a, "viewer", False):
        run_viewer(a.out)
    elif a.cmd == "run" and a.planes:
        run_planes(a.out, only, [d for d in a.designs.split(",") if d] or None)
    elif a.cmd == "run":
        run(a.out, only)
    elif a.planes:
        report_planes(a.outdir)
    else:
        report(a.outdir)


if __name__ == "__main__":
    main()

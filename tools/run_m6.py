"""M6: the P4 switch (p4/esun_switch.p4) in bmv2: compile, frame-level checks, and SUE-T traffic through it.

Runs in the VM as root, with Docker and the p4lang/p4c image (it carries p4c and bmv2 simple_switch):

    sudo env PYTHONPATH=$PWD PYTHONDONTWRITEBYTECODE=1 EMU_PYTHON=$HOME/esun-venv/bin/python \\
        $HOME/esun-venv/bin/python tools/run_m6.py --out $HOME/m6-out [--compile-to $HOME/p4build]

Writes <out>/p4-results.json; copy it to docs/experiments/ and the compiled JSON to p4/build/.
"""

import argparse
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from emu import lab as L  # noqa: E402
from emu.p4check import run_checks  # noqa: E402

N = 4
RAW = ["--no-llr", "--no-cbfc", "--no-shim"]


def compile_p4(dest):
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    p = subprocess.run(["docker", "run", "--rm", "-v", f"{ROOT / 'p4'}:/src:ro", "-v", f"{dest}:/out", L.P4_IMAGE,
                        "p4c", "--target", "bmv2", "--arch", "v1model", "-o", "/out", "/src/esun_switch.p4"],
                       capture_output=True, text=True)
    warnings = [x for x in (p.stdout + p.stderr).splitlines() if x.strip() and "platform" not in x]
    return {"ok": p.returncode == 0 and (dest / "esun_switch.json").exists(), "messages": warnings}


def frame_checks(out):
    lab = L.Lab(N, Path(out) / "checks", capture=True, planes=1, switch="bmv2")
    try:
        lab.build()
        lab.start_capture()
        lab.start_bmv2(0)
        res = run_checks(N, lambda c: lab.bmv2_cli(0, c), lambda: lab.bmv2_counters(0))
        lab.stop()
        return res
    finally:
        subprocess.run(["docker", "rm", "-f", "bmv2-sw0"], capture_output=True)
        lab.destroy()


def traffic(out, name, planes, ep_args, faults=()):
    t = time.monotonic()
    res = L.run(N, Path(out) / name, (), RAW + list(ep_args), faults=faults, timeout=90, capture=planes == 1,
                planes=planes, switch="bmv2")
    for p in range(planes):
        subprocess.run(["docker", "rm", "-f", f"bmv2-sw{p}"], capture_output=True)
    xs = [x for x in res["xpus"].values() if x]
    return {
        "completed": res["completed"], "planes": planes, "wall_s": round(time.monotonic() - t, 1),
        "done": sum(x["done"] for x in xs), "failed": sum(x["failed"] for x in xs), "total": sum(x["total"] for x in xs),
        "finished_s": max(x["finished_s"] for x in xs) if all(x["finished_s"] for x in xs) else None,
        "retx": sum(x["retx_pkts"] for x in xs), "rtos": sum(x["rtos"] for x in xs),
        "bad_marks": sum(x["bad_marks"] for x in xs), "port_pkts": [sum(x["port_pkts"][q] for x in xs) for q in range(planes)],
        "bmv2": res.get("bmv2"),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    ap.add_argument("--compile-to", default="")
    a = ap.parse_args(argv)
    out = Path(a.out)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    res = {}
    if a.compile_to:
        res["compile"] = compile_p4(a.compile_to)
        print("compile:", res["compile"], flush=True)
    res["checks"] = frame_checks(out)
    for c in res["checks"]:
        print(("PASS " if c["ok"] else "FAIL ") + c["check"], c["detail"], flush=True)
    res["traffic"] = {}
    runs = [
        ("1-plane-pinned", 1, ["--bytes-per-peer", "262144", "--path", "pin", "--order", "rodl", "--rto", "1.0"], ()),
        ("4-plane-spray", 4, ["--bytes-per-peer", "1048576", "--path", "spray", "--order", "rud", "--rto", "1.0",
                              "--window", "8", "--probe", "1.0"], ()),
        ("4-plane-spray-plane-kill", 4, ["--bytes-per-peer", "1048576", "--path", "spray", "--order", "rud", "--rto", "1.0",
                                         "--window", "8", "--probe", "1.0"], [(0.5, lambda lab: lab.plane(1, False))]),
        ("4-plane-pinned-plane-kill", 4, ["--bytes-per-peer", "1048576", "--path", "pin", "--order", "rodl", "--rto", "1.0",
                                          "--window", "8", "--max-rtos", "3"], [(0.5, lambda lab: lab.plane(1, False))]),
    ]
    for name, planes, args, faults in runs:
        r = traffic(out, name, planes, args, faults)
        res["traffic"][name] = r
        print(name, {k: v for k, v in r.items() if k != "bmv2"}, flush=True)
        print("   bmv2:", r["bmv2"], flush=True)
    (out / "p4-results.json").write_text(json.dumps(res, indent=1))


if __name__ == "__main__":
    main()

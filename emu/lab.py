"""The lab: network namespaces, veths, captures, the switch and endpoint processes, faults.

Topology (one plane; M5 adds more):

    xpu0 ns: eth0 (02:a0:00:00:00:00) ---veth--- sw0-p0 (02:5f:00:00:00:00) : sw0 ns, user-space switch
    xpu1 ns: eth0 (02:a0:00:00:00:01) ---veth--- sw0-p1 ...

Needs root on Linux (ip, tcpdump). `EMU_PYTHON` names the interpreter for the processes (a venv
with scapy); the repo must be on PYTHONPATH. tcpdump runs on the switch side of every link, so one
pcap per link holds both directions.

    sudo -E env PYTHONPATH=$PWD EMU_PYTHON=~/esun-venv/bin/python python3 -m emu.lab --n 4 --out /tmp/emu-clean
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

PY = os.environ.get("EMU_PYTHON", sys.executable)


def sh(*args, check=True):
    return subprocess.run([str(a) for a in args], check=check, capture_output=True, text=True)


def ns(name, *args, check=True):
    return sh("ip", "netns", "exec", name, *args, check=check)


class Lab:
    def __init__(self, n, outdir, capture=True, planes=1):
        self.n, self.out, self.capture, self.planes = n, Path(outdir), capture, planes
        self.out.mkdir(parents=True, exist_ok=True)
        self.procs, self.dumps = {}, []
        self.env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")

    # ------------------------------------------------------------ topology
    def build(self):
        self.destroy()
        sh("sysctl", "-q", "-w", "net.core.netdev_max_backlog=100000", check=False)   # veth bursts queue here
        for i in range(self.n):
            sh("ip", "netns", "add", f"xpu{i}")
        for p in range(self.planes):                     # one switch per plane; XPU i's port p -> switch p's port i
            sw = f"sw{p}"
            sh("ip", "netns", "add", sw)
            for i in range(self.n):
                sh("ip", "link", "add", f"x{i}e{p}", "type", "veth", "peer", "name", f"{sw}-p{i}")
                sh("ip", "link", "set", f"x{i}e{p}", "netns", f"xpu{i}")
                sh("ip", "link", "set", f"{sw}-p{i}", "netns", sw)
                ns(f"xpu{i}", "ip", "link", "set", "dev", f"x{i}e{p}", "name", f"eth{p}")
                ns(f"xpu{i}", "sysctl", "-q", "-w", f"net.ipv6.conf.eth{p}.disable_ipv6=1")
                ns(sw, "sysctl", "-q", "-w", f"net.ipv6.conf.{sw}-p{i}.disable_ipv6=1")
                ns(f"xpu{i}", "ip", "link", "set", "dev", f"eth{p}", "address", f"02:a0:00:00:00:{i:02x}", "mtu", "9000", "up")
                ns(sw, "ip", "link", "set", "dev", f"{sw}-p{i}", "address", f"02:5f:00:00:00:{i:02x}", "mtu", "9000", "up")
        time.sleep(0.2)

    def destroy(self):
        out = sh("ip", "netns", "list", check=False).stdout
        for line in out.splitlines():
            name = line.split()[0]
            if name.startswith("sw") or name.startswith("xpu"):
                sh("ip", "netns", "del", name, check=False)

    # ------------------------------------------------------------ processes
    def start_capture(self):
        if not self.capture:
            return
        for pl in range(self.planes):
            for i in range(self.n):
                name = f"link{i}.pcap" if self.planes == 1 else f"p{pl}-link{i}.pcap"
                p = subprocess.Popen(["ip", "netns", "exec", f"sw{pl}", "tcpdump", "-i", f"sw{pl}-p{i}", "-w", str(self.out / name),
                                      "-U", "-s", "0", "-q"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.dumps.append(p)
        time.sleep(0.5)                              # let tcpdump attach before the INIT handshake

    def start_switch(self, args=(), plane=0):
        tag = "switch" if self.planes == 1 else f"switch{plane}"
        cmd = ["ip", "netns", "exec", f"sw{plane}", PY, "-m", "emu.switch", "--ports", str(self.n), "--ifname", f"sw{plane}-p{{i}}",
               "--out", str(self.out / f"{tag}.json"), "--log", str(self.out / f"{tag}.log"), *map(str, args)]
        self.procs[tag] = subprocess.Popen(cmd, env=self.env, stdout=open(self.out / f"{tag}.stdout", "w"), stderr=subprocess.STDOUT)

    def start_endpoint(self, i, args=()):
        cmd = ["ip", "netns", "exec", f"xpu{i}", PY, "-m", "emu.endpoint", "--xpu", str(i), "--n", str(self.n),
               "--planes", str(self.planes), "--go-file", str(self.out / "go"),
               "--out", str(self.out / f"xpu{i}.json"), "--log", str(self.out / f"xpu{i}.log"), *map(str, args)]
        self.procs[f"xpu{i}"] = subprocess.Popen(cmd, env=self.env, stdout=open(self.out / f"xpu{i}.stdout", "w"), stderr=subprocess.STDOUT)

    def link(self, i, up, plane=0):
        ns(f"sw{plane}", "ip", "link", "set", "dev", f"sw{plane}-p{i}", "up" if up else "down")

    def plane(self, plane, up):
        for i in range(self.n):
            self.link(i, up, plane)

    def all_done(self):
        return all((self.out / f"xpu{i}.json.done").exists() for i in range(self.n))

    def wait(self, timeout, faults=()):
        """Run until every endpoint finished its own transfers; apply (t, fn) faults on the way."""
        t0 = time.monotonic()
        pending = sorted(faults, key=lambda f: f[0])
        while time.monotonic() - t0 < timeout:
            now = time.monotonic() - t0
            while pending and pending[0][0] <= now:
                _, fn = pending.pop(0)
                fn(self)
            if not pending and self.all_done():
                return True
            if any(p.poll() is not None for p in self.procs.values()):
                return False                         # something died: collect what there is
            time.sleep(0.05)
        return False

    def stop(self):
        time.sleep(0.3)                              # let the last ACKs and CtlOS land in the captures
        for name, p in self.procs.items():
            if p.poll() is None:
                p.send_signal(signal.SIGTERM)
        for p in self.procs.values():
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()
        for p in self.dumps:
            p.send_signal(signal.SIGINT)
        for p in self.dumps:
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()

    def results(self):
        def load(f):
            f = self.out / f
            return json.loads(f.read_text()) if f.exists() else None
        res = {"switch": load("switch.json") if self.planes == 1 else None, "xpus": {},
               "switches": {p: load(f"switch{p}.json") for p in range(self.planes)} if self.planes > 1 else None}
        for i in range(self.n):
            f = self.out / f"xpu{i}.json"
            res["xpus"][str(i)] = json.loads(f.read_text()) if f.exists() else None
        return res


def run(n, outdir, switch_args=(), endpoint_args=(), per_xpu=None, faults=(), timeout=60, capture=True, planes=1,
        per_plane=None):
    """One lab run; returns the merged results dict (and leaves pcaps/logs in outdir). `per_plane` adds switch
    arguments for one plane's switch (e.g. bit errors on plane 1)."""
    lab = Lab(n, outdir, capture=capture, planes=planes)
    try:
        lab.build()
        lab.start_capture()
        for p in range(planes):
            lab.start_switch(list(switch_args) + list((per_plane or {}).get(p, ())), plane=p)
        time.sleep(0.3)
        for i in range(n):
            lab.start_endpoint(i, list(endpoint_args) + list((per_xpu or {}).get(i, ())))
        t_ready = time.monotonic() + 30
        while time.monotonic() < t_ready and not all((lab.out / f"xpu{i}.json.ready").exists() for i in range(n)):
            time.sleep(0.01)
        time.sleep(0.05)
        (lab.out / "go").write_text("1")                 # everyone listens: start together (fault times count from here)
        ok = lab.wait(timeout, faults)
        lab.stop()
        res = lab.results()
        res["completed"] = ok
        res["n"] = n
        res["planes"] = planes
        (lab.out / "result.json").write_text(json.dumps(res, indent=1))
        return res
    finally:
        lab.destroy()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--n", type=int, default=4)
    ap.add_argument("--out", required=True)
    ap.add_argument("--timeout", type=float, default=60)
    ap.add_argument("--no-capture", action="store_true")
    ap.add_argument("--switch-args", default="")
    ap.add_argument("--endpoint-args", default="")
    a = ap.parse_args(argv)
    res = run(a.n, a.out, a.switch_args.split(), a.endpoint_args.split(), timeout=a.timeout, capture=not a.no_capture)
    print(json.dumps({k: v for k, v in res.items() if k != "xpus"}, indent=1))
    for i, r in res["xpus"].items():
        if r:
            print(f"xpu{i}: done {r['done']}/{r['total']} failed {r['failed']} pkts {r['tx_pkts']} retx {r['retx_pkts']} "
                  f"nacks {r['nacks_tx']}/{r['nacks_rx']} rtos {r['rtos']} finished {r['finished_s']} s  "
                  f"llr replays {r['port']['replayed']} nacks {r['port']['nacks_tx']}")


if __name__ == "__main__":
    main()

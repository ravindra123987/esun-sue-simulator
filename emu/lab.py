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


P4_IMAGE = os.environ.get("P4_IMAGE", "p4lang/p4c:latest")       # carries p4c and bmv2 simple_switch
P4_JSON = Path(__file__).resolve().parent.parent / "p4" / "build" / "esun_switch.json"


class Lab:
    def __init__(self, n, outdir, capture=True, planes=1, switch="python"):
        self.n, self.out, self.capture, self.planes = n, Path(outdir), capture, planes
        self.switch = switch                     # "python" (emu/switch.py) | "bmv2" (p4/esun_switch.p4)
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
            ns(sw, "ip", "link", "set", "lo", "up")      # bmv2's Thrift control server listens on 127.0.0.1
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
                # --immediate-mode: no block buffering in the capture ring, or a short run's frames are still
                # waiting there when tcpdump is stopped and never reach the file
                p = subprocess.Popen(["ip", "netns", "exec", f"sw{pl}", "tcpdump", "-i", f"sw{pl}-p{i}", "-w", str(self.out / name),
                                      "-U", "--immediate-mode", "-s", "0", "-q"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.dumps.append(p)
        time.sleep(0.5)                              # let tcpdump attach before the INIT handshake

    # ------------------------------------------------------------ the P4 switch (M6)
    def bmv2_cmds(self):
        """Static tables: XPU i is behind port i (by UFH_16 destination and by MAC); TC 0 -> queue 0,
        TC 1 (ACKs, responses) -> queue 1; ESUN CoS c -> queue c."""
        cmds = []
        for i in range(self.n):
            cmds.append(f"table_add ufh_fwd set_port {i} => {i}")
            cmds.append(f"table_add l2_fwd set_port 02:a0:00:00:00:{i:02x} => {i}")
        cmds += ["table_add tc_ufh set_queue 0 => 0", "table_add tc_ufh set_queue 1 => 1"]
        cmds += [f"table_add tc_esun set_queue {c} => {c}" for c in range(8)]
        return cmds

    def bmv2_cli(self, plane, cmds):
        p = subprocess.run(["docker", "exec", "-i", f"bmv2-sw{plane}", "ip", "netns", "exec", f"sw{plane}",
                            "simple_switch_CLI", "--thrift-port", "9090"], input="\n".join(cmds) + "\n",
                           capture_output=True, text=True)
        return p.stdout

    def start_bmv2(self, plane=0, log=False):
        """log=True: bmv2 logs every packet's parser states, table lookups and log_msg lines (docker logs)."""
        name = f"bmv2-sw{plane}"
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        ifs = sum([["-i", f"{i}@sw{plane}-p{i}"] for i in range(self.n)], [])
        cmd = ["docker", "run", "-d", "--rm", "--name", name, "--privileged", "--network", "host", "--pid", "host",
               "-v", "/var/run/netns:/var/run/netns", "-v", f"{P4_JSON.parent}:/p4:ro", P4_IMAGE,
               "ip", "netns", "exec", f"sw{plane}", "simple_switch", "--thrift-port", "9090",
               *(["--log-console", "--log-level", "debug"] if log else []),
               *ifs, "/p4/" + P4_JSON.name, "--", "--priority-queues", "8"]    # target options after "--"
        sh(*cmd)
        for _ in range(300):                     # wait for the Thrift server, then load the tables
            out = self.bmv2_cli(plane, ["show_tables"])
            if "ufh_fwd" in out:
                break
            time.sleep(0.2)
        else:
            raise RuntimeError(f"bmv2 on plane {plane} did not come up")
        self.bmv2_cli(plane, self.bmv2_cmds())
        self.procs[name] = None

    def bmv2_counters(self, plane):
        cmds = [f"counter_read SwIngress.tc_ctr {q}" for q in range(8)] + \
               [f"counter_read SwIngress.drop_ctr {k}" for k in range(4)] + ["counter_read SwEgress.ce_ctr 0"]
        out = self.bmv2_cli(plane, cmds)
        import re
        vals = [int(m) for m in re.findall(r"(\d+) packets", out)]       # "SwIngress.tc_ctr[0]= (0 bytes, 0 packets)"
        if len(vals) != 13:
            return {"raw": out[-500:]}
        return {"tc_packets": vals[:8], "drops": dict(zip(("no_route", "ttl", "mac_control", "parse"), vals[8:12])),
                "ce_marked": vals[12]}

    def start_switch(self, args=(), plane=0):
        if self.switch == "bmv2":
            return self.start_bmv2(plane)
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
            if any(p is not None and p.poll() is not None for p in self.procs.values()):
                return False                         # something died: collect what there is
            time.sleep(0.05)
        return False

    def stop(self):
        time.sleep(0.5)                              # let the last ACKs and CtlOS land in the captures
        if self.switch == "bmv2":
            self.counters = {p: self.bmv2_counters(p) for p in range(self.planes)}
        for name, p in self.procs.items():
            if p is not None and p.poll() is None:
                p.send_signal(signal.SIGTERM)
        for name, p in self.procs.items():
            if p is None:
                subprocess.run(["docker", "rm", "-f", name], capture_output=True)
                continue
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
        per_plane=None, switch="python"):
    """One lab run; returns the merged results dict (and leaves pcaps/logs in outdir). `per_plane` adds switch
    arguments for one plane's switch (e.g. bit errors on plane 1)."""
    lab = Lab(n, outdir, capture=capture, planes=planes, switch=switch)
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
        res["switch"] = res["switch"] if switch == "python" else None
        if switch == "bmv2":
            res["bmv2"] = getattr(lab, "counters", None)
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

"""Run wireshark/sue.lua through tshark over the golden pcaps.

The Lua CRC code is written independently of sue/crc.py, so matching results
cross-check both implementations and the byte layouts. Skipped without tshark.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from scapy.layers.l2 import Ether
from scapy.utils import PcapWriter, rdpcap

ROOT = Path(__file__).resolve().parent.parent
GOLDEN = ROOT / "pcaps" / "golden"
LUA = ROOT / "wireshark" / "sue.lua"
TSHARK = shutil.which("tshark") or "/Applications/Wireshark.app/Contents/MacOS/tshark"
HAVE_TSHARK = Path(TSHARK).exists()
pytestmark = pytest.mark.skipif(not HAVE_TSHARK, reason="tshark not installed")

MANIFEST = json.loads((GOLDEN / "golden.json").read_text())["captures"]
FIELDS = ["sue.crc.status", "sue.ses.opcode", "sue.ses.rsp.opcode", "sue.pds.psn", "sue.pds.rodl.psn_gap",
          "sue.ufh.dst", "sue.ufh.src", "sue.pds.spdcid", "sue.pds.rodl.spdcid", "sue.ses.lcl.target",
          "sue.pds.cack_psn", "sue.pds.ack_psn"]
# golden.json "fields" key -> dissector field(s)
FIELD_MAP = {"dst": ["sue.ufh.dst"], "src": ["sue.ufh.src"], "spdcid": ["sue.pds.spdcid", "sue.pds.rodl.spdcid"],
             "cack_psn": ["sue.pds.cack_psn"], "ack_psn": ["sue.pds.ack_psn"]}


def tshark(pcap: Path, *opts: str, fields=FIELDS) -> list[dict]:
    cmd = [TSHARK, "-X", f"lua_script:{LUA}", *opts, "-r", str(pcap), "-T", "fields"]
    for fl in fields:
        cmd += ["-e", fl]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True)
    assert "Lua" not in out.stderr and "error" not in out.stderr.lower(), out.stderr
    rows = []
    for line in out.stdout.splitlines():
        if line:
            vals = (line.split("\t") + [""] * len(fields))[:len(fields)]
            rows.append(dict(zip(fields, vals)))
    return rows


def count(v: str) -> int:
    return len(v.split(",")) if v else 0


@pytest.mark.parametrize("cap", MANIFEST, ids=[c["file"] for c in MANIFEST])
def test_golden_frames(cap):
    first_psn = cap["frames"][0]["expected_psn"]
    opts = ["-o", f"sue.assume_psn:{first_psn}"] if first_psn is not None else []
    rows = tshark(GOLDEN / cap["file"], *opts)
    assert len(rows) == len(cap["frames"])
    for i, (row, exp) in enumerate(zip(rows, cap["frames"])):
        want = exp["dissector"]
        where = f"{cap['file']} frame {i + 1} ({exp['note']})"
        assert row["sue.crc.status"] == str(want["crc_status"]), where
        if want["crc_status"] == 0:
            assert count(row["sue.ses.opcode"]) + count(row["sue.ses.rsp.opcode"]) == exp["ses_messages"], where
        if "psn" in want:
            assert row["sue.pds.psn"] == str(want["psn"]), where
            assert row["sue.pds.rodl.psn_gap"] == ("" if want["gap"] == 0 else str(want["gap"])), where
        if want["crc_status"] != 0:
            continue
        # Lua decodes the same field values as the Python layers
        for key, val in exp["fields"].items():
            if key == "targets":
                got = [int(x, 0) for x in row["sue.ses.lcl.target"].split(",") if x]
                assert got == val, f"{where}: targets {got} != {val}"
            else:
                got = next((row[fl] for fl in FIELD_MAP[key] if row[fl]), "")
                assert got and int(got, 0) == val, f"{where}: {key} {got!r} != {val}"


def test_wrong_assumed_psn_is_resynced_or_bad():
    # 1043 is one past the real PSN 1042: found by the resync window as a step back.
    rows = tshark(GOLDEN / "02-ufh16-rodl-two-stores.pcap", "-o", "sue.assume_psn:1043")
    assert rows[0]["sue.crc.status"] == "0" and rows[0]["sue.pds.psn"] == "1042"
    assert rows[0]["sue.pds.rodl.psn_gap"] == "-1"
    # Far outside the window: Bad.
    rows = tshark(GOLDEN / "02-ufh16-rodl-two-stores.pcap", "-o", "sue.assume_psn:5000")
    assert rows[0]["sue.crc.status"] == "1"
    # Resync off: an off-by-one PSN is Bad.
    rows = tshark(GOLDEN / "02-ufh16-rodl-two-stores.pcap", "-o", "sue.assume_psn:1043", "-o", "sue.psn_window:0")
    assert rows[0]["sue.crc.status"] == "1"


def test_unknown_psn_is_unverified():
    rows = tshark(GOLDEN / "02-ufh16-rodl-two-stores.pcap")
    assert rows[0]["sue.crc.status"] == "2"


def test_truncated_frames_never_raise_lua_errors(tmp_path):
    """Cut every golden frame at several lengths; the dissector must report, not crash."""
    out = tmp_path / "truncated.pcap"
    w = PcapWriter(str(out), linktype=1, sync=True)
    n = 0
    for cap in MANIFEST:
        for pkt in rdpcap(str(GOLDEN / cap["file"])):
            raw = bytes(pkt)
            for cut in sorted({14, 15, 16, 17, 18, 20, 22, 24, 28, 30, 34, len(raw) - 5, len(raw) - 1}):
                if 0 < cut < len(raw):
                    p = Ether(raw[:cut])
                    p.time = pkt.time
                    w.write(p)
                    n += 1
    w.close()
    res = subprocess.run([TSHARK, "-X", f"lua_script:{LUA}", "-r", str(out), "-V"],
                         capture_output=True, text=True, check=True)
    assert "Lua Error" not in res.stdout and "Lua Error" not in res.stderr
    assert res.stdout.count("Frame ") >= n


def test_no_runtime_lua_errors_in_full_trees():
    for cap in MANIFEST:
        res = subprocess.run([TSHARK, "-X", f"lua_script:{LUA}", "-r", str(GOLDEN / cap["file"]), "-V"],
                             capture_output=True, text=True, check=True)
        assert "Lua Error" not in res.stdout, cap["file"]
        assert "Malformed" not in res.stdout, cap["file"]


def test_committed_pcaps_match_generator(tmp_path):
    import importlib.util
    spec = importlib.util.spec_from_file_location("make_golden", ROOT / "tools" / "make_golden.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.main(tmp_path)
    for f in sorted(GOLDEN.glob("*.pcap")) + [GOLDEN / "golden.json"]:
        assert (tmp_path / f.name).read_bytes() == f.read_bytes(), f"{f.name} is stale: run tools/make_golden.py"

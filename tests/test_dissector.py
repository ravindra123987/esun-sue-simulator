"""Run wireshark/sue.lua through tshark over every golden pcap.

The Lua CRC code is written independently of sue/crc.py, so a Good status on
every frame cross-checks both implementations and the byte layouts.
Skipped when tshark is not installed.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
GOLDEN = ROOT / "pcaps" / "golden"
LUA = ROOT / "wireshark" / "sue.lua"
TSHARK = shutil.which("tshark") or "/Applications/Wireshark.app/Contents/MacOS/tshark"
HAVE_TSHARK = Path(TSHARK).exists()

MANIFEST = json.loads((GOLDEN / "golden.json").read_text())["captures"]


def run(pcap: Path, assume_psn: int | None):
    cmd = [TSHARK, "-X", f"lua_script:{LUA}", "-r", str(pcap), "-T", "fields",
           "-e", "sue.crc.status", "-e", "sue.ses.opcode", "-e", "sue.ses.rsp_opcode"]
    if assume_psn is not None:
        cmd[1:1] = ["-o", f"sue.assume_psn:{assume_psn}"]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True)
    assert "Lua" not in out.stderr and "error" not in out.stderr.lower(), out.stderr
    return [(line.split("\t") + ["", "", ""])[:3] for line in out.stdout.splitlines() if line]


@pytest.mark.skipif(not HAVE_TSHARK, reason="tshark not installed")
@pytest.mark.parametrize("cap", MANIFEST, ids=[c["file"] for c in MANIFEST])
def test_every_frame_crc_good(cap):
    first_psn = cap["frames"][0]["expected_psn"]
    rows = run(GOLDEN / cap["file"], first_psn)
    assert len(rows) == len(cap["frames"])
    for row, exp in zip(rows, cap["frames"]):
        assert row[0] == "0", f"{cap['file']}: CRC status {row[0]} ({exp['note']})"
        n_ses = len([x for x in (row[1].split(",") if row[1] else []) + (row[2].split(",") if row[2] else [])])
        assert n_ses == exp["ses_messages"]


@pytest.mark.skipif(not HAVE_TSHARK, reason="tshark not installed")
def test_wrong_psn_is_flagged_bad():
    rows = run(GOLDEN / "02-ufh16-rodl-two-stores.pcap", 1043)
    assert rows[0][0] == "1"

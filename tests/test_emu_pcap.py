"""The emulator's captures (pcaps/emu/): what emu/analyze.py counts and what the dissector shows for them."""

import shutil
import subprocess
from collections import Counter
from pathlib import Path

import pytest

from emu import shim as S
from emu.analyze import analyze

ROOT = Path(__file__).resolve().parent.parent
EMU = ROOT / "pcaps" / "emu"
LUA = ROOT / "wireshark" / "sue.lua"
TSHARK = shutil.which("tshark") or "/Applications/Wireshark.app/Contents/MacOS/tshark"


def test_clean_capture_holds_the_init_handshake_then_in_order_frames():
    c = analyze(str(EMU / "clean-link0.pcap"))
    assert c["other"] == 0                                                  # nothing but shim units on the wire
    assert c["sw_llr_init"] >= 1 and c["xpu_llr_init_echo"] >= 1 and c["xpu_llr_init"] >= 1
    assert c.get("xpu_bad", 0) == 0 and c.get("sw_bad", 0) == 0 and c.get("xpu_replayed", 0) == 0
    assert c["rodl_req"] > 0 and c["rodl_syn"] >= 1 and c["cmd_pdus"] == 8 * c["rodl_req"]
    assert c["rodl_crc_ok"] == c["rodl_req"]                               # hidden PSNs tracked from the syn packets
    assert c["xpu_cf_update"] > 0 and c["xpu_cc_update"] + c["sw_cc_update"] >= 1
    # no bare ACK packet in the first 160 units: with traffic both ways the ACK state rode on requests


def test_corrupted_link_capture_shows_nacks_and_replays():
    c = analyze(str(EMU / "ber-llr-link1.pcap"))
    assert c["xpu_bad"] + c["sw_bad"] > 0
    assert c["xpu_llr_nack"] + c["sw_llr_nack"] >= 1
    assert c["xpu_replayed"] + c["sw_replayed"] >= 1
    assert c["rodl_retx_flag"] == 0                                        # LLR repaired it; RODL never retransmitted
    assert c["nack_pkts"] == 0


def test_outage_capture_shows_flush_reinit_and_rodl_retransmissions():
    c = analyze(str(EMU / "link-outage-link1.pcap"))
    assert c["sw_llr_init"] + c["xpu_llr_init"] >= 2                        # start-up and after the FLUSH
    assert c["rodl_retx_flag"] >= 1 and c["nack_pkts"] + c["rodl_retx_flag"] >= 1


@pytest.mark.skipif(not Path(TSHARK).exists(), reason="tshark not installed")
def test_dissector_decodes_the_shim_and_the_frames_inside():
    cmd = [TSHARK, "-X", f"lua_script:{LUA}", "-r", str(EMU / "ber-llr-link1.pcap"), "-T", "fields",
           "-e", "_ws.col.Protocol", "-e", "sue.llr.type", "-e", "sue.llr.crc.status", "-e", "sue.crc.status",
           "-e", "sue.pds.psn", "-e", "sue.cbfc.cf1", "-e", "sue.cbfc.cc", "-e", "sue.llr.ack_nack_seq", "-e", "sue.pds.cack_psn"]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True)
    assert "Lua" not in out.stderr and "error" not in out.stderr.lower(), out.stderr
    rows = [line.split("\t") for line in out.stdout.splitlines()]
    kinds = Counter((r[0], r[1]) for r in rows)
    assert kinds[("LLR", "0x01")] > 0 and kinds[("LLR", "0x02")] > 0 and kinds[("LLR", "0x10")] > 0   # ACK, NACK, CF_Update
    assert kinds[("SUE/UFH16", "0x00")] > 0                                # frames: shim + the UFH_16 dissector
    assert any(r[2] == "1" for r in rows)                                  # corrupted frames flagged by the shim CRC
    good = [r for r in rows if r[0] == "SUE/UFH16" and r[3] == "0"]
    assert good and all(r[4] or r[8] for r in good)                        # CRC Good: a request with its PSN recovered, or an ACK
    assert any(r[5] for r in rows) and any(r[6] for r in rows)             # CF_Update counts and CC_Update counters decoded
    assert any(r[7] for r in rows if r[1] == "0x02")                       # the NACK carries ack_nack_seq


def test_sample_captures_are_what_the_analyser_expects():
    for p in EMU.glob("*.pcap"):
        c = analyze(str(p))
        assert c["other"] == 0 and c["duration_s"] > 0
        assert c["rodl_req"] > 0 and c["xpu_units"] > 0 and c["sw_units"] > 0


def test_shim_types_match_uec_table_5_8():
    assert S.T_ACK == 0x01 and S.T_NACK == 0x02 and S.T_INIT == 0x03 and S.T_INIT_ECHO == 0x04 and S.T_CF == 0x10

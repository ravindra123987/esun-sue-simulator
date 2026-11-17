-- sue.lua: Wireshark dissector for SUE-T over UFH_16, ESUN and UDP/IP.
--
-- Prototype for extending Wireshark's packet-uet.c (UEC 1.0.1) with UEC 1.1:
--   * UFH_16 with the RODL request / ACK folded into the MAC DA/SA (UEC 1.1 §5.4, Fig 3-68/3-120)
--   * RODL general header, pds.type 15 (UEC 1.1 §3.5.10.5, Fig 3-67)
--   * Unified Local SES: UET_HDR_REQUEST_LCL ac=0/ac=1, UET_HDR_RESPONSE_DATA_LCL (§3.4.3.3, Fig 3-28)
--   * UET CRC over UFH_16 (masked dscp/ecn, hidden expected PSN), over UDP/IPv4,
--     and over ESUN (project rule, docs/findings/m1-decisions.md D3)
--   * ESUN header (OCP ESUN 1.0 §5.2) on a configurable EtherType
--
-- Structured the way the C port would be (see wireshark/UPSTREAM.md):
--   * registered on EtherType 0xE790 (UFH) and on the ESUN EtherType, and on UDP port 4793;
--     the Ethernet dissector still runs, and the UFH bits are re-read from eth.dst / eth.src
--   * field abbreviations mirror packet-uet.c: sue.pds.type <-> uet.pds.type, ...
--   * bit fields use masks, as hf_register_info entries would
--
-- Usage: tshark -X lua_script:wireshark/sue.lua -r pcaps/golden/09-ufh16-conversation.pcap -V

local sue = Proto("sue", "SUE-T (UEC 1.1 Unified Local / RODL)")

-- ======================================================================= prefs
sue.prefs.esun_ethertype = Pref.uint("ESUN EtherType", 0x88B5,
  "EH-ET is unassigned in ESUN 1.0; 0x88B5 is the IEEE local experimental value")
sue.prefs.udp_port = Pref.uint("UET UDP port", 4793, "UDP destination port for UET")
sue.prefs.assume_psn = Pref.string("Assumed PSN", "",
  "PSN for a syn=0 UFH_16 RODL frame whose PDC had no earlier syn=1 frame (lets single-frame captures verify)")
sue.prefs.psn_window = Pref.uint("PSN resync window", 64,
  "On a CRC mismatch, try PSNs up to this far from the expected one to detect lost frames and retransmissions (0 = off)")
sue.prefs.psn_before_pad = Pref.bool("Hidden PSN before padding", false,
  "UFH_16: append the hidden PSN right after the SES payload (literal UEC 3.5.26.1 step 2) instead of after the minimum-size padding (Fig 3-122)")
sue.prefs.crc_le = Pref.bool("UET CRC little-endian", false,
  "UEC 1.1 and packet-uet.c read the trailer big-endian; enable to test the iSCSI-style reading")

-- ======================================================================= value strings
local PDS_TYPE = { [0]="Reserved", [1]="TSS", [2]="RUD_REQ", [3]="ROD_REQ", [4]="RUDI_REQ",
  [5]="RUDI_RESP", [6]="UUD_REQ", [7]="ACK", [8]="ACK_CC", [9]="ACK_CCX", [10]="NACK", [11]="CP",
  [12]="NACK_CCX", [13]="RUD_CC_REQ", [14]="ROD_CC_REQ", [15]="RODL_REQ" }
local NEXT_HDR = { [0]="UET_HDR_NONE", [6]="UET_HDR_RESPONSE_DATA_SMALL",
  [7]="UET_HDR_REQUEST_LCL", [8]="UET_HDR_RESPONSE_DATA_LCL" }
local REQ_OP = { [0]="UET_NO_OP", [1]="UET_WRITE", [2]="UET_READ", [3]="UET_ATOMIC", [4]="UET_FETCHING_ATOMIC" }
local RSP_OP = { [0]="UET_DEFAULT_RESPONSE", [1]="UET_RESPONSE", [2]="UET_RESPONSE_W_DATA", [3]="UET_NO_RESPONSE" }
local RC = { [0x00]="RC_NULL", [0x01]="RC_OK", [0x02]="RC_BAD_GENERATION", [0x03]="RC_DISABLED",
  [0x04]="RC_DISABLED_GEN", [0x05]="RC_NO_MATCH", [0x06]="RC_UNSUPPORTED_OP", [0x07]="RC_UNSUPPORTED_SIZE",
  [0x08]="RC_AT_INVALID", [0x09]="RC_AT_PERM", [0x0A]="RC_AT_ATS_ERROR", [0x0B]="RC_AT_NO_TRANS",
  [0x0C]="RC_AT_OUT_OF_RANGE", [0x0D]="RC_HOST_POISONED", [0x0E]="RC_HOST_UNSUCCESS_CMPL",
  [0x0F]="RC_AMO_UNSUPPORTED_OP", [0x10]="RC_AMO_UNSUPPORTED_DT", [0x11]="RC_AMO_UNSUPPORTED_SIZE",
  [0x12]="RC_AMO_UNALIGNED", [0x13]="RC_AMO_FP_NAN", [0x14]="RC_AMO_FP_UNDERFLOW", [0x15]="RC_AMO_FP_OVERFLOW",
  [0x16]="RC_AMO_FP_INEXACT", [0x17]="RC_PERM_VIOLATION", [0x18]="RC_OP_VIOLATION", [0x19]="RC_BAD_INDEX",
  [0x1A]="RC_BAD_PID", [0x1B]="RC_BAD_JOB_ID", [0x1C]="RC_BAD_MKEY", [0x1D]="RC_BAD_ADDR", [0x1E]="RC_CANCELLED",
  [0x1F]="RC_UNDELIVERABLE", [0x20]="RC_UNCOR", [0x21]="RC_UNCOR_TRNSNT", [0x22]="RC_TOO_LONG",
  [0x23]="RC_INITIATOR_ERROR", [0x24]="RC_DROPPED" }
for v = 0x30, 0x37 do RC[v] = string.format("RC_VENDOR_%d", v - 0x30) end
local EHL_VS = { [0]="none", [1]="4 B", [2]="8 B", [3]="16 B" }
local EHL = { [0]=0, [1]=4, [2]=8, [3]=16 }
local CRC_STATUS = { [0]="Good", [1]="Bad", [2]="Unverified" }
local W_VS = { [0]="UFH_32", [1]="UFH_16" }
local ADDR60 = UInt64.new(0xFFFFFFFF, 0x0FFFFFFF)

-- ======================================================================= fields
local f = {}
local function add(key, pf) f[key] = pf end
-- UFH (frame bytes 0-11, read through eth.dst / eth.src)
add("ufh_v",       ProtoField.uint8 ("sue.ufh.v", "Version", base.DEC, nil, 0x80))
add("ufh_w",       ProtoField.uint8 ("sue.ufh.w", "Width", base.DEC, W_VS, 0x40))
add("ufh_rr",      ProtoField.uint8 ("sue.ufh.rsvd", "Reserved", base.HEX, nil, 0x30))
add("da_encode",   ProtoField.uint8 ("sue.ufh.da_encode", "DA encode [z y x m]", base.HEX, nil, 0x0F))
add("ufh_dst",     ProtoField.uint16("sue.ufh.dst", "Destination address", base.HEX))
add("sa_encode",   ProtoField.uint8 ("sue.ufh.sa_encode", "SA encode [z y x m]", base.HEX, nil, 0x0F))
add("ufh_dscp",    ProtoField.uint8 ("sue.ufh.dscp", "DSCP", base.DEC, nil, 0xFC))
add("ufh_ecn",     ProtoField.uint8 ("sue.ufh.ecn", "ECN", base.DEC, nil, 0x03))
add("ufh_src",     ProtoField.uint16("sue.ufh.src", "Source address", base.HEX))
add("ufh_rsvd4",   ProtoField.uint8 ("sue.ufh.rsvd4", "Reserved", base.HEX, nil, 0xF0))
-- PDS, UFH_16 compressed form (mirrors uet.pds.*)
add("type8",       ProtoField.uint8 ("sue.pds.type", "Type", base.DEC, PDS_TYPE, 0xF8))
add("nh16",        ProtoField.uint16("sue.pds.nh", "Next header", base.HEX, NEXT_HDR, 0x0780))
add("retx8",       ProtoField.uint8 ("sue.pds.flags.retx", "retx", base.DEC, nil, 0x40))
add("ar8",         ProtoField.uint8 ("sue.pds.flags.ar", "ar", base.DEC, nil, 0x20))
add("syn8",        ProtoField.uint8 ("sue.pds.flags.syn", "syn", base.DEC, nil, 0x10))
add("dpdcid12",    ProtoField.uint16("sue.pds.dpdcid", "Destination PDCID", base.HEX, nil, 0x0FFF))
add("pdcinfo12",   ProtoField.uint16("sue.pds.pdc_info", "pdc_info", base.HEX, nil, 0x0C00))
add("psnoff12",    ProtoField.uint16("sue.pds.psn_offset", "psn_offset", base.DEC, nil, 0x03FF))
add("psh",         ProtoField.uint8 ("sue.pds.rodl.psn_state_hi", "psn_state_hi", base.HEX, nil, 0xF0))
add("psm",         ProtoField.uint16("sue.pds.rodl.psn_state_mid", "psn_state_mid", base.HEX, nil, 0xF000))
add("psl",         ProtoField.uint16("sue.pds.rodl.psn_state_low", "psn_state_low", base.HEX))
add("spdcid12",    ProtoField.uint16("sue.pds.spdcid", "Source PDCID", base.HEX, nil, 0x0FFF))
add("psn_state",   ProtoField.uint32("sue.pds.rodl.psn_state", "psn_state", base.HEX))
add("clear12",     ProtoField.int32 ("sue.pds.clear_psn_offset", "clear_psn_offset"))
add("revcack",     ProtoField.uint16("sue.pds.rodl.rev_cack_psn_lsb", "rev_cack_psn_lsb", base.HEX))
add("psn",         ProtoField.uint32("sue.pds.psn", "PSN", base.DEC))
add("psn_exp",     ProtoField.uint32("sue.pds.rodl.expected_psn", "Expected PSN", base.DEC))
add("psn_gap",     ProtoField.int32 ("sue.pds.rodl.psn_gap", "PSN gap (found - expected)"))
add("ackflags",    ProtoField.uint8 ("sue.pds.flags", "Flags", base.HEX, nil, 0x7F))
add("dpdhi",       ProtoField.uint8 ("sue.pds.dpdcid_hi", "dpdcid[11:4]", base.HEX))
add("dpdlo",       ProtoField.uint8 ("sue.pds.dpdcid_lo", "dpdcid[3:0]", base.HEX, nil, 0xF0))
add("dpdcid",      ProtoField.uint16("sue.pds.dpdcid_full", "Destination PDCID", base.HEX))
add("ack_off",     ProtoField.int16 ("sue.pds.ack_psn_offset", "ack_psn_offset / probe_opaque"))
add("ack_psn",     ProtoField.uint32("sue.pds.ack_psn", "ACK_PSN (cack_psn + offset)", base.DEC))
add("cack_psn",    ProtoField.uint32("sue.pds.cack_psn", "cack_psn", base.DEC))
-- PDS, RODL general (12 B)
add("g_type",      ProtoField.uint8 ("sue.pds.rodl.type", "Type", base.DEC, PDS_TYPE, 0xF8))
add("g_nh",        ProtoField.uint16("sue.pds.rodl.nh", "Next header", base.HEX, NEXT_HDR, 0x0780))
add("g_rsvd0",     ProtoField.uint16("sue.pds.rodl.flags.rsvd0", "rsvd", base.DEC, nil, 0x0040))
add("g_cack",      ProtoField.uint16("sue.pds.flags.cack", "cack", base.DEC, nil, 0x0020))
add("g_retx",      ProtoField.uint16("sue.pds.rodl.flags.retx", "retx", base.DEC, nil, 0x0010))
add("g_ar",        ProtoField.uint16("sue.pds.rodl.flags.ar", "ar", base.DEC, nil, 0x0008))
add("g_syn",       ProtoField.uint16("sue.pds.rodl.flags.syn", "syn", base.DEC, nil, 0x0004))
add("g_rsvd1",     ProtoField.uint16("sue.pds.rodl.flags.rsvd1", "rsvd", base.DEC, nil, 0x0003))
add("g_clear",     ProtoField.int16 ("sue.pds.rodl.clear_psn_offset", "clear_psn_offset"))
add("g_revcack",   ProtoField.uint16("sue.pds.rodl.rev_cack_psn_lsb16", "rev_cack_psn_lsb", base.HEX))
add("g_spdcid",    ProtoField.uint16("sue.pds.rodl.spdcid", "Source PDCID", base.HEX))
add("g_dpdcid",    ProtoField.uint16("sue.pds.rodl.dpdcid", "Destination PDCID / {pdc_info, psn_offset}", base.HEX))
-- ESUN
add("eh_rev",      ProtoField.uint8 ("sue.esun.rev", "Rev", base.DEC, nil, 0xC0))
add("eh_f",        ProtoField.uint8 ("sue.esun.f", "F (flow label valid)", base.DEC, nil, 0x20))
add("eh_cos",      ProtoField.uint8 ("sue.esun.cos", "EH-CoS", base.DEC, nil, 0x1C))
add("eh_ecn",      ProtoField.uint8 ("sue.esun.ecn", "EH-ECN", base.DEC, nil, 0x03))
add("eh_fl",       ProtoField.uint16("sue.esun.flow_label", "Flow label", base.HEX))
add("eh_ttl",      ProtoField.uint8 ("sue.esun.ttl", "TTL", base.DEC, nil, 0xF0))
add("eh_ud",       ProtoField.uint8 ("sue.esun.ud", "UD", base.HEX, nil, 0x0C))
add("eh_rsvd",     ProtoField.uint8 ("sue.esun.rsvd", "RSVD", base.HEX, nil, 0x03))
-- SES Unified Local (mirrors uet.ses.*)
add("ac",          ProtoField.uint8 ("sue.ses.lcl.ac", "ac (address compression)", base.DEC, nil, 0x80))
add("mm",          ProtoField.uint8 ("sue.ses.lcl.mm", "mm (more messages)", base.DEC, nil, 0x40))
add("opcode",      ProtoField.uint8 ("sue.ses.opcode", "Opcode", base.HEX, REQ_OP, 0x3F))
add("ver",         ProtoField.uint8 ("sue.ses.ver", "Version", base.DEC, nil, 0xC0))
add("dc",          ProtoField.uint8 ("sue.ses.dc", "dc (delivery complete)", base.DEC, nil, 0x20))
add("ie",          ProtoField.uint8 ("sue.ses.ie", "ie (initiator error)", base.DEC, nil, 0x10))
add("jobid",       ProtoField.uint16("sue.ses.jobid", "JobID", base.DEC, nil, 0x0FF0))
add("reqlen",      ProtoField.uint16("sue.ses.lcl.request_length", "request_length[11:0]", base.DEC, nil, 0x0FFF))
add("rle",         ProtoField.uint8 ("sue.ses.lcl.rle", "rle", base.DEC, nil, 0xC0))
add("ehl",         ProtoField.uint8 ("sue.ses.lcl.ehl", "ehl", base.DEC, EHL_VS, 0x30))
add("length",      ProtoField.uint32("sue.ses.lcl.length", "Length", base.DEC))
add("address",     ProtoField.uint64("sue.ses.lcl.address", "Address", base.HEX))
add("addr_off",    ProtoField.int32 ("sue.ses.lcl.address_offset", "address_offset"))
add("target",      ProtoField.uint64("sue.ses.lcl.target", "Target address", base.HEX))
add("ehl_inh",     ProtoField.uint8 ("sue.ses.lcl.ehl_inherited", "ehl (inherited)", base.DEC, EHL_VS))
add("r_rsv",       ProtoField.uint8 ("sue.ses.rsp.rsv", "rsv", base.DEC, nil, 0x80))
add("r_mm",        ProtoField.uint8 ("sue.ses.rsp.mm", "mm (more messages)", base.DEC, nil, 0x40))
add("r_opcode",    ProtoField.uint8 ("sue.ses.rsp.opcode", "Opcode", base.HEX, RSP_OP, 0x3F))
add("r_ver",       ProtoField.uint8 ("sue.ses.rsp.ver", "Version", base.DEC, nil, 0xC0))
add("r_rc",        ProtoField.uint8 ("sue.ses.return_code", "Return code", base.HEX, RC, 0x3F))
add("r_ehl",       ProtoField.uint16("sue.ses.rsp.ehl", "ehl", base.DEC, EHL_VS, 0xC000))
add("r_plen",      ProtoField.uint16("sue.ses.rsp.payload_length", "payload_length", base.DEC, nil, 0x3FFF))
add("ext",         ProtoField.bytes ("sue.ses.ext_hdr", "Extension header"))
add("atomic",      ProtoField.bytes ("sue.ses.atomic_hdr", "Atomic header (not decoded)"))
add("g_pdcinfo",   ProtoField.uint16("sue.pds.rodl.pdc_info", "pdc_info", base.HEX, nil, 0xF000))
add("g_psnoff",    ProtoField.uint16("sue.pds.rodl.psn_offset", "psn_offset", base.DEC, nil, 0x0FFF))
add("data",        ProtoField.bytes ("sue.ses.data", "Data"))
add("pad",         ProtoField.bytes ("sue.pad", "Padding"))
add("nmsg",        ProtoField.uint8 ("sue.ses.count", "Messages in packet", base.DEC))
-- CRC (mirrors uet.crc / uet.crc.status)
add("crc",         ProtoField.uint32("sue.crc", "UET CRC", base.HEX))
add("crc_calc",    ProtoField.uint32("sue.crc.calculated", "Calculated", base.HEX))
add("crc_status",  ProtoField.uint8 ("sue.crc.status", "Status", base.DEC, CRC_STATUS))
add("crc_cov",     ProtoField.string("sue.crc.coverage", "Coverage"))
for _, pf in pairs(f) do table.insert(sue.fields, pf) end

local E = {
  crc_bad    = ProtoExpert.new("sue.crc.bad", "UET CRC mismatch", expert.group.CHECKSUM, expert.severity.ERROR),
  crc_unv    = ProtoExpert.new("sue.crc.unverified", "UET CRC not verified: PSN unknown", expert.group.CHECKSUM, expert.severity.NOTE),
  psn_gap    = ProtoExpert.new("sue.psn.gap", "PSN gap: CRC matched a PSN after the expected one (frames lost)", expert.group.SEQUENCE, expert.severity.WARN),
  psn_back   = ProtoExpert.new("sue.psn.back", "PSN behind expected: retransmission (Go-Back-N)", expert.group.SEQUENCE, expert.severity.NOTE),
  malformed  = ProtoExpert.new("sue.malformed", "Malformed SUE-T frame", expert.group.MALFORMED, expert.severity.ERROR),
  rsvd       = ProtoExpert.new("sue.rsvd_nonzero", "Reserved bits are not zero", expert.group.PROTOCOL, expert.severity.WARN),
  ufh_ver    = ProtoExpert.new("sue.ufh.version", "Unsupported UFH version or width", expert.group.UNDECODED, expert.severity.WARN),
  snap       = ProtoExpert.new("sue.snaplen", "Frame cut short by the capture snap length: UET CRC not in the capture", expert.group.UNDECODED, expert.severity.NOTE),
  ac_first   = ProtoExpert.new("sue.ses.ac_first", "First SES header in a packet must have ac=0 (UEC 3.4.3.3)", expert.group.PROTOCOL, expert.severity.WARN),
}
sue.experts = {}
for _, e in pairs(E) do table.insert(sue.experts, e) end

-- field extractors for the Ethernet addresses and the IP/UDP headers
local fx_eth_dst, fx_eth_src = Field.new("eth.dst"), Field.new("eth.src")
local fx_ip, fx_udp = Field.new("ip"), Field.new("udp")

-- ======================================================================= helpers
local CRCT = {}
for i = 0, 255 do
  local c = i
  for _ = 1, 8 do c = (c & 1 == 1) and ((c >> 1) ~ 0x82F63B78) or (c >> 1) end
  CRCT[i] = c
end
-- CRC32C register after hashing `s` (not yet complemented)
local function crc_reg(s)
  local c = 0xFFFFFFFF
  for i = 1, #s do c = CRCT[(c ~ s:byte(i)) & 0xFF] ~ (c >> 8) end
  return c
end
local function crc32c(s) return crc_reg(s) ~ 0xFFFFFFFF end
-- finish a saved register with a 4-byte big-endian PSN appended: the resync
-- search tries many PSNs without re-hashing the frame each time
local function crc_finish(reg, psn, suffix)
  local c = reg
  for _, b in ipairs({ (psn >> 24) & 0xFF, (psn >> 16) & 0xFF, (psn >> 8) & 0xFF, psn & 0xFF }) do
    c = CRCT[(c ~ b) & 0xFF] ~ (c >> 8)
  end
  if suffix then for i = 1, #suffix do c = CRCT[(c ~ suffix:byte(i)) & 0xFF] ~ (c >> 8) end end
  return c ~ 0xFFFFFFFF
end

local function raw(r) return r:bytes():raw() end
local function pad4(n) return (4 - n % 4) % 4 end
-- payload bytes after the SES header: writes, atomics and vendor opcodes carry `len` (UEC 3.4.3.5)
local function req_wire_bytes(op, len)
  if op == 1 or op == 3 or op == 4 or (op >= 0x30 and op <= 0x3E) then return len end
  return 0
end
local function atomic_bytes(op) if op == 3 or op == 4 then return 4 end; return 0 end
local function need(tvb, off, n, what)
  if off + n > tvb:len() then
    error(string.format("truncated: %s needs %d bytes at offset %d, %d left", what, n, off, tvb:len() - off), 0)
  end
end
-- the innermost occurrence: an emulated link-layer shim (0x88B6) wraps a whole Ethernet frame
local function first(fx) local v = { fx() }; return v[#v] end

local function crc_wire(tvb, off)
  if sue.prefs.crc_le then return tvb(off, 4):le_uint() end
  return tvb(off, 4):uint()
end

local function add_crc(tree, tvb, crc_off, calc, coverage)
  local wire = crc_wire(tvb, crc_off)
  local t = tree:add(f.crc, tvb(crc_off, 4), wire)
  local st
  if calc == nil then
    st = 2; t:add_proto_expert_info(E.crc_unv)
  else
    t:add(f.crc_calc, tvb(crc_off, 4), calc):set_generated()
    st = (calc == wire) and 0 or 1
    if st == 1 then t:add_proto_expert_info(E.crc_bad) end
  end
  t:add(f.crc_status, tvb(crc_off, 4), st):set_generated()
  if coverage then t:add(f.crc_cov, tvb(crc_off, 4), coverage):set_generated() end
  t:append_text(" [" .. CRC_STATUS[st] .. "]")
  return st
end

-- ======================================================================= SES
-- Decodes the packed SES messages from `off` up to `limit`; returns offset, summary, count.
local function dissect_ses(tvb, tree, off, limit, next_hdr)
  local info, ehl_inh, addr, n = {}, 0, UInt64.new(0), 0
  local more = true
  while more and off < limit do
    if next_hdr == 7 then
      n = n + 1
      need(tvb, off, 8, "SES request")
      local b0 = tvb(off, 1):uint()
      local ac, mm, op = b0 >> 7, (b0 >> 6) & 1, b0 & 0x3F
      local hlen = (ac == 0) and 12 or 8
      need(tvb, off, hlen, "SES request header")
      local len = tvb(off + 2, 2):uint() & 0x0FFF
      local ehl
      local t = tree:add(sue, tvb(off, hlen), string.format("SES request %d: %s", n, REQ_OP[op] or string.format("opcode 0x%02x", op)))
      t:add(f.ac, tvb(off, 1)); t:add(f.mm, tvb(off, 1)); t:add(f.opcode, tvb(off, 1))
      t:add(f.ver, tvb(off + 1, 1)); t:add(f.dc, tvb(off + 1, 1)); t:add(f.ie, tvb(off + 1, 1))
      t:add(f.jobid, tvb(off + 1, 2)); t:add(f.reqlen, tvb(off + 2, 2))
      if n == 1 and ac == 1 then t:add_proto_expert_info(E.ac_first) end
      if ac == 0 then
        local b4 = tvb(off + 4, 1):uint()
        ehl = (b4 >> 4) & 3
        len = ((b4 >> 6) << 12) | len
        t:add(f.rle, tvb(off + 4, 1)); t:add(f.ehl, tvb(off + 4, 1))
        addr = tvb(off + 4, 8):uint64():band(ADDR60)
        t:add(f.address, tvb(off + 4, 8), addr)
        ehl_inh = ehl
      else
        local o = tvb(off + 4, 4):int()
        t:add(f.addr_off, tvb(off + 4, 4), o)
        local delta = UInt64.new(o & 0xFFFFFFFF, o < 0 and 0xFFFFFFFF or 0)   -- sign-extend to 64 bits
        addr = (addr + delta):band(ADDR60)
        ehl = ehl_inh
        t:add(f.ehl_inh, tvb(off, hlen), ehl):set_generated()
      end
      t:add(f.length, tvb(off, hlen), len):set_generated()
      t:add(f.target, tvb(off, hlen), addr):set_generated()
      local el, al, dl = EHL[ehl], atomic_bytes(op), req_wire_bytes(op, len)
      local pl = pad4(dl)
      need(tvb, off + hlen, el + al + dl + pl, "SES request body")
      local p = off + hlen
      if el > 0 then t:add(f.ext, tvb(p, el)); p = p + el end
      if al > 0 then t:add(f.atomic, tvb(p, al)); p = p + al end
      if dl > 0 then t:add(f.data, tvb(p, dl)); p = p + dl end
      if pl > 0 then t:add(f.pad, tvb(p, pl)); p = p + pl end
      t:set_len(p - off)
      t:append_text(string.format(" %d B%s", len, ac == 1 and " (ac=1)" or ""))
      table.insert(info, string.format("%s %dB", (REQ_OP[op] or "UET_OP"):sub(5), len))
      off, more = p, (mm == 1)
    elseif next_hdr == 8 then
      n = n + 1
      need(tvb, off, 4, "SES response")
      local b0, b1, w = tvb(off, 1):uint(), tvb(off + 1, 1):uint(), tvb(off + 2, 2):uint()
      local mm, op, rc, ehl, pl = (b0 >> 6) & 1, b0 & 0x3F, b1 & 0x3F, w >> 14, w & 0x3FFF
      local t = tree:add(sue, tvb(off, 4), string.format("SES response %d: %s %s", n, RSP_OP[op] or op, RC[rc] or rc))
      t:add(f.r_rsv, tvb(off, 1)); t:add(f.r_mm, tvb(off, 1)); t:add(f.r_opcode, tvb(off, 1))
      t:add(f.r_ver, tvb(off + 1, 1)); t:add(f.r_rc, tvb(off + 1, 1))
      t:add(f.r_ehl, tvb(off + 2, 2)); t:add(f.r_plen, tvb(off + 2, 2))
      if b0 & 0x80 ~= 0 then t:add_proto_expert_info(E.rsvd) end
      local el, pp = EHL[ehl], pad4(pl)
      need(tvb, off + 4, el + pl + pp, "SES response body")
      local p = off + 4
      if el > 0 then t:add(f.ext, tvb(p, el)); p = p + el end
      if pl > 0 then t:add(f.data, tvb(p, pl)); p = p + pl end
      if pp > 0 then t:add(f.pad, tvb(p, pp)); p = p + pp end
      t:set_len(p - off)
      table.insert(info, "RSP " .. (RC[rc] or rc))
      off, more = p, (mm == 1)
    else
      break
    end
  end
  if more and n > 0 and off >= limit then
    error("truncated: last SES header has mm=1 but the packet ends", 0)
  end
  return off, info, n
end

local function trailer(tvb, tree, off, crc_off)
  if crc_off > off then tree:add(f.pad, tvb(off, crc_off - off)) end
end

-- ======================================================================= PSN tracking
-- Expected PSN per {src, dst, spdcid} on the first pass; results stored per frame.
local next_psn, frame_res = {}, {}
function sue.init() next_psn, frame_res = {}, {} end

local function resolve_psn(reg, suffix, wire, exp, retx)
  if crc_finish(reg, exp, suffix) == wire then return exp, 0 end
  local w = sue.prefs.psn_window
  local order = {}
  local s1, s2 = 1, -1
  if retx then s1, s2 = -1, 1 end          -- a retransmission most likely goes back
  for d = 1, w do table.insert(order, s1 * d) end
  for d = 1, w do table.insert(order, s2 * d) end
  for _, d in ipairs(order) do
    local p = (exp + d) & 0xFFFFFFFF
    if crc_finish(reg, p, suffix) == wire then return p, d end
  end
  return nil, nil
end

-- ======================================================================= UFH_16
local function dissect_ufh16(tvb, pinfo, root, dstR, srcR)
  local d, s = raw(dstR), raw(srcR)
  local ptype = d:byte(2) >> 3
  local nh = ((d:byte(2) & 0x07) << 1) | (d:byte(3) >> 7)
  local ufh_dst, ufh_src = (d:byte(5) << 8) | d:byte(6), (s:byte(5) << 8) | s:byte(6)
  local crc_off = tvb:len() - 4
  pinfo.cols.protocol = "SUE/UFH16"
  pinfo.cols.src = string.format("ufh:%04x", ufh_src)
  pinfo.cols.dst = string.format("ufh:%04x", ufh_dst)

  local h = root:add(sue, dstR, "UFH_16 + PDS " .. (PDS_TYPE[ptype] or ptype))
  h:add(f.ufh_v, dstR(0, 1)); h:add(f.ufh_w, dstR(0, 1)); h:add(f.ufh_rr, dstR(0, 1)); h:add(f.da_encode, dstR(0, 1))
  if d:byte(1) & 0x30 ~= 0 then h:add_proto_expert_info(E.rsvd) end
  h:add(f.type8, dstR(1, 1)); h:add(f.nh16, dstR(1, 2))
  h:add(f.ufh_dst, dstR(4, 2)); h:add(f.sa_encode, srcR(0, 1))
  h:add(f.ufh_dscp, srcR(1, 1)); h:add(f.ufh_ecn, srcR(1, 1)); h:add(f.ufh_src, srcR(4, 2))
  local head = d .. s .. "\xE7\x90"
  local masked = head:sub(1, 7) .. "\0" .. head:sub(9)        -- byte 7 = dscp+ecn, as 0

  if ptype == 15 then
    need(tvb, 0, 2 + 4, "UFH_16 RODL")
    local b2 = d:byte(3)
    local retx, syn = (b2 >> 6) & 1, (b2 >> 4) & 1
    h:add(f.retx8, dstR(2, 1)); h:add(f.ar8, dstR(2, 1)); h:add(f.syn8, dstR(2, 1))
    if syn == 1 then h:add(f.pdcinfo12, dstR(2, 2)); h:add(f.psnoff12, dstR(2, 2))
    else h:add(f.dpdcid12, dstR(2, 2)) end
    h:add(f.psh, srcR(0, 1)); h:add(f.psm, srcR(2, 2)); h:add(f.spdcid12, srcR(2, 2)); h:add(f.psl, tvb(0, 2))
    local spd = ((s:byte(3) & 0x0F) << 8) | s:byte(4)
    local ps = ((s:byte(1) >> 4) << 20) | ((s:byte(3) >> 4) << 16) | tvb(0, 2):uint()
    h:add(f.psn_state, tvb(0, 2), ps):set_generated()
    -- key ignores the top nibble of src ("src_addr / entropy", Fig 3-120)
    local key = string.format("%03x>%04x/%03x", ufh_src & 0xFFF, ufh_dst, spd)

    local off, info, n = dissect_ses(tvb, root, 2, crc_off, nh)
    trailer(tvb, root, off, crc_off)

    local res = frame_res[pinfo.number]
    if not res then                                          -- first pass only
      res = {}
      -- hidden PSN after the pad (Fig 3-122) or right after the SES payload (pref)
      local split = sue.prefs.psn_before_pad and off or crc_off
      local reg = crc_reg(masked .. raw(tvb(0, split)))
      local suffix = (split < crc_off) and raw(tvb(split, crc_off - split)) or nil
      local wire = crc_wire(tvb, crc_off)
      if syn == 1 then
        res.psn = ps
        res.calc = crc_finish(reg, ps, suffix)
      else
        res.exp = next_psn[key] or tonumber(sue.prefs.assume_psn)
        if res.exp then
          res.psn, res.gap = resolve_psn(reg, suffix, wire, res.exp, retx == 1)
          res.calc = crc_finish(reg, res.psn or res.exp, suffix)
        end
      end
      local nxt = res.psn or res.exp
      if nxt then next_psn[key] = (nxt + 1) & 0xFFFFFFFF end
      frame_res[pinfo.number] = res
    end

    if syn == 1 then
      h:add(f.psn, tvb(0, 2), ps):append_text(" (syn=1: PSN = {0x00, psn_state})")
    else
      local cpo = ps >> 12; if cpo >= 0x800 then cpo = cpo - 0x1000 end
      h:add(f.clear12, tvb(0, 2), cpo):set_generated()
      h:add(f.revcack, tvb(0, 2), ps & 0xFFF):set_generated()
      if res.exp then h:add(f.psn_exp, tvb(0, 0), res.exp):set_generated() end
      if res.psn then
        local it = h:add(f.psn, tvb(0, 0), res.psn); it:set_generated()
        it:append_text(" (not on the wire; recovered from the UET CRC)")
        if res.gap and res.gap ~= 0 then
          local g = h:add(f.psn_gap, tvb(0, 0), res.gap); g:set_generated()
          g:add_proto_expert_info(res.gap > 0 and E.psn_gap or E.psn_back)
        end
      end
    end
    root:add(f.nmsg, tvb(0, 0), n):set_generated()
    local cov
    if res.psn then cov = string.format("frame from byte 0 (dscp/ecn as 0) + PSN %d", res.psn)
    elseif res.exp then cov = string.format("no PSN within %d of expected %d matches", sue.prefs.psn_window, res.exp)
    else cov = "PSN unknown: no syn=1 seen for this PDC (set sue.assume_psn)" end
    local st = add_crc(root, tvb, crc_off, res.calc, cov)
    local summary = string.format("RODL %s%s spdcid=0x%03x%s %s", syn == 1 and "SYN " or "",
      res.psn and ("PSN " .. res.psn) or "PSN ?", spd, retx == 1 and " retx" or "", table.concat(info, ", "))
    if res.gap and res.gap > 0 then summary = summary .. string.format(" [gap %d]", res.gap) end
    if res.gap and res.gap < 0 then summary = summary .. string.format(" [back %d]", -res.gap) end
    pinfo.cols.info = string.format("%s  0x%04x > 0x%04x  CRC %s", summary, ufh_src, ufh_dst, CRC_STATUS[st])

  elseif ptype == 7 then
    need(tvb, 0, 6 + 4, "UFH_16 ACK")
    h:add(f.ackflags, dstR(2, 1)); h:add(f.dpdhi, dstR(3, 1))
    if s:byte(1) & 0xF0 ~= 0 then h:add_proto_expert_info(E.rsvd) end
    h:add(f.ufh_rsvd4, srcR(0, 1)); h:add(f.dpdlo, srcR(2, 1)); h:add(f.spdcid12, srcR(2, 2))
    h:add(f.dpdcid, dstR(3, 1), (d:byte(4) << 4) | (s:byte(3) >> 4)):set_generated()
    h:add(f.ack_off, tvb(0, 2)); h:add(f.cack_psn, tvb(2, 4))
    h:add(f.ack_psn, tvb(0, 2), (tvb(2, 4):uint() + tvb(0, 2):int()) & 0xFFFFFFFF):set_generated()
    local off, info, n = dissect_ses(tvb, root, 6, crc_off, nh)
    trailer(tvb, root, off, crc_off)
    root:add(f.nmsg, tvb(0, 0), n):set_generated()
    local st = add_crc(root, tvb, crc_off, crc32c(masked .. raw(tvb(0, crc_off))),
      "frame from byte 0 (dscp/ecn as 0); no PSN for non-RODL types (UEC Fig 3-122)")
    pinfo.cols.info = string.format("ACK cack_psn=%d %s  0x%04x > 0x%04x  CRC %s", tvb(2, 4):uint(),
      table.concat(info, ", "), ufh_src, ufh_dst, CRC_STATUS[st])
  else
    pinfo.cols.info = "UFH_16 PDS " .. (PDS_TYPE[ptype] or ptype) .. " (not decoded yet)"
  end
end

-- ======================================================================= RODL general
local function dissect_rodl_general(tvb, root, off, limit)
  need(tvb, off, 12, "RODL header")
  local t = root:add(sue, tvb(off, 12), "PDS RODL request (general, 12 B)")
  t:add(f.g_type, tvb(off, 1)); t:add(f.g_nh, tvb(off, 2))
  local w = tvb(off, 2):uint()
  t:add(f.g_rsvd0, tvb(off, 2)); t:add(f.g_cack, tvb(off, 2)); t:add(f.g_retx, tvb(off, 2))
  t:add(f.g_ar, tvb(off, 2)); t:add(f.g_syn, tvb(off, 2)); t:add(f.g_rsvd1, tvb(off, 2))
  if w & 0x0043 ~= 0 then t:add_proto_expert_info(E.rsvd) end
  if w & 0x0020 ~= 0 then t:add(f.g_revcack, tvb(off + 2, 2)) else t:add(f.g_clear, tvb(off + 2, 2)) end
  local psn = tvb(off + 4, 4):uint()
  t:add(f.psn, tvb(off + 4, 4)); t:add(f.g_spdcid, tvb(off + 8, 2))
  if w & 0x0004 ~= 0 then t:add(f.g_pdcinfo, tvb(off + 10, 2)); t:add(f.g_psnoff, tvb(off + 10, 2))
  else t:add(f.g_dpdcid, tvb(off + 10, 2)) end
  local nh = (w >> 7) & 0xF
  local o, info, n = dissect_ses(tvb, root, off + 12, limit, nh)
  root:add(f.nmsg, tvb(off, 0), n):set_generated()
  return o, psn, info
end

-- ======================================================================= entry points
local function guarded(fn, tvb, pinfo, tree, title)
  local root = tree:add(sue, tvb(), title)
  if tvb:len() < tvb:reported_len() then
    root:add_proto_expert_info(E.snap)
    pinfo.cols.info:append(" [cut by snaplen]")
    return tvb:len()
  end
  local ok, err = pcall(fn, tvb, pinfo, root)
  if not ok then
    root:add_proto_expert_info(E.malformed, tostring(err))
    pinfo.cols.info:append(" [Malformed: " .. tostring(err) .. "]")
  end
  return tvb:len()
end

-- EtherType 0xE790 (UET): UFH frames are recognised from eth.dst byte 0
local ufh = Proto("sue_ufh", "SUE-T UFH")
function ufh.dissector(tvb, pinfo, tree)
  local dfi, sfi = first(fx_eth_dst), first(fx_eth_src)
  if not dfi or not sfi then return 0 end
  local dstR, srcR = dfi.range, sfi.range
  local b0 = dstR(0, 1):uint()
  if (b0 & 0x0E) ~= 0x02 then return 0 end            -- not SLAP AAI + local: not UFH
  return guarded(function(t, p, root)
    if (b0 & 0x80) ~= 0 or (b0 & 0x40) == 0 then
      root:add_proto_expert_info(E.ufh_ver, (b0 & 0x80) ~= 0 and "UFH v=1" or "UFH_32 (w=0) not decoded yet")
      p.cols.protocol = "SUE/UFH"
      return
    end
    p.cols.protocol = "SUE/UFH16"
    need(t, 0, 6, "UFH_16 frame")
    dissect_ufh16(t, p, root, dstR, srcR)
  end, tvb, pinfo, tree, "SUE-T over UFH_16")
end

-- ESUN header on its (configurable) EtherType
local esun = Proto("sue_esun", "SUE-T ESUN")
function esun.dissector(tvb, pinfo, tree)
  local dfi, sfi = first(fx_eth_dst), first(fx_eth_src)
  return guarded(function(t, p, root)
    need(t, 0, 4 + 12 + 4, "ESUN frame")
    p.cols.protocol = "SUE/ESUN"
    local crc_off = t:len() - 4
    local eh = root:add(sue, t(0, 4), "ESUN header (4 B)")
    eh:add(f.eh_rev, t(0, 1)); eh:add(f.eh_f, t(0, 1)); eh:add(f.eh_cos, t(0, 1)); eh:add(f.eh_ecn, t(0, 1))
    eh:add(f.eh_fl, t(1, 2)); eh:add(f.eh_ttl, t(3, 1)); eh:add(f.eh_ud, t(3, 1)); eh:add(f.eh_rsvd, t(3, 1))
    if t(3, 1):uint() & 0x03 ~= 0 then eh:add_proto_expert_info(E.rsvd) end
    local off, psn, info = dissect_rodl_general(t, root, 4, crc_off)
    trailer(t, root, off, crc_off)
    local calc
    if dfi and sfi then
      local b = raw(t(0, crc_off))
      b = string.char(b:byte(1) & 0xE0) .. b:sub(2, 3) .. string.char(b:byte(4) & 0x0F) .. b:sub(5)
      local et = sue.prefs.esun_ethertype
      calc = crc32c(raw(dfi.range) .. raw(sfi.range) .. string.char((et >> 8) & 0xFF, et & 0xFF) .. b)
    end
    local st = add_crc(root, t, crc_off, calc, "project rule: from DA, EH CoS/ECN/TTL as 0")
    local b0 = t(0, 1):uint()
    p.cols.info = string.format("ESUN cos=%d fl=0x%04x ttl=%d  RODL PSN %d %s  CRC %s", (b0 >> 2) & 7, t(1, 2):uint(),
      t(3, 1):uint() >> 4, psn, table.concat(info, ", "), CRC_STATUS[st])
  end, tvb, pinfo, tree, "SUE-T over ESUN")
end

-- UDP port 4793, RODL only (other PDS types are left to packet-uet.c)
local uetudp = Proto("sue_udp", "SUE-T over UDP")
function uetudp.dissector(tvb, pinfo, tree)
  if tvb:len() < 16 or (tvb(0, 1):uint() >> 3) ~= 15 then return 0 end
  local ipfi, udpfi = first(fx_ip), first(fx_udp)
  return guarded(function(t, p, root)
    p.cols.protocol = "SUE/UDP"
    local crc_off = t:len() - 4
    local off, psn, info = dissect_rodl_general(t, root, 0, crc_off)
    trailer(t, root, off, crc_off)
    local calc
    if ipfi and udpfi then
      local iph, udph = raw(ipfi.range), raw(udpfi.range)
      calc = crc32c(iph:sub(13) .. udph:sub(1, 6) .. "\0\0" .. raw(t(0, crc_off)))
    end
    local st = add_crc(root, t, crc_off, calc, "from IPv4 source address; UDP checksum as 0")
    p.cols.info = string.format("RODL PSN %d %s  CRC %s", psn, table.concat(info, ", "), CRC_STATUS[st])
  end, tvb, pinfo, tree, "SUE-T over UDP/IP")
end

-- ======================================================================= emulated link layer (emu/shim.py)
-- EtherType 0x88B6: what the netns emulator puts on a veth for the parts of UEC §5 a capture never
-- shows: the LLR frame_seq (preamble), LLR_ACK/NACK/INIT/INIT_ECHO and CF_Update (control ordered
-- sets), and a CRC-32 of the inner frame standing in for the FCS. The inner frame follows unchanged.
local llr = Proto("sue_llr", "UE LLR (emulated on a veth)")
local LLR_TYPE = { [0]="frame", [1]="LLR_ACK", [2]="LLR_NACK", [3]="LLR_INIT", [4]="LLR_INIT_ECHO", [0x10]="CF_UPDATE" }
local fl = {}
fl.type = ProtoField.uint8("sue.llr.type", "CtlOS type (Table 5-8 D1)", base.HEX, LLR_TYPE)
fl.seq = ProtoField.uint24("sue.llr.seq", "frame_seq", base.DEC)
fl.crc = ProtoField.uint32("sue.llr.crc", "Inner CRC-32 (FCS stand-in)", base.HEX)
fl.crc_status = ProtoField.uint8("sue.llr.crc.status", "Inner CRC status", base.DEC, CRC_STATUS)
fl.ack_seq = ProtoField.uint24("sue.llr.ack_nack_seq", "ack_nack_seq", base.DEC)
fl.init_seq = ProtoField.uint24("sue.llr.init_seq", "init_seq", base.DEC)
fl.init_data = ProtoField.uint16("sue.llr.init_data", "init_data", base.HEX)
fl.cf1_vc = ProtoField.uint8("sue.cbfc.cf1_vc", "CF1_VC_index", base.DEC)
fl.cf1 = ProtoField.uint16("sue.cbfc.cf1", "CF1_count (R_VC_CF)", base.DEC)
fl.cf2_vc = ProtoField.uint8("sue.cbfc.cf2_vc", "CF2_VC_index", base.DEC)
fl.cf2 = ProtoField.uint16("sue.cbfc.cf2", "CF2_count (R_VC_CF)", base.DEC)
fl.cc_type = ProtoField.uint8("sue.cbfc.cc_type", "CC_Update message type", base.HEX, { [1]="VC[0:15]", [2]="VC[16:31]" })
fl.cc = ProtoField.uint32("sue.cbfc.cc", "S_VC_CC", base.DEC)
llr.fields = { fl.type, fl.seq, fl.crc, fl.crc_status, fl.ack_seq, fl.init_seq, fl.init_data,
  fl.cf1_vc, fl.cf1, fl.cf2_vc, fl.cf2, fl.cc_type, fl.cc }
local E_llr_bad = ProtoExpert.new("sue.llr.crc.bad", "Inner CRC mismatch: the frame was corrupted on the wire",
  expert.group.CHECKSUM, expert.severity.WARN)
llr.experts = { E_llr_bad }

-- plain CRC-32 (zlib), for the FCS stand-in
local CRC32T = {}
for i = 0, 255 do
  local c = i
  for _ = 1, 8 do if c & 1 == 1 then c = (c >> 1) ~ 0xEDB88320 else c = c >> 1 end end
  CRC32T[i] = c
end
local function crc32(s)
  local c = 0xFFFFFFFF
  for i = 1, #s do c = CRC32T[(c ~ s:byte(i)) & 0xFF] ~ (c >> 8) end
  return c ~ 0xFFFFFFFF
end

local function seq20(tvb, off)        -- D2 = seq[19:12], D3 = seq[11:4], D4[7:4] = seq[3:0]
  return (tvb(off, 1):uint() << 12) | (tvb(off + 1, 1):uint() << 4) | (tvb(off + 2, 1):uint() >> 4)
end

local eth_dis = Dissector.get("eth_withoutfcs")

function llr.dissector(tvb, pinfo, tree)
  if tvb:len() < 8 then return 0 end
  local ty = tvb(0, 1):uint()
  local t = tree:add(llr, tvb(0, 8), "UE LLR " .. (LLR_TYPE[ty] or string.format("type 0x%02x", ty)))
  t:add(fl.type, tvb(0, 1))
  pinfo.cols.protocol = "LLR"
  if ty == 0 then
    local seq = tvb(1, 3):uint()
    t:add(fl.seq, tvb(1, 3))
    local inner = tvb(8):tvb()
    local wire, calc = tvb(4, 4):uint(), crc32(raw(tvb(8)))
    local ci = t:add(fl.crc, tvb(4, 4))
    local st = (wire == calc) and 0 or 1
    ci:add(fl.crc_status, tvb(4, 4), st):set_generated()
    ci:append_text(" [" .. CRC_STATUS[st] .. "]")
    if st == 1 then ci:add_proto_expert_info(E_llr_bad) end
    t:append_text(string.format(" seq %d%s", seq, st == 1 and " [bad CRC]" or ""))
    if inner:len() >= 20 and inner(12, 2):uint() == 0x8808 and inner(14, 2):uint() == 0xFFFE then
      -- CC_Update MAC control frame (UEC §5.2.6.2, Table 5-22)
      local c = tree:add(llr, inner(), "CBFC CC_Update (MAC control, opcode 0xFFFE)")
      c:add(fl.cc_type, inner(19, 1))
      local base = (inner(19, 1):uint() == 2) and 16 or 0
      local data = inner(20, 40)
      for i = 0, 15 do
        local bit = i * 20
        local b = bit // 8
        local v = ((data(b, 3):uint() >> (4 - (bit % 8))) & 0xFFFFF)
        local it = c:add(fl.cc, data(b, 3), v)
        it:prepend_text(string.format("VC %d: ", base + i))
      end
      pinfo.cols.info = string.format("LLR seq %d  CC_Update VC[%d:%d]", seq, base, base + 15)
    elseif st == 1 then
      pinfo.cols.info = string.format("LLR seq %d  [corrupted frame, %d B]", seq, inner:len())
    elseif inner:len() >= 16 and inner(12, 2):uint() == 0xE790 and (inner(0, 1):uint() & 0x0E) == 0x02 then
      local b0 = inner(0, 1):uint()
      if (b0 & 0x80) == 0 and (b0 & 0x40) ~= 0 then
        guarded(function(tv, p, root) dissect_ufh16(tv, p, root, inner(0, 6), inner(6, 6)) end,
          inner(14):tvb(), pinfo, tree, "SUE-T over UFH_16")
        pinfo.cols.info:prepend(string.format("LLR seq %d  ", seq))
      end
    else
      eth_dis:call(inner, pinfo, tree)
      pinfo.cols.info:prepend(string.format("LLR seq %d  ", seq))
    end
  elseif ty == 0x10 then
    need(tvb, 8, 6, "CF_Update")
    local a, b = seq20(tvb, 8), seq20(tvb, 11)
    t:add(fl.cf1_vc, tvb(8, 1), (a >> 15) & 0x1F); t:add(fl.cf1, tvb(8, 3), a & 0x7FFF)
    t:add(fl.cf2_vc, tvb(11, 1), (b >> 15) & 0x1F); t:add(fl.cf2, tvb(11, 3), b & 0x7FFF)
    pinfo.cols.info = string.format("CF_Update  VC%d=%d VC%d=%d", (a >> 15) & 0x1F, a & 0x7FFF, (b >> 15) & 0x1F, b & 0x7FFF)
  else
    need(tvb, 8, 6, "LLR CtlOS")
    local s = seq20(tvb, 8)
    if ty == 3 or ty == 4 then
      t:add(fl.init_seq, tvb(8, 3), s); t:add(fl.init_data, tvb(11, 2))
      pinfo.cols.info = string.format("%s init_seq %d", LLR_TYPE[ty], s)
    else
      t:add(fl.ack_seq, tvb(8, 3), s)
      pinfo.cols.info = string.format("%s ack_nack_seq %d", LLR_TYPE[ty] or "LLR", s)
    end
  end
  return tvb:len()
end

DissectorTable.get("ethertype"):add(0x88B6, llr)
DissectorTable.get("ethertype"):add(0xE790, ufh)
local reg_et, reg_port = sue.prefs.esun_ethertype, sue.prefs.udp_port
DissectorTable.get("ethertype"):add(reg_et, esun)
DissectorTable.get("udp.port"):add(reg_port, uetudp)
function sue.prefs_changed()
  if sue.prefs.esun_ethertype ~= reg_et then
    DissectorTable.get("ethertype"):remove(reg_et, esun)
    reg_et = sue.prefs.esun_ethertype
    DissectorTable.get("ethertype"):add(reg_et, esun)
  end
  if sue.prefs.udp_port ~= reg_port then
    DissectorTable.get("udp.port"):remove(reg_port, uetudp)
    reg_port = sue.prefs.udp_port
    DissectorTable.get("udp.port"):add(reg_port, uetudp)
  end
end

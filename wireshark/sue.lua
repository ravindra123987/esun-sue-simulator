-- sue.lua: Wireshark dissector for SUE-T over UFH_16, ESUN and UDP/IP.
--
-- Covers what Wireshark's packet-uet.c (UEC 1.0.1) does not:
--   * UFH_16 with the RODL request / ACK folded into the MAC area (UEC 1.1 §5.4, Fig 3-68/3-120)
--   * RODL general header, pds.type 15 (UEC 1.1 §3.5.10.5)
--   * Unified Local SES: UET_HDR_REQUEST_LCL ac=0/ac=1 and UET_HDR_RESPONSE_DATA_LCL (UEC 1.1 §3.4.3.3)
--   * the UET CRC over UFH_16 (masked dscp/ecn + hidden expected PSN), over UDP/IPv4,
--     and over ESUN (project rule, see docs/findings/m1-decisions.md)
--   * the ESUN header (OCP ESUN 1.0 §5.2) on a configurable EtherType
--
-- Usage: tshark -X lua_script:wireshark/sue.lua -r pcaps/golden/02-ufh16-rodl-two-stores.pcap -V
--   or copy into the Wireshark personal plugins folder.

local sue = Proto("sue", "SUE-T (UEC 1.1 Unified Local / RODL)")

-- ---------------------------------------------------------------- preferences
sue.prefs.esun_ethertype = Pref.uint("ESUN EtherType", 0x88B5,
  "EH-ET is unassigned in ESUN 1.0; 0x88B5 is the IEEE local experimental value", 16)
sue.prefs.udp_port = Pref.uint("UET UDP port", 4793, "UDP destination port for UET")
sue.prefs.assume_psn = Pref.string("Assumed PSN", "",
  "PSN to assume for a syn=0 UFH_16 RODL frame when no syn=1 frame for its PDC was seen (lets single-frame captures verify)")
sue.prefs.crc_le = Pref.bool("UET CRC little-endian", false,
  "UEC says network byte order; enable to test the iSCSI-style little-endian reading")

-- ---------------------------------------------------------------- value strings
local PDS_TYPE = { [0]="Reserved", [1]="TSS", [2]="RUD_REQ", [3]="ROD_REQ", [4]="RUDI_REQ",
  [5]="RUDI_RESP", [6]="UUD_REQ", [7]="ACK", [8]="ACK_CC", [9]="ACK_CCX", [10]="NACK", [11]="CP",
  [12]="NACK_CCX", [13]="RUD_CC_REQ", [14]="ROD_CC_REQ", [15]="RODL_REQ" }
local NEXT_HDR = { [0]="UET_HDR_NONE", [6]="UET_HDR_RESPONSE_DATA_SMALL",
  [7]="UET_HDR_REQUEST_LCL", [8]="UET_HDR_RESPONSE_DATA_LCL" }
local REQ_OP = { [0]="UET_NO_OP", [1]="UET_WRITE", [2]="UET_READ", [3]="UET_ATOMIC", [4]="UET_FETCHING_ATOMIC" }
local RSP_OP = { [0]="UET_DEFAULT_RESPONSE", [1]="UET_RESPONSE", [2]="UET_RESPONSE_W_DATA" }
local RC = { [0]="RC_NULL", [1]="RC_OK", [5]="RC_NO_MATCH", [7]="RC_UNSUPPORTED_SIZE", [0x1F]="RC_UNDELIVERABLE" }
local EHL = { [0]=0, [1]=4, [2]=8, [3]=16 }
local CRC_STATUS = { [0]="Good", [1]="Bad", [2]="Unverified" }

-- ---------------------------------------------------------------- fields
local F = {}
local function uf(name, abbr, b, vs) F[name] = ProtoField.uint32("sue." .. abbr, name, b or base.DEC, vs) end
local function u64(name, abbr) F[name] = ProtoField.uint64("sue." .. abbr, name, base.HEX) end
-- UFH
uf("UFH v", "ufh.v"); uf("UFH w", "ufh.w"); uf("UFH rsvd", "ufh.rr")
uf("da_encode", "ufh.da_encode", base.HEX); uf("sa_encode", "ufh.sa_encode", base.HEX)
uf("dst_addr", "ufh.dst", base.HEX); uf("src_addr", "ufh.src", base.HEX)
uf("dscp", "ufh.dscp"); uf("ecn", "ufh.ecn")
-- PDS
uf("type", "pds.type", base.DEC, PDS_TYPE); uf("next_hdr", "pds.next_hdr", base.HEX, NEXT_HDR)
uf("retx", "pds.retx"); uf("ar", "pds.ar"); uf("syn", "pds.syn"); uf("cack", "pds.cack")
uf("flags", "pds.flags", base.HEX)
uf("dpdcid", "pds.dpdcid", base.HEX); uf("spdcid", "pds.spdcid", base.HEX)
uf("pdc_info", "pds.pdc_info"); uf("psn_offset", "pds.psn_offset")
uf("psn_state", "pds.psn_state", base.HEX)
uf("clear_psn_offset", "pds.clear_psn_offset"); uf("rev_cack_psn_lsb", "pds.rev_cack_psn_lsb", base.HEX)
uf("psn", "pds.psn"); uf("expected psn", "pds.expected_psn")
uf("ack_psn", "pds.ack_psn"); uf("cack_psn", "pds.cack_psn")
-- ESUN
uf("EH rev", "esun.rev"); uf("EH F (flow label valid)", "esun.f"); uf("EH CoS", "esun.cos")
uf("EH ECN", "esun.ecn"); uf("EH flow label", "esun.flow_label", base.HEX); uf("EH TTL", "esun.ttl")
uf("EH UD", "esun.ud")
-- SES
uf("ac", "ses.ac"); uf("mm", "ses.mm")
uf("opcode", "ses.opcode", base.HEX, REQ_OP); uf("rsp opcode", "ses.rsp_opcode", base.HEX, RSP_OP)
uf("ver", "ses.ver"); uf("dc", "ses.dc"); uf("ie", "ses.ie"); uf("jobid", "ses.jobid")
uf("request_length", "ses.request_length"); uf("ehl", "ses.ehl")
u64("address", "ses.address"); u64("target address", "ses.target")
F["address_offset"] = ProtoField.int32("sue.ses.address_offset", "address_offset")
uf("return_code", "ses.return_code", base.HEX, RC); uf("payload_length", "ses.payload_length")
F["ext"] = ProtoField.bytes("sue.ses.ext", "extension header")
F["data"] = ProtoField.bytes("sue.ses.data", "data")
F["pad"] = ProtoField.bytes("sue.pad", "padding")
-- CRC
uf("UET CRC", "crc", base.HEX); uf("UET CRC calculated", "crc.calc", base.HEX)
uf("UET CRC status", "crc.status", base.DEC, CRC_STATUS)
F["crc_note"] = ProtoField.string("sue.crc.note", "UET CRC note")
for _, f in pairs(F) do table.insert(sue.fields, f) end

local ef_crc_bad = ProtoExpert.new("sue.crc.bad", "UET CRC mismatch", expert.group.CHECKSUM, expert.severity.ERROR)
local ef_crc_unv = ProtoExpert.new("sue.crc.unverified", "UET CRC not verified (PSN unknown)", expert.group.CHECKSUM, expert.severity.NOTE)
sue.experts = { ef_crc_bad, ef_crc_unv }

-- ---------------------------------------------------------------- helpers
local CRCT = {}
for i = 0, 255 do
  local c = i
  for _ = 1, 8 do c = (c & 1 == 1) and ((c >> 1) ~ 0x82F63B78) or (c >> 1) end
  CRCT[i] = c
end
local function crc32c(s)
  local c = 0xFFFFFFFF
  for i = 1, #s do c = CRCT[(c ~ s:byte(i)) & 0xFF] ~ (c >> 8) end
  return c ~ 0xFFFFFFFF
end

local function bytes_of(tvb, off, len) return tvb:range(off, len):bytes():raw() end
local function be(s, i, n) local v = 0; for k = 0, n - 1 do v = (v << 8) | s:byte(i + k) end; return v end
local function u32be(v) return string.char((v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF) end
local function bits(v, total, hi, n) return (v >> (total - hi - n)) & ((1 << n) - 1) end
local function pad4(n) return (4 - n % 4) % 4 end
local function crc_wire(tvb, off)
  local s = bytes_of(tvb, off, 4)
  if sue.prefs.crc_le then return s:byte(1) | (s:byte(2) << 8) | (s:byte(3) << 16) | (s:byte(4) << 24) end
  return be(s, 1, 4)
end
local function req_wire_bytes(op, len) if op == 1 or (op >= 3 and op <= 0x3E) then return len end; return 0 end

local function add_crc(tree, tvb, crc_off, calc, note)
  local wire = crc_wire(tvb, crc_off)
  local t = tree:add(sue, tvb(crc_off, 4), "UET CRC")
  t:add(F["UET CRC"], tvb(crc_off, 4), wire)
  local st
  if calc == nil then
    st = 2; t:add_proto_expert_info(ef_crc_unv)
  else
    t:add(F["UET CRC calculated"], tvb(crc_off, 4), calc):set_generated()
    st = (calc == wire) and 0 or 1
    if st == 1 then t:add_proto_expert_info(ef_crc_bad) end
  end
  t:add(F["UET CRC status"], tvb(crc_off, 4), st):set_generated()
  if note then t:add(F["crc_note"], tvb(crc_off, 4), note):set_generated() end
  t:append_text(string.format(": 0x%08X [%s]", wire, CRC_STATUS[st]))
  return st
end

-- SES chain. Returns the offset after the last message.
local function dissect_ses(tvb, tree, off, limit, next_hdr, info)
  local ehl_inh, addr, n, i = 0, 0, 0, 0
  local more = true
  while more and off < limit do
    i = i + 1
    if next_hdr == 7 then
      local w = be(bytes_of(tvb, off, 4), 1, 4)
      local ac, mm, op = bits(w, 32, 0, 1), bits(w, 32, 1, 1), bits(w, 32, 2, 6)
      local hlen = (ac == 0) and 12 or 8
      local t = tree:add(sue, tvb(off, hlen), string.format("SES request %d: %s (ac=%d)", i, REQ_OP[op] or string.format("op 0x%02x", op), ac))
      t:add(F["ac"], tvb(off, 1), ac); t:add(F["mm"], tvb(off, 1), mm); t:add(F["opcode"], tvb(off, 1), op)
      t:add(F["ver"], tvb(off + 1, 1), bits(w, 32, 8, 2)); t:add(F["dc"], tvb(off + 1, 1), bits(w, 32, 10, 1))
      t:add(F["ie"], tvb(off + 1, 1), bits(w, 32, 11, 1)); t:add(F["jobid"], tvb(off + 1, 2), bits(w, 32, 12, 8))
      local len = bits(w, 32, 20, 12)
      local ehl
      if ac == 0 then
        local s = bytes_of(tvb, off + 4, 8)
        local rle, e = (s:byte(1) >> 6) & 3, (s:byte(1) >> 4) & 3
        len = (rle << 12) | len
        addr = be(s, 1, 8) & 0x0FFFFFFFFFFFFFFF
        t:add(F["ehl"], tvb(off + 4, 1), e)
        t:add(F["address"], tvb(off + 4, 8), UInt64.new(addr & 0xFFFFFFFF, addr >> 32))
        ehl, ehl_inh = e, e
      else
        local o = be(bytes_of(tvb, off + 4, 4), 1, 4)
        if o >= 0x80000000 then o = o - 0x100000000 end
        addr = (addr + o) & 0x0FFFFFFFFFFFFFFF
        t:add(F["address_offset"], tvb(off + 4, 4), o)
        ehl = ehl_inh
      end
      t:add(F["request_length"], tvb(off + 2, 2), len)
      t:add(F["target address"], tvb(off, hlen), UInt64.new(addr & 0xFFFFFFFF, addr >> 32)):set_generated()
      off = off + hlen
      local el = EHL[ehl]
      if el > 0 then t:add(F["ext"], tvb(off, el)); off = off + el end
      local dl = req_wire_bytes(op, len)
      if dl > 0 then t:add(F["data"], tvb(off, dl)); off = off + dl end
      local pl = pad4(dl)
      if pl > 0 then t:add(F["pad"], tvb(off, pl)); off = off + pl end
      t:set_len(hlen + el + dl + pl)
      local nm = (REQ_OP[op] or "OP"):gsub("UET_", "")
      table.insert(info, nm .. " " .. len .. "B")
      more = (mm == 1)
    elseif next_hdr == 8 then
      local w = be(bytes_of(tvb, off, 4), 1, 4)
      local mm, op, rc, e, pl = bits(w, 32, 1, 1), bits(w, 32, 2, 6), bits(w, 32, 10, 6), bits(w, 32, 16, 2), bits(w, 32, 18, 14)
      local t = tree:add(sue, tvb(off, 4), string.format("SES response %d: %s %s", i, RSP_OP[op] or op, RC[rc] or rc))
      t:add(F["mm"], tvb(off, 1), mm); t:add(F["rsp opcode"], tvb(off, 1), op)
      t:add(F["ver"], tvb(off + 1, 1), bits(w, 32, 8, 2)); t:add(F["return_code"], tvb(off + 1, 1), rc)
      t:add(F["ehl"], tvb(off + 2, 1), e); t:add(F["payload_length"], tvb(off + 2, 2), pl)
      off = off + 4
      local el = EHL[e]
      if el > 0 then t:add(F["ext"], tvb(off, el)); off = off + el end
      if pl > 0 then t:add(F["data"], tvb(off, pl)); off = off + pl end
      local pp = pad4(pl)
      if pp > 0 then t:add(F["pad"], tvb(off, pp)); off = off + pp end
      t:set_len(4 + el + pl + pp)
      table.insert(info, "RSP " .. (RC[rc] or rc))
      more = (mm == 1)
    else
      break
    end
    n = n + 1
  end
  return off
end

local function trailer(tvb, tree, off, crc_off)
  if crc_off > off then tree:add(F["pad"], tvb(off, crc_off - off)) end
end

-- ---------------------------------------------------------------- PSN tracking (UFH_16 RODL)
-- Expected PSN per {src, dst, spdcid}; computed on the first pass and stored per frame.
local next_psn, frame_psn = {}, {}
function sue.init() next_psn, frame_psn = {}, {} end

-- ---------------------------------------------------------------- UFH_16
local function dissect_ufh16(tvb, pinfo, tree)
  local len = tvb:len()
  local raw = bytes_of(tvb, 0, len)
  local crc_off = len - 4
  local ptype = raw:byte(2) >> 3
  pinfo.cols.protocol = "SUE/UFH16"
  local root = tree:add(sue, tvb(), "SUE-T over UFH_16")
  local w0 = be(raw, 1, 4)
  local w1 = be(raw, 5, 4)
  local w2 = be(raw, 9, 4)
  local h = root:add(sue, tvb(0, (ptype == 7) and 20 or 16), "UFH_16 + PDS " .. (PDS_TYPE[ptype] or ptype))
  h:add(F["UFH v"], tvb(0, 1), bits(w0, 32, 0, 1)); h:add(F["UFH w"], tvb(0, 1), bits(w0, 32, 1, 1))
  h:add(F["da_encode"], tvb(0, 1), bits(w0, 32, 4, 4))
  h:add(F["type"], tvb(1, 1), ptype); local nh = bits(w0, 32, 13, 4); h:add(F["next_hdr"], tvb(1, 2), nh)
  local dst, src = bits(w1, 32, 0, 16), bits(w2, 32, 16, 16)
  h:add(F["dst_addr"], tvb(4, 2), dst); h:add(F["sa_encode"], tvb(6, 1), bits(w1, 32, 20, 4))
  h:add(F["dscp"], tvb(7, 1), bits(w1, 32, 24, 6)); h:add(F["ecn"], tvb(7, 1), bits(w1, 32, 30, 2))
  h:add(F["src_addr"], tvb(10, 2), src)
  local info = {}
  if ptype == 15 then
    local retx, ar, syn = bits(w0, 32, 17, 1), bits(w0, 32, 18, 1), bits(w0, 32, 19, 1)
    local dpd = bits(w0, 32, 20, 12)
    local spd = bits(w2, 32, 4, 12)
    local ps = (bits(w1, 32, 16, 4) << 20) | (bits(w2, 32, 0, 4) << 16) | be(raw, 15, 2)
    h:add(F["retx"], tvb(2, 1), retx); h:add(F["ar"], tvb(2, 1), ar); h:add(F["syn"], tvb(2, 1), syn)
    if syn == 1 then
      h:add(F["pdc_info"], tvb(2, 2), dpd >> 10); h:add(F["psn_offset"], tvb(2, 2), dpd & 0x3FF)
    else
      h:add(F["dpdcid"], tvb(2, 2), dpd)
    end
    h:add(F["spdcid"], tvb(8, 2), spd)
    h:add(F["psn_state"], tvb(6, 1), ps)
    local key = string.format("%04x>%04x/%03x", src, dst, spd)
    local psn
    if syn == 1 then
      psn = ps
      h:add(F["psn"], tvb(14, 2), psn):append_text(" (syn=1: PSN = {0x00, psn_state})")
    else
      local cpo = ps >> 12; if cpo >= 0x800 then cpo = cpo - 0x1000 end
      h:add(F["clear_psn_offset"], tvb(14, 2), cpo); h:add(F["rev_cack_psn_lsb"], tvb(14, 2), ps & 0xFFF)
      if not pinfo.visited then
        local ap = tonumber(sue.prefs.assume_psn)
        frame_psn[pinfo.number] = next_psn[key] or ap
      end
      psn = frame_psn[pinfo.number]
      if psn then h:add(F["expected psn"], tvb(0, 0), psn):set_generated() end
    end
    if not pinfo.visited and psn then next_psn[key] = (psn + 1) & 0xFFFFFFFF end
    local off = dissect_ses(tvb, root, 16, crc_off, nh, info)
    trailer(tvb, root, off, crc_off)
    local calc
    if psn then
      local m = raw:sub(1, 7) .. "\0" .. raw:sub(9, crc_off) .. u32be(psn)
      calc = crc32c(m)
    end
    local st = add_crc(root, tvb, crc_off, calc, psn and string.format("covers frame + PSN %d (not on the wire)", psn) or "syn=0 and no earlier syn=1 seen for this PDC")
    pinfo.cols.info = string.format("RODL %s%s spdcid=0x%03x %s  [%s]  CRC %s", syn == 1 and "SYN " or "",
      psn and ("PSN " .. psn) or "PSN ?", spd, table.concat(info, ", "), string.format("0x%04x > 0x%04x", src, dst), CRC_STATUS[st])
  elseif ptype == 7 then
    h:add(F["flags"], tvb(2, 1), bits(w0, 32, 17, 7))
    local dpd = (bits(w0, 32, 24, 8) << 4) | bits(w2, 32, 0, 4)
    h:add(F["dpdcid"], tvb(3, 1), dpd); h:add(F["spdcid"], tvb(8, 2), bits(w2, 32, 4, 12))
    h:add(F["ack_psn"], tvb(14, 2), be(raw, 15, 2)); h:add(F["cack_psn"], tvb(16, 4), be(raw, 17, 4))
    local off = dissect_ses(tvb, root, 20, crc_off, nh, info)
    trailer(tvb, root, off, crc_off)
    local m = raw:sub(1, 7) .. "\0" .. raw:sub(9, crc_off)
    local st = add_crc(root, tvb, crc_off, crc32c(m), "no PSN appended for non-RODL types (UEC Fig 3-122)")
    pinfo.cols.info = string.format("ACK cack_psn=%d %s  [0x%04x > 0x%04x]  CRC %s", be(raw, 17, 4),
      table.concat(info, ", "), src, dst, CRC_STATUS[st])
  else
    pinfo.cols.info = "UFH_16 PDS type " .. (PDS_TYPE[ptype] or ptype) .. " (not decoded)"
  end
end

-- ---------------------------------------------------------------- RODL general (ESUN, UDP)
local function dissect_rodl_general(tvb, tree, off, limit, info)
  local s = bytes_of(tvb, off, 12)
  local w0 = be(s, 1, 4)
  local t = tree:add(sue, tvb(off, 12), "PDS RODL request (general, 12 B)")
  t:add(F["type"], tvb(off, 1), bits(w0, 32, 0, 5))
  local nh = bits(w0, 32, 5, 4); t:add(F["next_hdr"], tvb(off, 2), nh)
  local cack = bits(w0, 32, 10, 1)
  t:add(F["cack"], tvb(off + 1, 1), cack); t:add(F["retx"], tvb(off + 1, 1), bits(w0, 32, 11, 1))
  t:add(F["ar"], tvb(off + 1, 1), bits(w0, 32, 12, 1)); t:add(F["syn"], tvb(off + 1, 1), bits(w0, 32, 13, 1))
  local p16 = w0 & 0xFFFF
  if cack == 1 then t:add(F["rev_cack_psn_lsb"], tvb(off + 2, 2), p16)
  else local v = p16; if v >= 0x8000 then v = v - 0x10000 end; t:add(F["clear_psn_offset"], tvb(off + 2, 2), v) end
  local psn = be(s, 5, 4)
  t:add(F["psn"], tvb(off + 4, 4), psn)
  t:add(F["spdcid"], tvb(off + 8, 2), be(s, 9, 2)); t:add(F["dpdcid"], tvb(off + 10, 2), be(s, 11, 2))
  table.insert(info, "RODL PSN " .. psn)
  return dissect_ses(tvb, tree, off + 12, limit, nh, info)
end

-- Full frame bytes, stashed by the top-level dissector for sub-dissectors that
-- need the whole frame for the CRC (ESUN covers from the DA, UDP from the IP source).
local cur_frame = { num = -1, raw = "" }

local esun = Proto("sue_esun", "ESUN header")
function esun.dissector(tvb, pinfo, tree)
  if cur_frame.num ~= pinfo.number then return 0 end
  local full = cur_frame.raw
  local base = #full - tvb:len()               -- offset of this tvb inside the frame
  local len = tvb:len()
  local crc_off = len - 4
  pinfo.cols.protocol = "SUE/ESUN"
  local root = tree:add(sue, tvb(), "SUE-T over ESUN")
  local w = be(bytes_of(tvb, 0, 4), 1, 4)
  local t = root:add(sue, tvb(0, 4), "ESUN header (4 B)")
  t:add(F["EH rev"], tvb(0, 1), bits(w, 32, 0, 2)); t:add(F["EH F (flow label valid)"], tvb(0, 1), bits(w, 32, 2, 1))
  t:add(F["EH CoS"], tvb(0, 1), bits(w, 32, 3, 3)); t:add(F["EH ECN"], tvb(0, 1), bits(w, 32, 6, 2))
  t:add(F["EH flow label"], tvb(1, 2), bits(w, 32, 8, 16)); t:add(F["EH TTL"], tvb(3, 1), bits(w, 32, 24, 4))
  t:add(F["EH UD"], tvb(3, 1), bits(w, 32, 28, 2))
  local info = {}
  local off = dissect_rodl_general(tvb, root, 4, crc_off, info)
  trailer(tvb, root, off, crc_off)
  local m = full:sub(1, base + crc_off)
  local eh = base + 1
  m = m:sub(1, eh - 1) .. string.char(m:byte(eh) & 0xE0) .. m:sub(eh + 1, eh + 2) .. string.char(m:byte(eh + 3) & 0x0F) .. m:sub(eh + 4)
  local st = add_crc(root, tvb, crc_off, crc32c(m), "project rule: from DA, EH CoS/ECN/TTL masked")
  pinfo.cols.info = string.format("ESUN cos=%d fl=0x%04x ttl=%d  %s  CRC %s", bits(w, 32, 3, 3), bits(w, 32, 8, 16),
    bits(w, 32, 24, 4), table.concat(info, ", "), CRC_STATUS[st])
  return len
end

local uetudp = Proto("sue_udp", "UET RODL over UDP")
function uetudp.dissector(tvb, pinfo, tree)
  if cur_frame.num ~= pinfo.number then return 0 end
  if tvb:len() < 16 or (tvb(0, 1):uint() >> 3) ~= 15 then return 0 end
  local full = cur_frame.raw
  local base = #full - tvb:len()
  local len = tvb:len()
  local crc_off = len - 4
  pinfo.cols.protocol = "SUE/UDP"
  local root = tree:add(sue, tvb(), "SUE-T over UDP/IP")
  local info = {}
  local off = dissect_rodl_general(tvb, root, 0, crc_off, info)
  trailer(tvb, root, off, crc_off)
  -- IPv4 without VLAN: IP at 14, UDP checksum at base-2
  local ip = 15
  local m = full:sub(ip + 12, base - 2) .. "\0\0" .. full:sub(base + 1, base + crc_off)
  local st = add_crc(root, tvb, crc_off, crc32c(m), "from IPv4 source address, UDP checksum as 0")
  pinfo.cols.info = string.format("%s  CRC %s", table.concat(info, ", "), CRC_STATUS[st])
  return len
end

-- ---------------------------------------------------------------- top level
local eth = Dissector.get("eth_withoutfcs")
function sue.dissector(tvb, pinfo, tree)
  local len = tvb:len()
  if len >= 20 then
    local b0 = tvb(0, 1):uint()
    local et = tvb(12, 2):uint()
    if (b0 & 0x80) == 0 and (b0 & 0x0E) == 0x02 and (b0 & 0x40) ~= 0 and et == 0xE790 then
      dissect_ufh16(tvb, pinfo, tree)
      return len
    end
  end
  cur_frame.num, cur_frame.raw = pinfo.number, bytes_of(tvb, 0, len)
  return eth:call(tvb, pinfo, tree)
end

DissectorTable.get("wtap_encap"):add(wtap.ETHERNET, sue)
DissectorTable.get("ethertype"):add(sue.prefs.esun_ethertype, esun)
DissectorTable.get("udp.port"):add(sue.prefs.udp_port, uetudp)

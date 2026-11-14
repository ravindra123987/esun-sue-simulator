"""Code points and configuration shared by the layers, the CRC and the dissector.

Every value cites where it comes from. Values marked DECISION are not fixed by
any spec; they are this project's choice and are recorded in docs/findings/m1-decisions.md.
"""

# --- Ethernet ---------------------------------------------------------------
ETHERTYPE_UET = 0xE790          # UEC 1.1 §5.4.3: EtherType after UFH = UET
UDP_PORT_UET = 4793             # SUE-T §8.3, UEC: UDP destination port for UET

# DECISION: ESUN EH-ET is "pending assignment" (ESUN 1.0 §5.1). 0x88B5 is the
# IEEE 802 local experimental EtherType. Keep it configurable.
ESUN_ETHERTYPE = 0x88B5
# DECISION: nothing in an ESUN frame says what follows the EH; SUE-T §8.3 says
# it is "inferred by network wide configuration". We assume the RODL general header.
ESUN_PAYLOAD = "rodl"

# --- UFH (UEC 1.1 §5.4.3, Table 5-40) -----------------------------------------
# First DA octet, readable format: [v w r r | z y x m]
UFH_V = 0                       # current version
UFH_W_32 = 0                    # w=0: UFH_32
UFH_W_16 = 1                    # w=1: UFH_16
# da_encode / sa_encode = [z, y, x, m]: z=y=0 (SLAP AAI), x=1 (local), m=multicast
UFH_ENCODE_UNICAST = 0b0010
UFH_ENCODE_MULTICAST = 0b0011
UFH16_HDR_LEN = 16              # 12 B overlay + EtherType + psn_state_low (Fig 3-68)
UFH16_TC_BYTE = 7               # dscp(6)+ecn(2): masked to 0 in the UET CRC (§3.5.26.1)

# --- PDS (UEC 1.1 Table 3-39) -------------------------------------------------
PDS_TYPE = {
    0: "Reserved", 1: "TSS", 2: "RUD_REQ", 3: "ROD_REQ", 4: "RUDI_REQ",
    5: "RUDI_RESP", 6: "UUD_REQ", 7: "ACK", 8: "ACK_CC", 9: "ACK_CCX",
    10: "NACK", 11: "CP", 12: "NACK_CCX", 13: "RUD_CC_REQ", 14: "ROD_CC_REQ",
    15: "RODL_REQ",
}
PDS_TYPE_ACK = 7
PDS_TYPE_NACK = 10
PDS_TYPE_RODL = 15
RODL_HDR_LEN = 12               # general format (Fig 3-67)

# --- SES next_hdr (UEC 1.1 §3.4.3.8, p275) ------------------------------------
NH_NONE = 0x00
NH_RESPONSE_DATA_SMALL = 0x06
NH_REQUEST_LCL = 0x07
NH_RESPONSE_DATA_LCL = 0x08
NEXT_HDR = {NH_NONE: "UET_HDR_NONE", NH_RESPONSE_DATA_SMALL: "UET_HDR_RESPONSE_DATA_SMALL",
            NH_REQUEST_LCL: "UET_HDR_REQUEST_LCL", NH_RESPONSE_DATA_LCL: "UET_HDR_RESPONSE_DATA_LCL"}

# --- SES opcodes (UEC 1.1 Table 3-8, p276) -----------------------------------
OP_NO_OP = 0x00
OP_WRITE = 0x01
OP_READ = 0x02
OP_ATOMIC = 0x03
OP_FETCHING_ATOMIC = 0x04
REQ_OPCODE = {OP_NO_OP: "UET_NO_OP", OP_WRITE: "UET_WRITE", OP_READ: "UET_READ",
              OP_ATOMIC: "UET_ATOMIC", OP_FETCHING_ATOMIC: "UET_FETCHING_ATOMIC"}
VENDOR_OPCODES = range(0x30, 0x3F)   # SUE-T: 0x30-0x3E vendor defined

RSP_DEFAULT_RESPONSE = 0x00
RSP_RESPONSE = 0x01
RSP_RESPONSE_W_DATA = 0x02
RSP_NO_RESPONSE = 0x03
RSP_OPCODE = {RSP_DEFAULT_RESPONSE: "UET_DEFAULT_RESPONSE", RSP_RESPONSE: "UET_RESPONSE",
              RSP_RESPONSE_W_DATA: "UET_RESPONSE_W_DATA", RSP_NO_RESPONSE: "UET_NO_RESPONSE"}

# Return codes (UEC 1.1 p277-278)
RETURN_CODE = {
    0x00: "RC_NULL", 0x01: "RC_OK", 0x02: "RC_BAD_GENERATION", 0x03: "RC_DISABLED", 0x04: "RC_DISABLED_GEN",
    0x05: "RC_NO_MATCH", 0x06: "RC_UNSUPPORTED_OP", 0x07: "RC_UNSUPPORTED_SIZE", 0x08: "RC_AT_INVALID",
    0x09: "RC_AT_PERM", 0x0A: "RC_AT_ATS_ERROR", 0x0B: "RC_AT_NO_TRANS", 0x0C: "RC_AT_OUT_OF_RANGE",
    0x0D: "RC_HOST_POISONED", 0x0E: "RC_HOST_UNSUCCESS_CMPL", 0x0F: "RC_AMO_UNSUPPORTED_OP",
    0x10: "RC_AMO_UNSUPPORTED_DT", 0x11: "RC_AMO_UNSUPPORTED_SIZE", 0x12: "RC_AMO_UNALIGNED",
    0x13: "RC_AMO_FP_NAN", 0x14: "RC_AMO_FP_UNDERFLOW", 0x15: "RC_AMO_FP_OVERFLOW", 0x16: "RC_AMO_FP_INEXACT",
    0x17: "RC_PERM_VIOLATION", 0x18: "RC_OP_VIOLATION", 0x19: "RC_BAD_INDEX", 0x1A: "RC_BAD_PID",
    0x1B: "RC_BAD_JOB_ID", 0x1C: "RC_BAD_MKEY", 0x1D: "RC_BAD_ADDR", 0x1E: "RC_CANCELLED",
    0x1F: "RC_UNDELIVERABLE", 0x20: "RC_UNCOR", 0x21: "RC_UNCOR_TRNSNT", 0x22: "RC_TOO_LONG",
    0x23: "RC_INITIATOR_ERROR", 0x24: "RC_DROPPED",
    **{v: f"RC_VENDOR_{v - 0x30}" for v in range(0x30, 0x38)},   # SUE-T maps AXI SLVERR/DECERR here
}
RC_NULL, RC_OK, RC_NO_MATCH, RC_UNSUPPORTED_SIZE, RC_BAD_ADDR, RC_UNDELIVERABLE = 0x00, 0x01, 0x05, 0x07, 0x1D, 0x1F

EHL_BYTES = {0: 0, 1: 4, 2: 8, 3: 16}   # ses.ehl encoding (Table 3-12)
ATOMIC_HDR_LEN = 4                       # §3.4.3.5, Fig 3-20/3-22: after the extension header
MAX_PACKED = 16                          # SUE-T: up to 16 CMD_PDUs per packet

# --- Frame sizing (UEC §3.5.26.1) --------------------------------------------
MIN_BODY_BEFORE_CRC = 56        # pad to 56 so CRC(4)+FCS(4) reach 64 B
UET_CRC_LEN = 4

# DECISION (D8): byte order of the 4-byte UET CRC trailer. Big-endian matches
# UEC's "network byte order" and Wireshark packet-uet.c (ENC_BIG_ENDIAN), whose
# generated test capture we reproduce. UEC's other sentence ("x^31 in the
# left-most bit of the first octet", copied from IEEE 802.3) suggests the
# little-endian FCS-style layout. Unresolved until a hardware capture exists.
CRC_BYTE_ORDER = "big"
# DECISION: byte order of the hidden 32-bit PSN appended to the CRC input.
PSN_BYTE_ORDER = "big"
# DECISION (D6): with minimum-size padding, the hidden PSN goes after the pad
# (Fig 3-122 "crc_end for RODL"). False = the literal §3.5.26.1 step 2 reading:
# right after the SES payload, before the pad.
PSN_AFTER_PAD = True

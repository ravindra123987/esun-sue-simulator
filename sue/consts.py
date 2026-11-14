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
RSP_OPCODE = {RSP_DEFAULT_RESPONSE: "UET_DEFAULT_RESPONSE", RSP_RESPONSE: "UET_RESPONSE",
              RSP_RESPONSE_W_DATA: "UET_RESPONSE_W_DATA"}

# Return codes (UEC 1.1 p277-278), the subset SUE-T uses
RC_NULL = 0x00
RC_OK = 0x01
RC_NO_MATCH = 0x05
RC_UNSUPPORTED_SIZE = 0x07
RC_UNDELIVERABLE = 0x1F
RETURN_CODE = {RC_NULL: "RC_NULL", RC_OK: "RC_OK", RC_NO_MATCH: "RC_NO_MATCH",
               RC_UNSUPPORTED_SIZE: "RC_UNSUPPORTED_SIZE", RC_UNDELIVERABLE: "RC_UNDELIVERABLE"}

EHL_BYTES = {0: 0, 1: 4, 2: 8, 3: 16}   # ses.ehl encoding (Table 3-12)

# --- Frame sizing (UEC §3.5.26.1) --------------------------------------------
MIN_BODY_BEFORE_CRC = 56        # pad to 56 so CRC(4)+FCS(4) reach 64 B
UET_CRC_LEN = 4

# DECISION: byte order of the 4-byte UET CRC trailer. UEC says "network byte
# order, x^31 term in the left-most bit of the first octet" -> big-endian.
CRC_BYTE_ORDER = "big"
# DECISION: byte order of the hidden 32-bit PSN appended to the CRC input.
PSN_BYTE_ORDER = "big"

"""Scapy layers for SUE-T over UFH_16, ESUN and UDP/IP (UEC 1.1 Unified Local + RODL)."""

from scapy.layers.inet import UDP
from scapy.layers.l2 import Ether
from scapy.packet import bind_layers

from .. import consts as C
from .esun import ESUN
from .pds import RODL
from .ses import SESReqLcl0, SESReqLcl1, SESRespLcl, target_addresses
from .ufh import UFH16Ack, UFH16RODL, is_ufh, is_ufh16, psn_state_syn0, split_psn_state

bind_layers(Ether, ESUN, type=C.ESUN_ETHERTYPE)
bind_layers(UDP, RODL, dport=C.UDP_PORT_UET)

__all__ = ["ESUN", "RODL", "SESReqLcl0", "SESReqLcl1", "SESRespLcl", "UFH16Ack", "UFH16RODL",
           "is_ufh", "is_ufh16", "psn_state_syn0", "split_psn_state", "target_addresses"]

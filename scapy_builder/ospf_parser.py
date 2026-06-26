"""
OSPF Packet Parsing Utilities

Provides functions to parse OSPF packets received from the target:
- parse_hello(): Extract Hello packet fields
- parse_dbd(): Extract Database Description fields and LSA headers
- parse_lsu(): Extract Link State Update and LSAs
- parse_lsack(): Extract Link State Acknowledgment headers

These functions operate on Scapy packet objects.
"""

from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello, OSPF_DBDesc, OSPF_LSUpd, OSPF_LSA_Hdr
from scapy.contrib.ospf import OSPF_Router_LSA, OSPF_Network_LSA, OSPF_SummaryIP_LSA, OSPF_External_LSA
from typing import Dict, List, Optional, Any


def parse_hello(packet) -> Optional[Dict[str, Any]]:
    """
    Parse OSPF Hello packet
    
    Returns dict with:
    - router_id: str (e.g., "10.0.0.1")
    - area_id: str
    - network_mask: str
    - hello_interval: int
    - dead_interval: int
    - priority: int
    - dr: str (Designated Router)
    - bdr: str (Backup Designated Router)
    - neighbors: List[str] (list of router IDs)
    """
    try:
        if not packet.haslayer(OSPF_Hello):
            return None
        
        ospf_hdr = packet[OSPF_Hdr]
        hello = packet[OSPF_Hello]
        
        result = {
            'router_id': ospf_hdr.src,
            'area_id': ospf_hdr.area,
            'network_mask': hello.mask,
            'hello_interval': hello.hellointerval,
            'dead_interval': hello.deadinterval,
            'priority': hello.prio,
            'dr': hello.router,
            'bdr': hello.backup,
            'neighbors': []
        }
        
        # Extract neighbor list (Active Neighbors field)
        # Scapy stores neighbors in the 'neighbors' field as a list
        if hasattr(hello, 'neighbors') and hello.neighbors:
            result['neighbors'] = [str(n) for n in hello.neighbors]
        
        return result
        
    except Exception as e:
        print(f"[-] Error parsing Hello packet: {e}")
        return None


def parse_dbd(packet) -> Optional[Dict[str, Any]]:
    """
    Parse OSPF Database Description packet
    
    Returns dict with:
    - seq: int (DD sequence number)
    - init: bool (I-bit)
    - more: bool (M-bit)
    - master: bool (MS-bit)
    - lsa_headers: List[Dict] (list of LSA header dicts)
    
    Each LSA header dict contains:
    - ls_type: int (1=Router, 2=Network, 3=Summary, 5=External)
    - ls_id: str (Link State ID)
    - adv_router: str (Advertising Router)
    - seq: int (LS Sequence Number)
    - age: int (LS Age)
    - checksum: int (LS Checksum)
    - length: int (LS Length)
    """
    try:
        if not packet.haslayer(OSPF_DBDesc):
            return None
        
        dbd = packet[OSPF_DBDesc]
        
        # Extract flags from options field
        # OSPF DBD flags: bit 0 = MS (Master), bit 1 = M (More), bit 2 = I (Init)
        options = dbd.options if hasattr(dbd, 'options') else 0
        
        # DBDesc-specific flags (ddseq field contains flags in Scapy)
        # Actually, Scapy uses separate fields for these
        master = bool(dbd.options & 0x01) if hasattr(dbd, 'options') else False
        more = bool(dbd.options & 0x02) if hasattr(dbd, 'options') else False
        init = bool(dbd.options & 0x04) if hasattr(dbd, 'options') else False
        
        result = {
            'seq': dbd.ddseq,
            'init': init,
            'more': more,
            'master': master,
            'lsa_headers': []
        }
        
        # Parse LSA headers
        # Scapy stores LSA headers in 'lsaheaders' field
        if hasattr(dbd, 'lsaheaders') and dbd.lsaheaders:
            lsa_list = dbd.lsaheaders
            
            # Handle both single LSA and list of LSAs
            if not isinstance(lsa_list, list):
                lsa_list = [lsa_list]
            
            for lsa_hdr in lsa_list:
                if hasattr(lsa_hdr, 'type'):
                    header_dict = {
                        'ls_type': lsa_hdr.type,
                        'ls_id': lsa_hdr.id,
                        'adv_router': lsa_hdr.adrouter,
                        'seq': lsa_hdr.seq,
                        'age': lsa_hdr.age,
                        'checksum': lsa_hdr.chksum,
                        'length': lsa_hdr.len
                    }
                    result['lsa_headers'].append(header_dict)
        
        return result
        
    except Exception as e:
        print(f"[-] Error parsing DBD packet: {e}")
        import traceback
        traceback.print_exc()
        return None


def parse_lsu(packet) -> Optional[Dict[str, Any]]:
    """
    Parse OSPF Link State Update packet
    
    Returns dict with:
    - lsa_count: int (number of LSAs)
    - lsas: List[Dict] (list of complete LSA dicts)
    
    Each LSA dict contains the header fields plus type-specific data.
    For simplicity, we only extract header information here.
    """
    try:
        if not packet.haslayer(OSPF_LSUpd):
            return None
        
        lsu = packet[OSPF_LSUpd]
        
        result = {
            'lsa_count': lsu.lsacount,
            'lsas': []
        }
        
        # Parse LSAs
        # Scapy stores LSAs in 'lsalist' field
        if hasattr(lsu, 'lsalist') and lsu.lsalist:
            lsa_list = lsu.lsalist
            
            # Handle both single LSA and list of LSAs
            if not isinstance(lsa_list, list):
                lsa_list = [lsa_list]
            
            for lsa in lsa_list:
                if hasattr(lsa, 'type'):
                    lsa_dict = {
                        'ls_type': lsa.type,
                        'ls_id': lsa.id,
                        'adv_router': lsa.adrouter,
                        'seq': lsa.seq,
                        'age': lsa.age,
                        'checksum': lsa.chksum,
                        'length': lsa.len,
                        'data': lsa  # Store full LSA object for detailed parsing if needed
                    }
                    result['lsas'].append(lsa_dict)
        
        return result
        
    except Exception as e:
        print(f"[-] Error parsing LSU packet: {e}")
        import traceback
        traceback.print_exc()
        return None


def parse_lsack(packet) -> Optional[Dict[str, Any]]:
    """
    Parse OSPF Link State Acknowledgment packet
    
    Returns dict with:
    - lsa_headers: List[Dict] (list of acknowledged LSA headers)
    
    Same format as parse_dbd() LSA headers.
    """
    try:
        # LSAck uses OSPF_LSA_Hdr directly in payload
        if not packet.haslayer(OSPF_Hdr):
            return None
        
        ospf_hdr = packet[OSPF_Hdr]
        
        # Check if packet type is 5 (LS Acknowledgment)
        if ospf_hdr.type != 5:
            return None
        
        result = {
            'lsa_headers': []
        }
        
        # Parse LSA headers from the packet
        # LSAck contains one or more OSPF_LSA_Hdr layers
        current_layer = ospf_hdr.payload
        
        while current_layer:
            if isinstance(current_layer, OSPF_LSA_Hdr):
                header_dict = {
                    'ls_type': current_layer.type,
                    'ls_id': current_layer.id,
                    'adv_router': current_layer.adrouter,
                    'seq': current_layer.seq,
                    'age': current_layer.age,
                    'checksum': current_layer.chksum,
                    'length': current_layer.len
                }
                result['lsa_headers'].append(header_dict)
            
            # Move to next layer
            if hasattr(current_layer, 'payload'):
                current_layer = current_layer.payload
            else:
                break
        
        return result
        
    except Exception as e:
        print(f"[-] Error parsing LSAck packet: {e}")
        return None


def get_packet_type(packet) -> Optional[int]:
    """
    Get OSPF packet type from packet
    
    Returns:
    - 1: Hello
    - 2: Database Description
    - 3: Link State Request
    - 4: Link State Update
    - 5: Link State Acknowledgment
    - None: Not an OSPF packet or unable to determine
    """
    try:
        if packet.haslayer(OSPF_Hdr):
            return packet[OSPF_Hdr].type
        return None
    except Exception:
        return None


def format_lsa_header(lsa_header: Dict[str, Any]) -> str:
    """
    Format LSA header dict as human-readable string
    
    Used for debugging and logging
    """
    ls_type_names = {
        1: "Router-LSA",
        2: "Network-LSA",
        3: "Summary-LSA (IP)",
        4: "Summary-LSA (ASBR)",
        5: "AS-External-LSA",
        7: "NSSA-External-LSA"
    }
    
    type_name = ls_type_names.get(lsa_header['ls_type'], f"Type-{lsa_header['ls_type']}")
    
    return (f"{type_name}: "
            f"ID={lsa_header['ls_id']}, "
            f"AdvRtr={lsa_header['adv_router']}, "
            f"Seq=0x{lsa_header['seq']:08x}, "
            f"Age={lsa_header['age']}s")


def print_lsa_headers(lsa_headers: List[Dict[str, Any]], prefix: str = "  "):
    """
    Pretty-print list of LSA headers
    
    Used for debugging
    """
    if not lsa_headers:
        print(f"{prefix}(no LSA headers)")
        return
    
    for i, hdr in enumerate(lsa_headers, 1):
        print(f"{prefix}[{i}] {format_lsa_header(hdr)}")

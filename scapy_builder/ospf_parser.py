import threading
import time
from scapy.all import *
from scapy.contrib.ospf import *
from config import *
from typing import Optional
from scapy.packet import NoPayload
from scapy.contrib.ospf import OSPF_DBDesc, OSPF_Hdr, OSPF_LSA_Hdr

# Packet parsing utilities

def parse_hello(pkt) -> dict:
    """
    Extract relevant fields from Hello packet
    """
    if not pkt.haslayer(OSPF_Hello):
        return None # type: ignore
    
    hello = pkt[OSPF_Hello]
    ospf_hdr = pkt[OSPF_Hdr]
    options_int = int(hello.options) if hello.options is not None else 0
    
    return {
        'router_id': ospf_hdr.src,
        'netmask': hello.mask,  
        'priority': hello.prio,
        'dr': hello.router,
        'bdr': hello.backup,
        'neighbors': hello.neighbors if hasattr(hello, 'neighbors') else [],
        'options': hello.options,
        'dead_interval': hello.deadinterval,
        'hello_interval': hello.hellointerval,
        'options_int':options_int
    }




def parse_dbd(pkt) -> dict:
    """
    Extract relevant fields from an OSPF DBD packet.
    Raises ValueError if the packet is not a valid OSPF DBD packet.
    """
    if not pkt.haslayer(OSPF_DBDesc) or not pkt.haslayer(OSPF_Hdr):
        raise ValueError("Provided packet is missing OSPF_DBDesc or OSPF_Hdr layers")

    dbd = pkt[OSPF_DBDesc]
    ospf_hdr = pkt[OSPF_Hdr]

    # Parse DBD flags (I/M/MS bits)
    flags = dbd.dbdescr
    init = bool(flags & 0x04)
    more = bool(flags & 0x02)
    master = bool(flags & 0x01)

    # Walk the payload chain and collect LSA headers
    lsa_headers = []
    for lsa in dbd.lsaheaders:
        lsa_headers.append({
            'type': lsa.type,
            'id': lsa.id,
            'adv_router': lsa.adrouter,
            'seq': lsa.seq,
            'age': lsa.age,
            'chksum': lsa.chksum,
        })
    # print("attention"*60)
    # print(lsa_headers)

    # raise BaseException("check error ro")
    return {
        'router_id': ospf_hdr.src,
        'seq': dbd.ddseq,
        'mtu': dbd.mtu,
        'options': dbd.options,
        'init': init,
        'more': more,
        'master': master,
        'lsa_headers': lsa_headers,
    }


def parse_lsr(pkt) -> dict:
    """
    Extract LSA requests from LSR packet
    """
    if not pkt.haslayer(OSPF_LSReq):
        return None # type: ignore
    
    ospf_hdr = pkt[OSPF_Hdr]
    requests = []
    
    layer = pkt
    while layer:
        if layer.haslayer(OSPF_LSReq):
            lsr = layer[OSPF_LSReq]
            requests.append({
                'type': lsr.type,
                'id': lsr.id,
                'adv_router': lsr.adrouter
            })
            layer = layer.payload
        else:
            break
    
    return {
        'router_id': ospf_hdr.src,
        'requests': requests
    }


def parse_lsu(pkt) -> dict:
    """
    Extract LSAs from LSU packet
    """
    if not pkt.haslayer(OSPF_LSUpd):
        return None # type: ignore
    
    ospf_hdr = pkt[OSPF_Hdr]
    lsu = pkt[OSPF_LSUpd]
    
    lsas = []
    layer = pkt
    while layer:
        if layer.haslayer(OSPF_LSA_Hdr):
            lsa_hdr = layer[OSPF_LSA_Hdr]
            lsas.append({
                'type': lsa_hdr.type,
                'id': lsa_hdr.id,
                'adv_router': lsa_hdr.adrouter,
                'seq': lsa_hdr.seq,
                'age': lsa_hdr.age,
                'chksum': lsa_hdr.chksum,
                'raw': lsa_hdr  # Keep raw object for LSAck
            })
            layer = layer.payload
        else:
            break
    
    return {
        'router_id': ospf_hdr.src,
        'lsa_count': lsu.lsacount,
        'lsas': lsas
    }


def parse_lsack(pkt) -> dict:
    """
    Extract acknowledged LSA headers from LSAck packet
    """
    if not pkt.haslayer(OSPF_Hdr):
        return None # type: ignore
    
    ospf_hdr = pkt[OSPF_Hdr]
    
    # LSAck is just a series of LSA headers
    lsa_headers = []
    layer = pkt
    while layer:
        if layer.haslayer(OSPF_LSA_Hdr):
            lsa_hdr = layer[OSPF_LSA_Hdr]
            lsa_headers.append({
                'type': lsa_hdr.type,
                'id': lsa_hdr.id,
                'adv_router': lsa_hdr.adrouter,
                'seq': lsa_hdr.seq
            })
            layer = layer.payload
        else:
            break
    
    return {
        'router_id': ospf_hdr.src,
        'acked_lsas': lsa_headers
    }

"""
OSPF Packet Handler - Reactive packet processing
Sniffs OSPF packets, parses them, and dispatches to FSM callbacks
"""

import threading
import time
from scapy.all import *
from scapy.contrib.ospf import *
from config import *
from typing import Optional
from scapy.packet import NoPayload
from scapy.contrib.ospf import OSPF_DBDesc, OSPF_Hdr, OSPF_LSA_Hdr

class OSPFPacketHandler:
    """
    Reactive OSPF packet handler
    Runs background sniffer and dispatches parsed packets to registered callbacks
    """
    
    def __init__(self, target_router_id: str):
        self.target_router_id = target_router_id
        self.running = False
        self.sniffer_thread = None
        
        # Callback registry: packet_type -> callback function
        self.callbacks: dict[int, Optional[Callable[[Any], None]]] = {
            1: None,  # Hello
            2: None,  # DBD
            3: None,  # LSR
            4: None,  # LSU
            5: None   # LSAck
        }

        self.queues = {
            1: Queue(), # Hello
            2: Queue(), # DBD
            3: Queue(), # LSR
            4: Queue(), # LSU
            5: Queue()  # LSAck
        }
        
        self.lock = threading.Lock()
    
    def register_callback(self, packet_type: int, callback):
        """
        Register callback for specific OSPF packet type
        packet_type: 1=Hello, 2=DBD, 3=LSR, 4=LSU, 5=LSAck
        callback: function(packet) to call when packet received
        """
        with self.lock:
            self.callbacks[packet_type] = callback
    
    def _packet_filter(self, pkt) -> bool:
        """
        Filter for OSPF packets from target router
        """
        if not pkt.haslayer(OSPF_Hdr):
            return False
        
        ospf_hdr = pkt[OSPF_Hdr]
        
        # Only process packets from our target router
        if ospf_hdr.src != self.target_router_id:
            return False
        
        return True
    
    def _packet_callback(self, pkt):
        """
        Process received OSPF packet and dispatch to appropriate handler
        """
        if not self._packet_filter(pkt):
            return
        
        ospf_hdr = pkt[OSPF_Hdr]
        packet_type = ospf_hdr.type
        
        #save all of the packet
        if packet_type in self.queues:
            self.queues[packet_type].put(pkt)

        
        # Get registered callback for this packet type
        with self.lock:
            callback = self.callbacks.get(packet_type)
        
        if callback:
            try:
                callback(pkt)
            except Exception as e:
                print(f"[-] Error in callback for packet type {packet_type}: {e}")
    
    def _sniffer_loop(self):
        """
        Background sniffer loop
        """
        print(f"[*] Starting OSPF sniffer on {IFACE}")
        
        # Scapy filter: IP protocol 89 (OSPF)
        sniff(
            iface=IFACE,
            filter="proto 89",
            prn=self._packet_callback,
            store=False,
            stop_filter=lambda x: not self.running
        )
        
        print("[*] OSPF sniffer stopped")
    
    def start(self):
        """
        Start background packet sniffer
        """
        if self.running:
            print("[-] Handler already running")
            return
        
        self.running = True
        self.sniffer_thread = threading.Thread(target=self._sniffer_loop, daemon=True)
        self.sniffer_thread.start()
        print("[+] OSPF packet handler started")
    
    def stop(self):
        """
        Stop background packet sniffer
        """
        if not self.running:
            return
        
        print("[*] Stopping OSPF packet handler...")
        self.running = False
        
        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=3)
        
        print("[+] OSPF packet handler stopped")
    
    def wait_for_packet(self, packet_type: int, timeout: int = 10):
        try:
            #return first packet in queue or wait for it
            return self.queues[packet_type].get(block=True, timeout=timeout)
        except Empty:
            return None


# Packet parsing utilities

def parse_hello(pkt) -> dict:
    """
    Extract relevant fields from Hello packet
    """
    if not pkt.haslayer(OSPF_Hello):
        return None # type: ignore
    
    hello = pkt[OSPF_Hello]
    ospf_hdr = pkt[OSPF_Hdr]
    
    return {
        'router_id': ospf_hdr.src,
        'priority': hello.prio,
        'dr': hello.router,
        'bdr': hello.backup,
        'neighbors': hello.neighbors if hasattr(hello, 'neighbors') else [],
        'options': hello.options,
        'dead_interval': hello.deadinterval,
        'hello_interval': hello.hellointerval
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

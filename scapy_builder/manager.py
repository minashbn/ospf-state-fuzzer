#!/usr/bin/env python3
"""
OSPF Neighbor FSM Simulator - Main Entry Point

Drives a target FRRouting (FRR) router through the complete OSPFv2 
state machine from Down to Full adjacency.

Usage:
    sudo python3 main.py

Requirements:
    - Root/sudo access (raw socket operations)
    - Target FRR router reachable on configured interface
    - Scapy installed with OSPF contrib module
"""

import sys
import signal
import time
import logging
from typing import Optional

from .ospf_neighbor import OSPFNeighbor, OSPFState
from .ospf_handler import OSPFPacketHandler
from .ospf_fsm import OSPFStateMachine
from config import (
    TARGET_ROUTER_ID,
    TARGET_ROUTER_IP,
    ATTACKER_ROUTER_ID,
    ATTACKER_IP,
    IFACE
)

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


class OSPFSimulator:
    """
    Main OSPF Neighbor Simulator
    
    Orchestrates the FSM controller, packet handler, and neighbor state
    to drive adjacency to Full state and maintain it.
    """
    
    def __init__(self,func):
        self.neighbor: Optional[OSPFNeighbor] = None
        self.handler: Optional[OSPFPacketHandler] = None
        self.fsm: Optional[OSPFStateMachine] = None
        self.running = False
        self.func=func
        
        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle Ctrl+C and termination signals"""
        logger.warning("\n[!] Received shutdown signal")
        self.shutdown()
        sys.exit(0)
    
    def initialize(self) -> bool:
        """
        Initialize all components
        
        Returns:
            True if initialization succeeded, False otherwise
        """
        try:
            logger.info("=" * 60)
            logger.info("OSPF Neighbor FSM Simulator")
            logger.info("=" * 60)
            logger.info(f"Our Router ID:     {ATTACKER_ROUTER_ID}")
            logger.info(f"Our IP:            {ATTACKER_IP}")
            logger.info(f"Target Router ID:  {TARGET_ROUTER_ID}")
            logger.info(f"Target IP:         {TARGET_ROUTER_IP}")
            logger.info(f"Interface:         {IFACE}")
            logger.info("=" * 60)
            
            # Create neighbor instance
            self.neighbor = OSPFNeighbor(
                target_router_id=TARGET_ROUTER_ID,
                target_ip=TARGET_ROUTER_IP
            )
            
            # Register state change callback
            self.neighbor.register_state_callback(OSPFState.DOWN,self._on_state_change)
            
            # Create packet handler
            self.handler = OSPFPacketHandler(
                target_router_id=TARGET_ROUTER_ID
            )
            
            # Create FSM controller
            self.fsm = OSPFStateMachine(
                neighbor=self.neighbor,
                handler=self.handler
            )
            
            logger.info("[+] All components initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"[-] Initialization failed: {e}")
            return False
    
    def _on_state_change(self, old_state: OSPFState, new_state: OSPFState):
        """Callback invoked on neighbor state transitions"""
        logger.info(f"[STATE] {old_state.name} → {new_state.name}")
    
    def run(self) -> dict:
        """
        Execute the main simulation
        
        Returns:
            True if Full adjacency achieved and maintained, False otherwise
        """
        if not self.initialize():
            return {}
        
        self.running = True
        
        try:
            # Start packet handler in background
            logger.info("[*] Starting packet handler...")
            self.handler.start() # type: ignore
            
            # Give handler time to initialize
            time.sleep(1)
            
            # Drive FSM to Full state
            logger.info("[*] Starting FSM progression to FULL state...")
            
            success = getattr(self.fsm, self.func)() # type: ignore
            
            if not success:
                logger.error("[-] Failed to reach FULL state")
                return {}
            
            param=self.fsm.get_neighbor_params() # type: ignore
            
            logger.info("[+] FULL adjacency established!")
            logger.info("")
            logger.info("=" * 60)
            logger.info("Adjacency is now active. Heartbeat running.")
            logger.info("=" * 60)
            
            # Monitor adjacency health
            # self._monitor_adjacency()
            
            return param
            
        
            
        finally:
            self.shutdown()
    
    def _monitor_adjacency(self):
        """
        Monitor adjacency health in infinite loop
        
        Checks neighbor liveness every 10 seconds.
        If neighbor dies (no Hello received within dead interval),
        attempt to re-establish adjacency.
        """
        check_interval = 10  # seconds
        
        while self.running:
            try:
                time.sleep(check_interval)
                
                if not self.neighbor.is_alive(): # type: ignore
                    logger.warning("[!] Neighbor appears dead (no Hello received)")
                    logger.info("[*] Attempting to re-establish adjacency...")
                    
                    # Reset neighbor state
                    self.neighbor.set_state(OSPFState.DOWN) # type: ignore
                    
                    # Attempt to drive back to Full
                    success = self.fsm.drive_to_full() # type: ignore
                    
                    if success:
                        logger.info("[+] Adjacency re-established")
                    else:
                        logger.error("[-] Failed to re-establish adjacency")
                        logger.info("[*] Will retry in next check cycle...")
                
                else:
                    # Adjacency healthy
                    current_state = self.neighbor.get_state() # type: ignore
                    if current_state == OSPFState.FULL:
                        logger.debug(f"[✓] Adjacency healthy (state={current_state.name})")
                    
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"[-] Monitor error: {e}")
    
    def shutdown(self):
        """Clean shutdown of all components"""
        logger.info("[*] Shutting down...")
        
        self.running = False
        
        if self.neighbor:
            self.neighbor.stop_heartbeat()
        
        if self.handler:
            self.handler.stop()
        
        logger.info("[+] Shutdown complete")


def main():
    """Main entry point"""
    
    # Check for root privileges
    if sys.platform.startswith('linux'):
        import os
        if os.geteuid() != 0:
            print("[-] Error: This script requires root privileges")
            print("    Run with: sudo python3 main.py")
            sys.exit(1)
    
    # Create and run simulator
    # simulator = OSPFSimulator()
    # success = simulator.run()
    
    # Exit with appropriate code
    # sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()

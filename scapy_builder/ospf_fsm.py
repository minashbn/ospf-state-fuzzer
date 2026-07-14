"""
OSPF Finite State Machine - RFC 2328 compliant
Implements complete adjacency formation with dynamic parameter extraction
All packets synchronized with target router configuration
"""
import time
from scapy.all import sendp
from scapy.contrib.ospf import *
from config import *
from .ospf_packets import *
from .ospf_handler import *
from .ospf_neighbor import OSPFState
import ipaddress
from scapy.contrib.ospf import OSPF_LSA_Hdr


class OSPFStateMachine:
    """
    FSM transition logic for OSPF neighbor adjacency
    Each reach_state_X() function drives the target from current state to target state
    Uses dynamic parameter extraction to ensure packet field consistency
    """
    
    def __init__(self, neighbor, handler):
        self.neighbor = neighbor
        self.handler = handler
        self.max_retries = neighbor.max_retries
        self.retry_timeout = neighbor.retry_timeout
        self.neighbor_params = None  # Extracted from target's Hello packet
        
    def _send_packet(self, pkt):
        """Send OSPF packet on configured interface"""
        sendp(pkt, iface=IFACE, verbose=False)
        
    def _retry_wrapper(self, func, state_name: str):
            """Retry logic for state transitions with full DOWN reset on failure"""
            for attempt in range(1, self.max_retries + 1):
                print(f"[*] Attempting {state_name} (attempt {attempt}/{self.max_retries})")
                if func():
                    print(f"[+] {state_name} reached successfully")
                    return True
                    
                if attempt < self.max_retries:
                    print(f"[!] {state_name} failed. Hard-resetting state machine to DOWN for the next attempt...")
                    self._hard_reset_to_down()
                    print(f"[!] Retry {state_name} in {self.retry_timeout}s...")
                    time.sleep(self.retry_timeout)
                    
            print(f"[-] Failed to reach {state_name} after {self.max_retries} attempts")
            self._hard_reset_to_down()
            return False

    def _hard_reset_to_down(self):
        """Completely wipes the neighbor context and forces OSPF State to DOWN"""
        self.neighbor.set_state(OSPFState.DOWN)
        self.neighbor_params = None
        
        self.neighbor.target_router_id = None
        self.neighbor.target_priority = None
        self.neighbor.target_dr = None
        self.neighbor.target_bdr = None
        
        self.neighbor.dd_sequence = None
        self.neighbor.target_dd_sequence = None
        self.neighbor.master = None
        self.neighbor.received_lsa_headers = []
        print("[*] State machine context has been completely cleared (Fresh Start).")
    
    def get_neighbor_params(self) -> dict:
        """
        Return all captured neighbor parameters as a dictionary.
        These parameters are extracted during INIT state by sniffing the target's Hello packet.
        
        Returns:
            dict: Dictionary containing all OSPF neighbor parameters, or empty dict if not yet captured
        """
        if not self.neighbor_params:
            return {}
        
        self.update_target_lsa_params()
        
        print(60*'***')
        return {
            'router_id': self.neighbor.target_router_id,
            'area_id': self.neighbor.area_id,
            'network_mask': getattr(self.neighbor, 'network_mask', None),
            'hello_interval': getattr(self.neighbor, 'hello_interval', None),
            'router_priority': self.neighbor.target_priority,
            'router_dead_interval': getattr(self.neighbor, 'dead_interval', None),
            'designated_router': self.neighbor.target_dr,
            'backup_designated_router': self.neighbor.target_bdr,
            'auth_type': getattr(self.neighbor, 'auth_type', None),
            'auth_data': getattr(self.neighbor, 'auth_data', None),

            # FIX: Include the negotiated state parameters for BoFuzz to pick up
            'dbd_flags': getattr(self.neighbor, 'next_dbd_flags', 0x02),
            'dd_seq_number': getattr(self.neighbor, 'next_dd_seq', 0x00000001),
            'mtu': getattr(self.neighbor, 'mtu', 1500),

            # NEW: Extracted Target LSA values for stable LSR generation
            'req_ls_type': getattr(self.neighbor, 'target_req_ls_type', 1),
            'req_link_state_id': getattr(self.neighbor, 'target_req_link_state_id', '0.0.0.0'),
            'req_advertising_router': getattr(self.neighbor, 'target_req_advertising_router', '0.0.0.0')
        }

    def update_target_lsa_params(self):
        """
        Extracts the first LSA header from received DBDs and updates neighbor target properties.
        """
        # بررسی وجود لیست هدرها و خالی نبودن آن
        headers = getattr(self.neighbor, 'received_lsa_headers', [])
        
        if headers and len(headers) > 0:
            target_lsa = headers[0] # برداشتن اولین LSA برای تولید پایدار LSR
            
            self.neighbor.target_req_ls_type = target_lsa.get('type', 1)
            self.neighbor.target_req_link_state_id = target_lsa.get('id', '0.0.0.0')
            self.neighbor.target_req_advertising_router = target_lsa.get('adv_router', '0.0.0.0')
            
            # برای دیباگ راحت‌تر در کنسول Boofuzz
            print(f"[+] LSA Params Updated for LSR -> Type: {self.neighbor.target_req_ls_type}, "
                f"ID: {self.neighbor.target_req_link_state_id}, "
                f"Adv Router: {self.neighbor.target_req_advertising_router}")
        else:
            # مقادیر پیش‌فرض امن در صورتی که هنوز LSA دریافت نشده باشد
            self.neighbor.target_req_ls_type = getattr(self.neighbor, 'target_req_ls_type', 1)
            self.neighbor.target_req_link_state_id = getattr(self.neighbor, 'target_req_link_state_id', '0.0.0.0')
            self.neighbor.target_req_advertising_router = getattr(self.neighbor, 'target_req_advertising_router', '0.0.0.0')


    def reach_state_init(self) -> bool:
        """
        Transition: DOWN -> INIT
        Pre-sniff target Hello, extract parameters, then send synchronized Hello
        """
        def attempt_init():
            print("[*] Waiting for target Hello packet to extract parameters...")
            
            # Step 1: Sniff target's Hello packet
            response = self.handler.wait_for_packet(
                packet_type=1, 
                timeout=self.retry_timeout * 2
            )
            
            if not response:
                print("[-] No Hello received from target")
                return False
            
            # Step 2: Extract all dynamic parameters from target's Hello
            self.neighbor_params = extract_neighbor_params(
                hello_packet=response,
                our_router_id=self.neighbor.our_router_id,
                our_ip=self.neighbor.our_ip
            )
            
            if not self.neighbor_params:
                print("[-] Failed to extract neighbor parameters")
                return False
            
            print(f"[+] Extracted parameters from target:")
            print(f"    - Area ID: {self.neighbor_params['area_id']}")
            print(f"    - Network Mask: {self.neighbor_params['network_mask']}")
            print(f"    - Hello Interval: {self.neighbor_params['hello_interval']}")
            print(f"    - Dead Interval: {self.neighbor_params['dead_interval']}")
            print(f"    - Auth Type: {self.neighbor_params['auth_type']}")
            print(f"    - Peer Router ID: {self.neighbor_params['peer_router_id']}")
            
            # Step 3: Parse Hello to extract target state
            hello_data = parse_hello(response)
            if not hello_data:
                print("[-] Failed to parse Hello packet")
                return False
            
            print(f"[+] Target router state:")
            print(f"    - Router ID: {hello_data['router_id']}")
            print(f"    - Priority: {hello_data['priority']}")
            print(f"    - DR: {hello_data['dr']}")
            print(f"    - BDR: {hello_data['bdr']}")
            print(f"    - Neighbors: {hello_data['neighbors']}")
            
            # Step 4: Send synchronized Hello with extracted parameters
            hello_pkt = build_hello_packet(
                neighbor_params=self.neighbor_params,
                neighbors=[]
            )
            hello_pkt = wrap_in_ip(
                hello_pkt
            )
            self._send_packet(hello_pkt)
            print("[+] Sent synchronized Hello packet")
            
            # Step 5: Update neighbor state
            self.neighbor.target_router_id = hello_data['router_id']
            self.neighbor.area_id=self.neighbor_params['area_id']
            self.neighbor.network_mask=self.neighbor_params['network_mask']
            self.neighbor.hello_interval=self.neighbor_params['hello_interval']
            self.neighbor.dead_interval=self.neighbor_params['dead_interval']
            self.neighbor.target_priority = hello_data['priority']
            self.neighbor.target_dr = hello_data['dr']
            self.neighbor.target_bdr = hello_data['bdr']
            self.neighbor.last_hello_received = time.time()
            self.neighbor.set_state(OSPFState.INIT)
            
            return True
        
        return self._retry_wrapper(attempt_init, "INIT state")

    def reach_state_2way(self) -> bool:
        """
        Transition: INIT -> 2-WAY
        Send Hello with target in neighbor list, wait for bidirectional visibility
        """
        def attempt_2way():
            # Ensure we're at least in INIT
            if self.neighbor.state == OSPFState.DOWN:
                if not self.reach_state_init():
                    return False
            
            if not self.neighbor_params:
                print("[-] Neighbor parameters not extracted")
                return False
            
            
            # Wait for Hello from target
            response = self.handler.wait_for_packet(
                packet_type=1,
                timeout=self.retry_timeout
            )
            
            if not response:
                print("[-] No Hello response received")
                return False
            
            # Parse Hello
            hello_data = parse_hello(response)
            if not hello_data:
                print("[-] Failed to parse Hello response")
                return False
            
            # Check bidirectional visibility
            neighbors = hello_data.get('neighbors', [])
            if self.neighbor.our_router_id not in neighbors:
                print(f"[-] Our router ID {self.neighbor.our_router_id} not in target's neighbor list")
                print(f"    Target's neighbors: {neighbors}")
                return False
            
            # Send Hello with target router ID in neighbor list
            hello_pkt = build_hello_packet(
                neighbor_params=self.neighbor_params,
                neighbors=[self.neighbor.target_router_id]
            )
            hello_pkt = wrap_in_ip(
                hello_pkt
            )
            self._send_packet(hello_pkt)
            print(f"[+] Sent Hello with target {self.neighbor.target_router_id} in neighbor list")
            
            
            print(f"[+] Bidirectional visibility confirmed")
            self.neighbor.last_hello_received = time.time()
            self.neighbor.set_state(OSPFState.TWO_WAY)
            
            return True
        
        return self._retry_wrapper(attempt_2way, "2-WAY state")

    def reach_state_exstart(self) -> bool:
        """
        Transition: 2-WAY -> EXSTART
        Negotiate master/slave relationship via initial DBD exchange
        """
        def attempt_exstart():
            # Ensure we're at least in 2-WAY
            if self.neighbor.state != OSPFState.TWO_WAY:
                if not self.reach_state_2way():
                    return False
            
            if not self.neighbor_params:
                print("[-] Neighbor parameters not extracted")
                return False
            
            # Choose initial DD sequence number
            our_seq = int(time.time()) & 0xFFFFFFFF
            self.neighbor.dd_sequence = our_seq
            
            print(f"[*] Initiating EXSTART with sequence {our_seq}")
            
            # Send initial DBD with I-M-MS bits set
            dbd_pkt = build_dbd_packet(
                neighbor_params=self.neighbor_params,
                dd_sequence=our_seq,
                flags=0x07,  # I=1, M=1, MS=1
                lsa_headers=[]
            )
            dbd_pkt = wrap_in_ip(
                dbd_pkt
            )
            self._send_packet(dbd_pkt)
            
            # Wait for DBD proposal from target router
            response = self.handler.wait_for_packet(
                packet_type=2,
                timeout=self.retry_timeout
            )
            
            if not response:
                print("[-] No DBD response received")
                return False
            
            # Parse DBD
            dbd_data = parse_dbd(response)
            if not dbd_data:
                print("[-] Failed to parse DBD response")
                return False
            self.neighbor.mtu=dbd_data['mtu']
            
            # Determine master/slave by comparing Router IDs
            our_rid = ipaddress.IPv4Address(self.neighbor.our_router_id)
            target_rid = ipaddress.IPv4Address(self.neighbor.target_router_id)

            if our_rid > target_rid:
                self.neighbor.master = True
                print(f"[+] We are MASTER (our RID {our_rid} > target RID {target_rid})")
                
                # As Master, wait for the Slave to ACK our 0x07 packet by sending a new packet
                print("[*] Master mode: Waiting for Slave's ACK packet...")
                slave_ack = self.handler.wait_for_packet(packet_type=2, timeout=self.retry_timeout)
                if not slave_ack:
                    print("[-] Slave failed to acknowledge Master's sequence")
                    return False
                
                slave_dbd = parse_dbd(slave_ack)
                # Check if the Slave has acknowledged its role (MS=0, I=0) and matched our sequence number
                if not slave_dbd or slave_dbd['master']==1 or slave_dbd['init']==1 or slave_dbd['seq'] != our_seq:
                    print("[-] Invalid DBD ACK received from Slave")
                    return False
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            
                self.neighbor.target_dd_sequence = slave_dbd['seq']
                self.neighbor.received_lsa_headers = slave_dbd['lsa_headers']    
                print(slave_dbd['lsa_headers'])  
                print(f"[+] Slave ACK received. Received {len(slave_dbd['lsa_headers'])} LSA headers.")

            else:
                self.neighbor.master = False
                print(f"[+] We are SLAVE (our RID {our_rid} < target RID {target_rid})")
                
                # As Slave, set our sequence number to match the Master's sequence number
                master_seq = dbd_data['seq']
                self.neighbor.dd_sequence = master_seq
                self.neighbor.target_dd_sequence = master_seq
                
                # Immediately send the ACK packet to notify the Master of our role acceptance
                print("[*] Slave mode: Sending ACK packet to Master...")
                ack_pkt = build_dbd_packet(
                    neighbor_params=self.neighbor_params,
                    dd_sequence=master_seq,
                    flags=0x02,  # I=0, M=1, MS=0 (Slave role confirmation)
                )
                ack_pkt = wrap_in_ip(ack_pkt)
                self._send_packet(ack_pkt) # Call your packet sending method here

            # Once both sides accept their roles, transition the neighbor state to EXSTART
            self.neighbor.set_state(OSPFState.EXSTART) 
            print("[+] EXSTART Negotiation completed successfully.")
            return True
                
        return self._retry_wrapper(attempt_exstart, "EXSTART state")


    def reach_state_exchange(self) -> bool:
        """
        Transition: EXSTART -> EXCHANGE
        Properly handles Master/Slave DBD exchange logic.
        """
        def attempt_exchange():
            if self.neighbor.state != OSPFState.EXSTART:
                if not self.reach_state_exstart():
                    return False
            
            self.neighbor.set_state(OSPFState.EXCHANGE)
            print(f"[*] Entering EXCHANGE state as {'MASTER' if self.neighbor.master else 'SLAVE'}")

            # Define the LSA we want to advertise (only once)
            my_lsa = OSPF_LSA_Hdr(
                age=1, options=0x02, type=1,
                id=ATTACKER_ROUTER_ID, adrouter=ATTACKER_ROUTER_ID,
                seq=0x80000001, chksum=0x0000, len=36
            )

            if not self.neighbor_params:
                print("[-] Neighbor parameters not extracted")
                return False
            
            target_has_more = True
            first_packet_sent = False

            while target_has_more:
                if self.neighbor.master:
                    # --- MASTER LOGIC ---
                    # Increment sequence for each new exchange (except the very first one in ExStart)    
                    self.neighbor.dd_sequence += 1
                    
                    # Send DBD
                    flags = 0x01  # MS=1, M=we_have_more
                    dbd_pkt = build_dbd_packet(
                        neighbor_params=self.neighbor_params,
                        dd_sequence=self.neighbor.dd_sequence,
                        flags=flags,
                        lsa_headers=[my_lsa] if not first_packet_sent else []
                    )
                    self._send_packet(wrap_in_ip(dbd_pkt))
                    first_packet_sent = True

                    # Wait for Slave's Echo (ACK)
                    response = self.handler.wait_for_packet(packet_type=2, timeout=self.retry_timeout)
                    if not response:
                        print("[-] Master: No DBD response from Slave")
                        return False
                    
                    dbd_data = parse_dbd(response)
                    # Master check: Slave must echo the SAME sequence number
                    if dbd_data['seq'] != self.neighbor.dd_sequence:
                        print(f"[-] Master: Sequence mismatch! Sent {self.neighbor.dd_sequence}, Got {dbd_data['seq']}")
                        return False
                    if dbd_data['lsa_headers']:
                        self.neighbor.received_lsa_headers.extend(dbd_data['lsa_headers'])
                        
                    
                    target_has_more = dbd_data['more']

                else:
                    # --- SLAVE LOGIC ---
                    # 1. Wait for Master's DBD
                    response = self.handler.wait_for_packet(packet_type=2, timeout=self.retry_timeout)
                    if not response:
                        print("[-] Slave: No DBD received from Master")
                        return False
                    
                    dbd_data = parse_dbd(response)
                    # Slave MUST use the sequence number from Master
                    self.neighbor.dd_sequence = dbd_data['seq']
                    target_has_more = dbd_data['more']

                    # 2. Process received LSA headers
                    if dbd_data['lsa_headers']:
                        self.neighbor.received_lsa_headers.extend(dbd_data['lsa_headers'])

                    # 3. Send DBD as ACK (Echo the sequence)
                    flags = 0 # MS=0, M=we_have_more
                    dbd_pkt = build_dbd_packet(
                        neighbor_params=self.neighbor_params,
                        dd_sequence=self.neighbor.dd_sequence,
                        flags=flags,
                        lsa_headers=[my_lsa] if not first_packet_sent else []
                    )
                    self._send_packet(wrap_in_ip(dbd_pkt))
                    first_packet_sent = True

                # Break if both sides have no more data
                if not target_has_more:
                    print("[+] Exchange complete: Both sides have M=0")
                    break

            # Transition to Loading or Full
            if len(self.neighbor.received_lsa_headers) > 0:
                self.neighbor.set_state(OSPFState.LOADING)
                print(f"[*] Transition to LOADING. {len(self.neighbor.received_lsa_headers)} LSAs to request.")
            else:
                self.neighbor.set_state(OSPFState.FULL)
                print("[*] Transition to FULL (Database synchronized)")
            return True

        return self._retry_wrapper(attempt_exchange, "EXCHANGE state")



    def reach_state_loading(self) -> bool:
        """
        Transition: EXCHANGE -> LOADING
        Request and receive full LSAs via LSR/LSU exchange
        """
        def attempt_loading():
            # Ensure we're at least in EXCHANGE
            if self.neighbor.state < OSPFState.EXCHANGE:
                if not self.reach_state_exchange():
                    return False
            
            # Skip if already FULL
            if self.neighbor.state == OSPFState.FULL:
                return True
            
            if not self.neighbor_params:
                print("[-] Neighbor parameters not extracted")
                return False
            
            # Skip if no LSAs to request
            if len(self.neighbor.received_lsa_headers) == 0:
                print("[*] No LSAs to request, transitioning to FULL")
                self.neighbor.set_state(OSPFState.FULL)
                return True
            
            self.neighbor.set_state(OSPFState.LOADING)
            print(f"[*] Entering LOADING state, requesting {len(self.neighbor.received_lsa_headers)} LSAs")
            
            # Send LSR for all received LSA headers
            lsr_pkt = build_lsr_packet(
                neighbor_params=self.neighbor_params,
                ls_requests=self.neighbor.received_lsa_headers
            )
            lsr_pkt = wrap_in_ip(
                lsr_pkt
            )
            self._send_packet(lsr_pkt)
            print(f"[+] Sent LSR for {len(self.neighbor.received_lsa_headers)} LSAs")
            
            # Wait for LSU response
            response = self.handler.wait_for_packet(
                packet_type=4,
                timeout=self.retry_timeout * 2
            )
            
            if not response:
                print("[-] No LSU response received")
                return False
            
            # Parse LSU
            lsu_data = parse_lsu(response)
            if not lsu_data:
                print("[-] Failed to parse LSU response")
                return False
            
            print(f"[+] Received {lsu_data['lsa_count']} LSAs in LSU")
            
            # Send LSAck
            lsack_pkt = build_lsack_packet(
                neighbor_params=self.neighbor_params,
                lsa_headers=self.neighbor.received_lsa_headers
            )
            lsack_pkt = wrap_in_ip(
                lsack_pkt
            )
            self._send_packet(lsack_pkt)
            print(f"[+] Sent LSAck for {len(self.neighbor.received_lsa_headers)} LSAs")
            
            return True
        
        return self._retry_wrapper(attempt_loading, "LOADING state")


    def reach_state_full(self) -> bool:
        """
        Transition: LOADING -> FULL (or EXCHANGE -> FULL if no LSAs)
        Final adjacency state with active heartbeat
        """
        def attempt_full():
            # Skip if already FULL
            if self.neighbor.state == OSPFState.FULL:
                print("[*] Already in FULL state")
                return True
            
            # Ensure we're at least in EXCHANGE
            if self.neighbor.state < OSPFState.EXCHANGE:
                if not self.reach_state_exchange():
                    return False
            
            # If we have LSAs and not yet FULL, complete LOADING
            if len(self.neighbor.received_lsa_headers) > 0 and self.neighbor.state != OSPFState.FULL:
                if not self.reach_state_loading():
                    return False
            
            # Transition to FULL
            self.neighbor.set_state(OSPFState.FULL)
            
            # Start heartbeat to maintain adjacency
            self.neighbor.start_heartbeat()
            
            print("\n" + "="*60)
            print("[+] OSPF ADJACENCY ESTABLISHED - FULL STATE")
            print("="*60)
            print(f"Neighbor Router ID:    {self.neighbor.target_router_id}")
            print(f"Neighbor IP:           {self.neighbor.target_ip}")
            print(f"Our Router ID:         {self.neighbor.our_router_id}")
            print(f"Master/Slave Role:     {'MASTER' if self.neighbor.master else 'SLAVE'}")
            print(f"LSAs Received:         {len(self.neighbor.received_lsa_headers)}")
            print(f"Heartbeat Active:      Yes")
            print("="*60 + "\n")
            
            return True
        
        return self._retry_wrapper(attempt_full, "FULL state")

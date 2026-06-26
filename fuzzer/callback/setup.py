import struct
from scapy_builder.manager import *
from .utils import *
from boofuzz import REQUESTS
import socket
import struct





def setup_state_2_hello_2way(target, fuzz_data_logger, session, *args, **kwargs):
    fuzz_data_logger.log_info("Preamble: Advancing to State 2.")
    simulator = OSPFSimulator(func="reach_state_init")
    params = simulator.run()

    # Store on session — accessible in all subsequent callbacks
    
    original_send = target.send
    
    def patched_send(data):
        data = bytearray(data) 
        
        # Verify it's an OSPFv2 packet and has at least the minimum header size
        if len(data) >= 24 and data[0] == 2:
            
            # --- 1. Patch Header Fields via external function ---
            # We pass both the mutable 'data' array and the 'params' dictionary
            router_id, area_id = fix_header(data, params)

            #  OSPF HELLO BODY FIELDS (Offsets 24+)
            # Only patch if the packet is long enough to contain the Hello body
            # =========================================================================
            if len(data) >= 36:
                # 2. Patch Network Mask (Offset 24, 4 bytes)
                netmask = params.get('network_mask')
                if netmask:
                    data[24:28] = socket.inet_aton(netmask)

                # 3. Patch Hello Interval (Offset 28, 2 bytes)
                hello_int = params.get('hello_interval')
                if hello_int is not None:
                    struct.pack_into("!H", data, 28, int(hello_int))

                # 4. Patch Router Dead Interval (Offset 32, 4 bytes)
                dead_int = params.get('router_dead_interval')
                if dead_int is not None:
                    struct.pack_into("!I", data, 32, int(dead_int))

            # --- 5. Dynamically Update Length (Offset 2, 2 bytes) ---
            struct.pack_into("!H", data, 2, len(data))

            # --- 6. Clear and Recalculate OSPF Checksum (Offset 12, 2 bytes) ---
            data[12] = 0
            data[13] = 0
            checksum = ospf_checksum(bytes(data))
            data[12:14] = checksum
            
            fuzz_data_logger.log_info(
                f"Patched OSPF Header -> RID: {router_id}, Area: {area_id}, Checksum: {checksum.hex()}"
            )
            
        return original_send(bytes(data))
        
    target.send = patched_send


def setup_state_3_ExStart(target, fuzz_data_logger, session, *args, **kwargs):
    fuzz_data_logger.log_info("Preamble: Advancing to State 2.")
    simulator = OSPFSimulator(func="reach_state_2way")
    params = simulator.run()

    original_send = target.send
    
    def patched_send(data):
        data = bytearray(data) 
        
        # Verify it's an OSPFv2 packet and has at least the minimum header size
        if len(data) >= 24 and data[0] == 2:
            
            # --- 1. Patch Header Fields via external function ---
            # We pass both the mutable 'data' array and the 'params' dictionary
            router_id, area_id = fix_header(data, params)

            # --- 2. Dynamically Update Length (Offset 2, 2 bytes) ---
            struct.pack_into("!H", data, 2, len(data))

            # --- 3. Clear and Recalculate OSPF Checksum (Offset 12, 2 bytes) ---
            data[12] = 0
            data[13] = 0
            checksum = ospf_checksum(bytes(data))
            data[12:14] = checksum
            
            fuzz_data_logger.log_info(
                f"Patched OSPF Header -> RID: {router_id}, Area: {area_id}, Checksum: {checksum.hex()}"
            )
            
        return original_send(bytes(data))
        
    target.send = patched_send

    
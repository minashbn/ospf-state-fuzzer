import struct
from scapy_builder.manager import *
from .utils import *
from boofuzz import REQUESTS
import socket
import struct
from config import FUZZING_PHASE




def setup_state_2_hello_2way(target, fuzz_data_logger, session, *args, **kwargs):
    fuzz_data_logger.log_info("Preamble: Advancing to State init.")
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
    fuzz_data_logger.log_info("Preamble: Advancing to State 2way.")
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


def setup_state_4_Exchange(target, fuzz_data_logger, session, *args, **kwargs):
    fuzz_data_logger.log_info("Preamble: Advancing to State Exstart.")
    simulator = OSPFSimulator(func="reach_state_exstart")
    params = simulator.run()

    original_send = target.send
    
    def patched_send(data):
        data = bytearray(data) 
        
        # Verify it's an OSPFv2 packet and has at least the minimum header size
        if len(data) >= 24 and data[0] == 2:
            
            # --- 1. Patch Header Fields via external function ---
            router_id, area_id = fix_header(data, params)

            # --- 2. Patch Live DBD State Machine Parameters ---
            dbd_flags = params.get('dbd_flags', 0x02)
            dd_seq = params.get('dd_seq_number', 0x00000001)
            dd_mtu = params.get('mtu', 1500)
            struct.pack_into("!I", data, 28, dd_seq)     # Packs 4 bytes at offset 28-31

            if len(data) >= 32 and FUZZING_PHASE == "LSA_PARSING":
                struct.pack_into("!H", data, 24, dd_mtu)    # Packs 2 bytes at offset 24 & 25
                struct.pack_into("!B", data, 27, dbd_flags)  # Packs 1 byte at offset 27
            
            # --- 3. Calculate and Patch LSA Header Parameters ---
            if len(data) >= 52:  # 32 (offset) + 20 (minimum LSA header size)
                lsa_start_offset = 32
                
                # 1. Read the LSA Type dynamically from the packet (Offset 35)
                lsa_type = data[35] 
                
                # 2. Compute the physical length in our buffer
                lsa_total_length = len(data) - lsa_start_offset
                
                # 3. Adjust length based on OSPF specifications
                if lsa_type == 1 and lsa_total_length == 20:
                    lsa_total_length = 24
                elif lsa_type == 2 and lsa_total_length == 20:
                    lsa_total_length = 24

                # 4. FIX: Write LSA Length dynamically to the correct offset (50)
                struct.pack_into("!H", data, 50, lsa_total_length)
                
                # 5. FIX: Zero out the correct LSA checksum bytes (Offsets 48, 49)
                data[48] = 0
                data[49] = 0
                
                # 6. Extract the LSA block to compute Fletcher Checksum
                lsa_bytes = data[lsa_start_offset:]
                lsa_chk = fletcher16_ospf_lsa(lsa_bytes)
                
                # 7. FIX: Write the freshly calculated LSA Checksum to the correct offset (48)
                data[48:50] = lsa_chk
                
                fuzz_data_logger.log_info(f"Patched LSA -> Type: {lsa_type}, Set Length: {lsa_total_length}, Fletcher Chk: {lsa_chk.hex()}")
            # --- 4. Dynamically Update Global OSPF Packet Length (Offset 2, 2 bytes) ---
            struct.pack_into("!H", data, 2, len(data))

            # --- 5. Clear and Recalculate Global OSPF Checksum (Offset 12, 2 bytes) ---
            data[12] = 0
            data[13] = 0
            checksum = ospf_checksum(bytes(data))
            data[12:14] = checksum
            
            fuzz_data_logger.log_info(
                f"Patched OSPF Header -> RID: {router_id}, Area: {area_id}, Checksum: {checksum.hex()}"
            )
            
        return original_send(bytes(data))
    target.send = patched_send


def setup_state_5_Loading_lsr(target, fuzz_data_logger, session, *args, **kwargs):
    fuzz_data_logger.log_info("Preamble: Advancing to State Exstart.")
    simulator = OSPFSimulator(func="reach_state_exchange")
    params = simulator.run()


    original_send = target.send

    def patched_send(data):
        data = bytearray(data) 
        
        # Verify it's an OSPFv2 packet and has at least the minimum header size
        if len(data) >= 24 and data[0] == 2:
            
            # --- 1. Patch Header Fields via external function ---
            router_id, area_id = fix_header(data, params)

            # --- 2. Inject Valid LSR Block 1 (If Packet Type is 3 / LSR) ---
            # An LSR packet must be at least 36 bytes (24-byte header + 12-byte block)
            if data[1] == 3 and len(data) >= 36:
                try:
                    # Extract values from the simulator params dictionary
                    ls_type = int(params.get('req_ls_type', 1))
                    ls_id_str = params.get('req_link_state_id', '0.0.0.0')
                    adv_router_str = params.get('req_advertising_router', '0.0.0.1')
                    
                    # Pack values into network-byte-order (Big Endian) bytes
                    ls_type_bytes = struct.pack('>I', ls_type)
                    ls_id_bytes = socket.inet_aton(ls_id_str)
                    adv_router_bytes = socket.inet_aton(adv_router_str)
                    
                    # Overwrite the first 12 payload bytes directly following the 24-byte header
                    data[24:28] = ls_type_bytes      # LS Type (4 bytes)
                    data[28:32] = ls_id_bytes        # Link State ID (4 bytes)
                    data[32:36] = adv_router_bytes   # Advertising Router (4 bytes)
                    
                    fuzz_data_logger.log_info(
                        f"Injected Valid LSR Block 1 -> Type: {ls_type}, ID: {ls_id_str}, AdvRouter: {adv_router_str}"
                    )
                except Exception as e:
                    fuzz_data_logger.log_error(f"Failed to inject valid LSR fields: {str(e)}")

            # --- 4. Dynamically Update Global OSPF Packet Length (Offset 2, 2 bytes) ---
            struct.pack_into("!H", data, 2, len(data))

            # --- 5. Clear and Recalculate Global OSPF Checksum (Offset 12, 2 bytes) ---
            data[12] = 0
            data[13] = 0
            checksum = ospf_checksum(bytes(data))
            data[12:14] = checksum
            
            fuzz_data_logger.log_info(
                f"Patched OSPF Header -> RID: {router_id}, Area: {area_id}, Checksum: {checksum.hex()}"
            )
            
        return original_send(bytes(data))
    
    target.send = patched_send
import struct
import requests
import struct
import socket

def ospf_checksum(data):
    data = list(data)
    data[12] = 0
    data[13] = 0
    data = bytes(data)

    if len(data) % 2 != 0:
        data += b'\x00'

    res = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    res = (res >> 16) + (res & 0xFFFF)
    res += res >> 16
    res = (~res) & 0xFFFF
    return struct.pack("!H", res)

def fix_header(data, params):
    """
    Modifies the OSPF header bytearray in place using the provided params dictionary.
    """
    router_id = params.get('router_id')
    if router_id:
        # FIXED: Pass the variable router_id, not the string literal 'router_id'
        data[4:8] = socket.inet_aton(router_id)
            
    # --- 2. Patch Area ID (Offset 8, 4 bytes) ---
    area_id = params.get('area_id')
    if area_id is not None:
        if isinstance(area_id, str) and '.' in area_id:
            data[8:12] = socket.inet_aton(area_id)
        else:
            struct.pack_into("!I", data, 8, int(area_id))

    # --- 3. Patch Auth Type (Offset 14, 2 bytes) ---
    auth_type = params.get('auth_type')
    if auth_type is not None:
        struct.pack_into("!H", data, 14, int(auth_type))

    # --- 4. Patch Auth Data (Offset 16, 8 bytes) ---
    auth_data = params.get('auth_data')
    if auth_data is not None:
        if isinstance(auth_data, bytes):
            data[16:24] = auth_data.ljust(8, b'\x00')[:8]
        elif isinstance(auth_data, str):
            data[16:24] = auth_data.encode('utf-8').ljust(8, b'\x00')[:8]
        else:
            struct.pack_into("!Q", data, 16, int(auth_data))
            
    return router_id, area_id


def reset_target_state(target, fuzz_data_logger, session, *args, **kwargs):

    AGENT_URL = "http://192.168.56.101:26000/reset_ospf" 
    try:
        response = requests.get(AGENT_URL, timeout=2)
        if response.status_code == 200:
            fuzz_data_logger.log_info("OSPF State cleared successfully via Agent.")
        else:
            fuzz_data_logger.log_fail(f"Agent failed to clear OSPF: {response.text}")
    except requests.exceptions.RequestException as e:
        fuzz_data_logger.log_error(f"Failed to connect to Agent: {str(e)}")

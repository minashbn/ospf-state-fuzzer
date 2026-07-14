import struct
import requests
import struct
import socket
from config import ATTACKER_ROUTER_ID

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
    router_id = ATTACKER_ROUTER_ID
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


def fletcher16_ospf_lsa(data: bytearray):
    """
    Calculates the Fletcher-16 checksum for an OSPF LSA Header 
    according to RFC 2328 / RFC 905.
    The checksum field is at bytes 14 and 15 of the LSA header.
    """
    length = len(data)
    if length < 20:
        return b"\x00\x00"

    # Fletcher-16 algorithm variables
    c0 = 0
    c1 = 0
    
    # We must calculate the checksum as if the checksum bytes (offsets 14 and 15) are 0
    for i in range(length):
        if i == 14 or i == 15:
            val = 0
        else:
            val = data[i]
            
        c0 = (c0 + val) % 255
        c1 = (c1 + c0) % 255

    # Formula to derive the check bytes to be placed in the packet
    x = ((length - 14) * c0 - c1) % 255
    y = ((length - 13) * -c0 + c1) % 255

    if x == 0: x = 255
    if y == 0: y = 255

    return bytes([x, y])

def reset_target_state(target, fuzz_data_logger, session, *args, **kwargs):
    pass
    raise BaseException("stop it")

    # AGENT_URL = "http://192.168.56.101:26000/reset_ospf" 
    # try:
    #     response = requests.get(AGENT_URL, timeout=2)
    #     if response.status_code == 200:
    #         fuzz_data_logger.log_info("OSPF State cleared successfully via Agent.")
    #     else:
    #         fuzz_data_logger.log_fail(f"Agent failed to clear OSPF: {response.text}")
    # except requests.exceptions.RequestException as e:
    #     fuzz_data_logger.log_error(f"Failed to connect to Agent: {str(e)}")

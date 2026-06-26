import struct
import requests

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

def update_ospf_packet(target, fuzz_data_logger, session, *args, **kwargs):
    original_send = target.send
    
    def patched_send(data):
        data = bytearray(data) 
        if len(data) >= 24 and data[0] == 2:
            struct.pack_into("!H", data, 2, len(data))
            data[12] = 0
            data[13] = 0
            checksum = ospf_checksum(bytes(data))
            data[12:14] = checksum
            fuzz_data_logger.log_info(f"OSPF checksum fixed: {checksum.hex()}")
        return original_send(bytes(data))
    target.send = patched_send


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

from boofuzz import *

OSPF_TYPE_MAP = {
    "hello": 0x01,
    "dbd":   0x02,
    "lsr":   0x03,
    "lsu":   0x04,
    "lsack": 0x05,
}

OSPF_MIN_LENGTH = {
    "hello": 44,   # 24 header + 20 hello body
    "dbd":   32,   # 24 header + 8 dbd body
    "lsr":   36,   # 24 header + 12 lsr body
    "lsu":   28,   # 24 header + 4 (num LSAs) + variable
    "lsack": 24,   # 24 header + variable
}

def define_ospf_header(packet_type: str):
    """
    packet_type: "hello" | "dbd" | "lsr" | "lsu" | "lsack"
    """
    if packet_type not in OSPF_TYPE_MAP:
        raise ValueError(f"Invalid OSPF packet type: '{packet_type}'. "
                         f"Valid types: {list(OSPF_TYPE_MAP.keys())}")

    type_value  = OSPF_TYPE_MAP[packet_type]
    base_length = OSPF_MIN_LENGTH[packet_type]

    with s_block(f"ospf_header"):
        s_byte(0x02, name=f"ver", fuzzable=False)
        s_byte(type_value, name=f"type", fuzzable=False)
        s_word(base_length, name="len", fuzzable=False, endian='>')
        s_dword(0x03030303, name=f"r_id", fuzzable=False, endian='>')
        s_dword(0x00000000, name=f"area", fuzzable=False, endian='>')
        s_word(0x0000, name=f"ospf_checksum", fuzzable=False)
        s_word(0x0000, name=f"auth_type", fuzzable=False, endian='>')
        s_qword(0, name=f"auth_data", fuzzable=False, endian='>')




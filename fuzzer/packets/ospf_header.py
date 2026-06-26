from boofuzz import *
import socket
import struct

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
    type_value  = OSPF_TYPE_MAP[packet_type]
    base_length = OSPF_MIN_LENGTH[packet_type]

    with s_block("ospf_header"):
        s_byte(0x02,        name="ver",           fuzzable=False)
        s_byte(type_value,  name="type",          fuzzable=False)
        s_word(base_length, name="len",           fuzzable=False, endian='>')
        s_dword(0x00000000, name="r_id",          fuzzable=False, endian='>')  # patched at send time
        s_dword(0x00000000, name="area",          fuzzable=False, endian='>')  # patched at send time
        s_word(0x0000,      name="ospf_checksum", fuzzable=False)
        s_word(0x0000,      name="auth_type",     fuzzable=False, endian='>')  # patched at send time
        s_qword(0,          name="auth_data",     fuzzable=False, endian='>')  # patched at send time
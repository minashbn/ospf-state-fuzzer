from boofuzz import *
import socket
from config import *
from .ospf_header import define_ospf_header,_ip_to_dword

#fuzzable=false : go to next state faster
def define_hello_init():
    s_initialize("hello_init")
    define_ospf_header("hello") 
        
    with s_block("hello_body"):
        s_dword(0xFFFFFF00, name="netmask", fuzzable=False, endian='>')
        s_word(10, name="hello_interval", fuzzable=False, endian='>')
        s_byte(0x02, name="options", fuzzable=False)
        s_byte(1, name="priority", fuzzable=False)
        s_dword(40, name="dead_interval", fuzzable=False, endian='>')
        s_dword(0x00000000, name="dr", fuzzable=False, endian='>')
        s_dword(0x00000000, name="bdr", fuzzable=True, endian='>')

def define_hello_2way(params: dict = None): # type: ignore
    s_initialize("hello_2way")
    define_ospf_header("hello") 
    with s_block("way_hello_body"):
        # extract the valid value for fuzzable=false whitin scapy 
        s_dword(0xFFFFFF00, name="way_netmask", fuzzable=False, endian='>')
        s_word(10, name="way_hello_interval", fuzzable=False, endian='>')
        s_byte(0x02, name="way_options", fuzzable=True) 
        s_byte(1, name="way_priority", fuzzable=True)
        s_dword(40, name="way_dead_interval", fuzzable=False, endian='>')
        s_dword(0, name="way_dr", fuzzable=True, endian='>')
        s_dword(0, name="way_bdr", fuzzable=True, endian='>')
        
        s_bytes(socket.inet_aton(TARGET_ROUTER_ID), name="way_neighbor_router_id", size=4, fuzzable=False)



def define_dbd_ExStart():
    s_initialize("ospf_ExStart")
    define_ospf_header("dbd")           # type=0x02, len=32 
    with s_block("dbd_body"):
        s_word(1500, name="mtu",         fuzzable=True, endian='>')
        s_byte(0x02, name="options",     fuzzable=True)
        s_byte(0x07, name="flags",       fuzzable=True)
        s_dword(0x1,   name="seq_number",  fuzzable=True, endian='>')




# def define_lsr_packet():
#     s_initialize("ospf_lsr")
#     define_ospf_header("lsr")           # type=0x03, len=36 set می‌شود
#     with s_block("lsr_body"):
#         s_dword(0x01, name="ls_type",    fuzzable=True, endian='>')
#         s_dword(0x00000000, name="ls_id",    fuzzable=True, endian='>')
#         s_dword(0x01010101, name="adv_router", fuzzable=True, endian='>')

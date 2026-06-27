from boofuzz import *
import socket
from config import *
from .ospf_header import define_ospf_header

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


# ==============================================================================
# CONFIGURATION: Choose your phase
# "DBD_FRAMEWORK" -> Fuzzes MTU/Options, keeps LSA static (Phase 1)
# "LSA_PARSING"   -> Keeps DBD stable, fuzzes the deep LSA headers (Phase 2)
# ==============================================================================


def define_dbd_ExChange():
    s_initialize("dbd_Exchange")
    
    # Custom OSPF header hook (assumed defined elsewhere in your framework)
    define_ospf_header("dbd")           

    # Determine fuzzable flags based on the chosen phase
    fuzz_dbd = (FUZZING_PHASE == "DBD_FRAMEWORK")
    fuzz_lsa = (FUZZING_PHASE == "LSA_PARSING")

    # --------------------------------------------------------------------------
    # 1. DBD Body Section (Controls OSPF State / Session Stability)
    # --------------------------------------------------------------------------
    with s_block("dbd_body"):
        s_word(1500, name="interface_mtu", fuzzable=fuzz_dbd, endian='>')
        s_byte(0x02, name="options",       fuzzable=fuzz_dbd)
        
        # Critical state flags - ALWAYS static to maintain the Exchange state
        s_byte(0x02, name="dbd_flags",     fuzzable=False) 
        s_dword(0x00000001, name="dd_seq_number", fuzzable=False, endian='>')

    # --------------------------------------------------------------------------
    # 2. LSA Header Section (Deep Parser Testing)
    # --------------------------------------------------------------------------
    with s_block("lsa_header"):
        # LS Age: Time elapsed since LSA was originated (2 bytes)
        s_word(1, name="lsa_age", fuzzable=fuzz_lsa, endian='>')
        
        # Options: LSA capabilities (1 byte)
        s_byte(0x02, name="lsa_options", fuzzable=fuzz_lsa)
        
        # LS Type: e.g., Router-LSA (0x01) or Network-LSA (0x02) (1 byte)
        s_byte(1, name="lsa_type", fuzzable=fuzz_lsa)
        
        # Link State ID (4 bytes)
        s_dword(0x0a000001, name="link_state_id", fuzzable=fuzz_lsa, endian='>')
        
        # Advertising Router ID (4 bytes)
        s_dword(0x0a000001, name="advertising_router", fuzzable=fuzz_lsa, endian='>')
        
        # LS Sequence Number (4 bytes)
        s_dword(0x80000001, name="lsa_seq_number", fuzzable=fuzz_lsa, endian='>')
        
        # LS Checksum (2 bytes)
        # Note: Set to False if the router instantly drops packets with bad checksums.
        s_word(0x0000, name="lsa_checksum", fuzzable=False, endian='>')
        
        # Length: Total length of LSA (2 bytes)
        # Note: If fuzzing this field breaks the packet structure too early, 
        # change fuzzable to False to ensure mutations reach fields above.
        s_word(20, name="lsa_length", fuzzable=False, endian='>')

# def define_lsr_packet():
#     s_initialize("ospf_lsr")
#     define_ospf_header("lsr")           # type=0x03, len=36 set می‌شود
#     with s_block("lsr_body"):
#         s_dword(0x01, name="ls_type",    fuzzable=True, endian='>')
#         s_dword(0x00000000, name="ls_id",    fuzzable=True, endian='>')
#         s_dword(0x01010101, name="adv_router", fuzzable=True, endian='>')

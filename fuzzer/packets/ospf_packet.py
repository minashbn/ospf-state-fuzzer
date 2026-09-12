from boofuzz import *
import socket
from config import *
from .ospf_header import define_ospf_header

#fuzzable=false : go to next state faster
def define_hello_init():
    s_initialize("hello_init")
    define_ospf_header("hello") 
        
    with s_block("hello_body"):
        s_dword(0xFFFFFF00, name="netmask", fuzzable=True, endian='>')
        s_word(10, name="hello_interval", fuzzable=True, endian='>')
        s_byte(0x02, name="options", fuzzable=True)
        s_byte(1, name="priority", fuzzable=False)
        s_dword(40, name="dead_interval", fuzzable=False, endian='>')
        s_dword(0x00000000, name="dr", fuzzable=False, endian='>')
        s_dword(0x00000000, name="bdr", fuzzable=True, endian='>')

def define_hello_2way(params: dict = None): # type: ignore
    s_initialize("hello_2way")
    define_ospf_header("hello") 
    with s_block("way_hello_body"):
        # extract the valid value for fuzzable=false whitin scapy 
        s_dword(0xFFFFFF00, name="netmask", fuzzable=False, endian='>')
        s_word(10, name="hello_interval", fuzzable=True, endian='>')
        s_byte(0x02, name="options", fuzzable=True) 
        s_byte(1, name="priority", fuzzable=False)
        s_dword(40, name="dead_interval", fuzzable=True, endian='>')
        s_dword(0, name="dr", fuzzable=True, endian='>')
        s_dword(0, name="bdr", fuzzable=True, endian='>')
        
        s_bytes(socket.inet_aton(TARGET_ROUTER_ID), name="neighbor_router_id", size=4, fuzzable=False)



def define_dbd_ExStart():
    s_initialize("ospf_ExStart")
    define_ospf_header("dbd")           # type=0x02, len=32 
    with s_block("dbd_body"):
        s_word(1500, name="mtu",         fuzzable=True, endian='>')
        s_byte(0x02, name="options",     fuzzable=True)
        s_byte(0x07, name="flags",       fuzzable=True)
        s_dword(0x1,   name="seq_number",  fuzzable=True, endian='>')


def define_dbd_ExChange():
    s_initialize("dbd_Exchange")
    
    # Custom OSPF header hook (assumed defined elsewhere in your framework)
    define_ospf_header("dbd")           

    # --------------------------------------------------------------------------
    # 1. DBD Body Section (Controls OSPF State / Session Stability)
    # --------------------------------------------------------------------------
    with s_block("dbd_body"):
        s_word(1500, name="mtu", fuzzable=True, endian='>')
        s_byte(0x02, name="options",       fuzzable=True)
        
        # Critical state flags - ALWAYS static to maintain the Exchange state
        s_byte(0x02, name="flags",     fuzzable=True) 
        s_dword(0x00000001, name="seq", fuzzable=False, endian='>')

    # --------------------------------------------------------------------------
    # 2. LSA Header Section (Deep Parser Testing)
    # --------------------------------------------------------------------------
    with s_block("lsa_header"):
        # LS Age: Time elapsed since LSA was originated (2 bytes)
        s_word(1, name="lsa_age", fuzzable=True, endian='>')
        
        # Options: LSA capabilities (1 byte)
        s_byte(0x02, name="lsa_options", fuzzable=True)
        
        # LS Type: e.g., Router-LSA (0x01) or Network-LSA (0x02) (1 byte)
        s_byte(7, name="lsa_type", fuzzable=True)
        
        # Link State ID (4 bytes)
        s_dword(0x0a000001, name="link_state_id", fuzzable=True, endian='>')
        
        # Advertising Router ID (4 bytes)
        s_dword(0x0a000001, name="advertising_router", fuzzable=True, endian='>')
        
        # LS Sequence Number (4 bytes)
        s_dword(0x80000001, name="lsa_seq_number", fuzzable=True, endian='>')
        
        # LS Checksum (2 bytes)
        # Note: Set to False if the router instantly drops packets with bad checksums.
        s_word(0x0000, name="lsa_checksum", fuzzable=False, endian='>')
        
        # Length: Total length of LSA (2 bytes)
        # Note: If fuzzing this field breaks the packet structure too early, 
        # change fuzzable to False to ensure mutations reach fields above.
        s_word(20, name="lsa_length", fuzzable=False, endian='>')


def define_lsr():
    # After s_initialize, print the request to verify both blocks render
    s_initialize("ospf_lsr")
    define_ospf_header("lsr")

    with s_block("lsr_all_requests"):
        
        # (Request 1)
        s_dword(1, name="type_1", fuzzable=False, endian='>')
        s_dword(0x0a000002, name="id_1", fuzzable=False, endian='>')
        s_dword(0x0a000002, name="adv_1", fuzzable=False, endian='>')

        #  (Request 2 - Fuzzable)
        s_dword(1, name="type_2", fuzzable=True, endian='>')
        s_dword(0x0a000003, name="id_2", fuzzable=True, endian='>')
        s_dword(0x0a000003, name="adv_2", fuzzable=True, endian='>')
# Verify rendered size before sending

def define_lsu():
    s_initialize("ospf_lsu")
    
    # هوک هدر اختصاصی OSPF (مانند نمونه قبلی شما)
    define_ospf_header("lsu")           

    # تعیین فیلدهای قابل فاز بر اساس فاز فازینگ انتخابی


    # --------------------------------------------------------------------------
    # 1. LSU Body Header (مشخص کردن تعداد LSAهای موجود در پکت)
    # --------------------------------------------------------------------------
    with s_block("lsu_envelope"):
        # Number of LSAs (4 bytes): تعداد LSAهایی که در ادامه می‌آیند
        s_dword(1, name="num_of_lsas", fuzzable=True, endian='>')

    # --------------------------------------------------------------------------
    # 2. LSA Header Section (تست عمیق پارسر LSA)
    # --------------------------------------------------------------------------
    with s_block("lsa_header"):
        # LS Age (2 bytes): مدت زمان گذشته از تولید LSA
        s_word(1, name="lsa_age", fuzzable=True, endian='>')
        
        # Options (1 byte): قابلیت‌های LSA
        s_byte(0x02, name="lsa_options", fuzzable=True)
        
        # LS Type (1 byte): مثلاً Router-LSA (0x01) یا Network-LSA (0x02)
        s_byte(1, name="lsa_type", fuzzable=True)
        
        # Link State ID (4 bytes)
        s_dword(0x0a000001, name="link_state_id", fuzzable=True, endian='>')
        
        # Advertising Router ID (4 bytes)
        s_dword(0x0a000001, name="advertising_router", fuzzable=True, endian='>')
        
        # LS Sequence Number (4 bytes)
        s_dword(0x80000001, name="lsa_seq_number", fuzzable=True, endian='>')
        
        # LS Checksum (2 bytes)
        s_word(0x0000, name="lsa_checksum", fuzzable=False, endian='>')
        
        # Length (2 bytes): طول کل LSA شامل هدر و بدنه (در اینجا فرضاً 24 بایت)
        s_word(24, name="lsa_length", fuzzable=False, endian='>')

    # --------------------------------------------------------------------------
    # 3. LSA Body Section (Router-LSA Payload)
    # --------------------------------------------------------------------------
    # این بخش بسته به LS Type تغییر می‌کند. در اینجا نمونه Router-LSA آورده شده است.
    with s_block("router_lsa_body"):
        # Flags (1 byte): پرچم‌های V (Virtual Link)، E (ASBR) و B (ABR)
        s_byte(0x00, name="router_lsa_flags", fuzzable=True)
        
        # Must be 0 (1 byte)
        s_byte(0x00, name="router_lsa_zero", fuzzable=False)
        
        # Number of Links (2 bytes): تعداد لینک‌های معرفی شده در این LSA
        s_word(0, name="router_lsa_num_links", fuzzable=True, endian='>')
from .ospf_utils import *
from pcap_manager import PcapManager
# ----------------------------------------------
# Send Hello
# ----------------------------------------------
pcap_mgr = PcapManager()

def send_hello(neighbors=None):

    pkt = build_hello_packet(neighbors)

    sendp(pkt, iface=IFACE, verbose=False)
    pcap_mgr.write_packet(pkt)

    print("[+] Hello sent")


# ---------------------------
# Sniff Target Hello
# ---------------------------

def sniff_target_hello(timeout=11):

    def ospf_filter(pkt):

        if OSPF_Hdr not in pkt:
            return False

        if pkt[OSPF_Hdr].type != 1:
            return False

        if pkt[OSPF_Hdr].src != TARGET_ROUTER_ID:
            return False

        return True

    packets = sniff(
        iface=IFACE,
        timeout=timeout,
        lfilter=ospf_filter
    )

    if len(packets) == 0:
        return None

    return packets[-1]


def get_neighbors(pkt):

    if OSPF_Hello not in pkt:
        return []

    hello = pkt[OSPF_Hello]

    return hello.neighbors


def ip_to_int(ip_str):
    """Convert IP string to integer for Boofuzz injection."""
    return struct.unpack("!I", socket.inet_aton(ip_str))[0]


# ---------------------------
# Reach 2-Way State
# ---------------------------

def reach_2way_state():
    print("[**] Attempting to reach OSPF 2-Way state")
    known_neighbors = []
    while True:

        send_hello(known_neighbors)

        pkt = sniff_target_hello()

        if pkt is None:
            print("[-] No Hello received from target, retrying...")
            continue

        neighbors = get_neighbors(pkt)
        ospf_hdr = pkt[OSPF_Hdr]
        ospf_hello = pkt[OSPF_Hello]

        print("[*] Target neighbor list:", neighbors)

        # --- INIT CHECK ---
        if ATTACKER_ROUTER_ID not in neighbors:

            print("[*] Router in INIT state")

            continue
        
        # --- 2-WAY ---
        print("[+] Target Router should be in 2-Way state !")
        return True


# ---------------------------
# Reach ExStart State
# ---------------------------


def reach_ExStart_state():
    
    reach_2way_state()

    print("[*] Forcing bidirectional 2-Way")

    # Phase 2: send hello with neighbor
    send_hello([TARGET_ROUTER_ID])

    print("[+] Both routers should now be in 2-Way state")


# ---------------------------
# Sniff Target dbd
# ---------------------------


def sniff_dbd(timeout=10):

    def dbd_filter(pkt):

        if OSPF_Hdr not in pkt:
            return False

        if pkt[OSPF_Hdr].type != 2:
            return False

        if pkt[OSPF_Hdr].src != TARGET_ROUTER_ID:
            return False

        return True

    packets = sniff(
        iface=IFACE,
        timeout=timeout,
        lfilter=dbd_filter
    )

    if not packets:
        return None

    return packets[-1]


def extract_dbd_info(pkt):

    if OSPF_DBDesc not in pkt:
        print("[-] Not a DBDesc packet")
        return None

    dbd = pkt[OSPF_DBDesc]

    info = {}

    info["seq"] = dbd.ddseq
    info["mtu"] = dbd.mtu
    info["options"] = dbd.options
    info["flags"] = dbd.dbdescr

    return info


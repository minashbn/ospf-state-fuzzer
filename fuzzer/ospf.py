#!/usr/bin/env python3
import socket
import time
import sys
import requests
import subprocess 
import os
from datetime import datetime
from boofuzz import *
from boofuzz.connections import ITargetConnection
from .packets.ospf_packet import *
from config import *
from .connection.ospf_connection import *
from .callback.utils import *
from .callback.setup import *
import struct
from .monitor.ospf_monitor import *


STATE_HANDLERS = {
    1: (define_hello_init, "hello_init", None,0),
    2: (define_hello_2way, "hello_2way", setup_state_2_hello_2way,10.1),
    3: (define_dbd_ExStart, "ospf_ExStart",setup_state_3_ExStart,10.1)
    # 4: (define_dd_exchange, "dd_exchange", setup_state_4_exchange),
}






def fuzzing(state):

    handler = STATE_HANDLERS.get(state)
    interface = "enp0s8"

    
    if not handler:
        print(f"[!!!] CRITICAL: State {state} is not supported or defined in STATE_HANDLERS.")
        sys.exit(1)

    define_grammar_func, node_name, preamble_callback,timeout = handler
    # 2. Setup Connection to Docker Container (For Fuzzing)
    connection = SimpleRawOSPF(
    interface="enp0s8", 
    target_ip="192.168.56.201", 
    response_timeout=timeout,  # 
    agent_url="http://{TARGET_AGENT_IP}:{AGENT_PORT}"
    )
    monitor = FRRMonitor(TARGET_AGENT_IP, AGENT_PORT)
    target = Target(connection=connection, monitors=[monitor])    # 3. Setup Monitor to Host VM (For Health Checks)
    # 4. Setup Session
    session = Session(
        target=target,
        sleep_time=2,
        fuzz_loggers=[FuzzLoggerText()],
        # pre_send_callbacks=[update_ospf_packet],
        post_test_case_callbacks=[reset_target_state],
        receive_data_after_fuzz=True 
    )

    #Difine packet
    define_grammar_func()
    if preamble_callback is not None:
            session.connect(s_get(node_name), callback=preamble_callback)
    else:
        session.connect(s_get(node_name))
    print(f"[*] Configuration loaded for Node: {node_name}. Fuzzing started...")


    session.fuzz()
        
    print("\n[!] Fuzzing interrupted by user.")




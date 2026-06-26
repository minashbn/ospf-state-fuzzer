from scapy_sm.traversal import *


def setup_state_2_hello_2way(target, fuzz_data_logger, session, *args, **kwargs):
    fuzz_data_logger.log_info("Preamble: Advancing to State 2.")
    reach_2way_state()
    
def setup_state_3_ExStart(target, fuzz_data_logger, session, *args, **kwargs):
    fuzz_data_logger.log_info("Preamble: Advancing to State 2.")
    reach_ExStart_state()
    
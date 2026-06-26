from scapy_builder.manager import *


def setup_state_2_hello_2way(target, fuzz_data_logger, session, *args, **kwargs):
    fuzz_data_logger.log_info("Preamble: Advancing to State 2.")
    simulator = OSPFSimulator(func="reach_state_init")
    success = simulator.run()

def setup_state_3_ExStart(target, fuzz_data_logger, session, *args, **kwargs):
    fuzz_data_logger.log_info("Preamble: Advancing to State 2.")
    simulator = OSPFSimulator(func="reach_state_2way")
    success = simulator.run()
    
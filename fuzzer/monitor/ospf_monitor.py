#!/usr/bin/env python3
import time
import requests
from boofuzz import BaseMonitor

class FRRMonitor(BaseMonitor):
    def __init__(self, agent_ip, agent_port=26000):
        super().__init__()
        self.agent_ip = agent_ip
        self.agent_port = agent_port
        self.agent_url = f"http://{agent_ip}:{agent_port}"
        self.name = "FRRMonitor"
        
    # def alive(self) -> bool:  # type: ignore[override]
    #     """
    #     Called once when the Monitor is attached to the session.
    #     Ensures Boofuzz can talk to our agent before starting the fuzzing run.
    #     """
    #     try:
    #         response = requests.get(f"{self.agent_url}/health", timeout=2)
    #         print(f"{self.agent_url}/health")

    #         return response.status_code == 200
    #     except Exception:
    #         return False


    # def post_send(self, target=None, fuzz_data_logger=None, session=None) ->bool: # type: ignore[override]
    #     """
    #     Called automatically AFTER every mutation transmission.
    #     This is where crash verification belongs.
    #     """
    #     time.sleep(0.1) # Small delay to give ospfd time to log a crash or fail
        
    #     try:
    #         response = requests.get(f"{self.agent_url}/status", timeout=2)
    #         if response.status_code == 200:
    #             status = response.json()
                
    #             if status.get('crashed', False):
    #                 msg = (
    #                     f"CRASH DETECTED via Agent Status!\n"
    #                     f"     OSPF processes: {status.get('ospfd_running')}/{status.get('expected')}\n"
    #                     f"     FRR active: {status.get('frr_active')}"
    #                 )
    #                 if fuzz_data_logger:
    #                     fuzz_data_logger.log_fail(msg)
    #                 else:
    #                     print(f"\n[!!!] {msg}")
    #                 return False # Signals Boofuzz that a crash occurred
                
    #             return True
    #         return False
    #     except Exception as e:
    #         msg = f"Check failed post-send (Target might have hard-crashed/frozen): {e}"
    #         if fuzz_data_logger:
    #             fuzz_data_logger.log_error(msg)
    #         else:
    #             print(f"[Monitor] {msg}")
    #         return False
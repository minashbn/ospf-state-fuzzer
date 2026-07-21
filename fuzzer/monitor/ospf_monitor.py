#!/usr/bin/env python3
import time
import requests
from boofuzz import BaseMonitor
from scapy_builder.ospf_parser import *
from scapy.layers.l2 import Ether
from scapy.contrib.ospf import OSPF_Hdr

#according to type field in ospf packet
STATE_PARSERS = {
    1: parse_hello,  
    2: parse_dbd,  
    3: parse_lsr,    

}

class FRRMonitor(BaseMonitor):
    def __init__(self, agent_ip,fuzzing_state,connection_obj, agent_port=5000):
        super().__init__()
        self.agent_ip = agent_ip
        self.agent_port = agent_port
        self.agent_url = f"http://{agent_ip}:{agent_port}"
        self.name = "FRRMonitor"
        self.fuzzing_state=fuzzing_state
        self.connection_obj = connection_obj
        
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

    @staticmethod
    def make_json_serializable(data):
        """
        Recursively traverse all dictionary fields and convert objects that are
        not JSON-serializable (e.g., Scapy Flag objects) into strings.
        """
        if isinstance(data, dict):
            # Pylance fix: qualify the recursive static method call with the class name.
            return {k: FRRMonitor.make_json_serializable(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [FRRMonitor.make_json_serializable(item) for item in data]
        # Convert non-primitive Python/Scapy objects to strings.
        elif data is not None and not isinstance(data, (str, int, float, bool)):
            return str(data)  # e.g., "<Flag 1 (MT)>"
        return data

    def _parse_packet_to_dict(self, raw_packet):
            if not raw_packet:
                return None
                
            try:
                #Ether and IP parsing
                pkt = Ether(raw_packet)
                
                
                packet_info={}
                
                # 2. ospf parsing
                if pkt.haslayer(OSPF_Hdr):
                    ospf_hdr = pkt[OSPF_Hdr]
                    
                    packet_info = {
                        "type": ospf_hdr.type,
                        "current_fuzzing_state": self.fuzzing_state,
                        "details": {}
                    }
                    # parse packet according to its state
                    parser_func = STATE_PARSERS.get(ospf_hdr.type)
                    
                    if parser_func:
                        try:
                            parsed_details = parser_func(pkt)
                            
                            if parser_func == parse_lsu and parsed_details and 'lsas' in parsed_details:
                                for lsa in parsed_details['lsas']:
                                    lsa.pop('raw', None)
                                    
                            packet_info["details"] =self.make_json_serializable(parsed_details)
                            
                        except Exception as parser_err:
                            # capture parser exception
                            packet_info["details"] = {"parser_error": f"State parser failed: {str(parser_err)}"}
                    else:
                        #
                        packet_info["details"] = {"info": "No specific parser mapped for this state", "summary": ospf_hdr.summary()}
                    
                    
                    
                return packet_info
                
            except Exception as e:
                return {"error": f"Failed to parse base packet layers: {str(e)}"}


    def post_send(self, target=None, fuzz_data_logger=None, session=None) ->bool: # type: ignore[override]
        """
        Called automatically AFTER every mutation transmission.
        This is where crash verification belongs.
        """
        time.sleep(0.1) # Small delay to give ospfd time to log a crash or fail
        
        sent_packet_raw = getattr(self.connection_obj, 'last_sent_packet', None)
        recv_packet_raw = getattr(self.connection_obj, 'last_recv_packet', None)
        
        #  reset for next capture
        if self.connection_obj:
            self.connection_obj.last_sent_packet = None
            self.connection_obj.last_recv_packet = None

        parsed_sent = self._parse_packet_to_dict(sent_packet_raw)
        parsed_recv = self._parse_packet_to_dict(recv_packet_raw)

        # 3. making payload
        payload = {
                    "sent_packet": parsed_sent,
                    "received_packet": parsed_recv
                }
        print('payload' * 60)
        print(payload)
        
        ##################################################################
        try:
            # 1. Change endpoint to /analyze_step and send payload via POST method
            response = requests.post(f"{self.agent_url}/analyze_step", json=payload, timeout=5)
            # The agent returns 200 (stable) or 503 (vulnerable/unhealthy)
            if response.status_code in [200, 503]:
                analysis_result = response.json()
                bugs = analysis_result.get('bugs_detected', {})
                
                # 2. Check Step 1: Daemon or Container Hard Crash
                if bugs.get('process_crash', False):
                    msg = (
                        f"CRASH DETECTED via Agent Analysis!\n"
                        f"     Reason: OSPFD daemon or container R1 has halted.\n"
                        f"     Target Status: {analysis_result.get('status')}"
                    )
                    if fuzz_data_logger:
                        fuzz_data_logger.log_fail(msg)
                    else:
                        print(f"\n[!!!] {msg}")
                    return True
                
                # 3. Check for structural state machine, RFC compliance, and memory bugs
                active_violations = [
                    bug for bug, triggered in bugs.items() 
                    if triggered and bug != 'process_crash'
                ]
                print('bug' * 60)
                print(bugs)
                
                if active_violations:
                    msg = (
                        f"OSPF PROTOCOL VULNERABILITY DETECTED!\n"
                        f"     Triggered Violations: {', '.join(active_violations)}\n"
                        f"     Full Execution State: {bugs}"
                    )
                    if fuzz_data_logger:
                        fuzz_data_logger.log_fail(msg)
                    else:
                        print(f"\n[!] {msg}")
                else:
                    print(f"[Monitor] Target is stable. Internal state: {analysis_result.get('frr_internal_state')}")
                
                return True
            
            print(f"[Monitor] Unexpected response status from Agent: {response.status_code}")
            return False

        except requests.exceptions.RequestException as e:
            # If the Flask agent itself is unreachable, the entire docker environment or port might be dead
            msg = f"Check failed post-send (Target/Agent might have hard-crashed or frozen entirely): {e}"
            if fuzz_data_logger:
                fuzz_data_logger.log_error(msg)
            else:
                print(f"[Monitor] {msg}")
            return False        



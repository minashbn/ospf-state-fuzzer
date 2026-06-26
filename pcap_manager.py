import os
import shutil
from scapy.utils import PcapWriter

class PcapManager:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(PcapManager, cls).__new__(cls)
            cls._instance.pcap_dir = "pcaps_output"
            cls._instance.tmp_dir = "pcaps_tmp"
            cls._instance.testcase_index = 0
            os.makedirs(cls._instance.pcap_dir, exist_ok=True)
            os.makedirs(cls._instance.tmp_dir, exist_ok=True)
        return cls._instance

    def rotate_pcap(self):
        """Called at the beginning of each Boofuzz test case."""
        self.testcase_index += 1
        # Write to a temporary tracking file first
        self.current_pcap = os.path.join(self.tmp_dir, f"current_test.pcap")
        if os.path.exists(self.current_pcap):
            os.remove(self.current_pcap)

    def write_packet(self, packet):
        """Writes an outgoing packet to the temporary PCAP."""
        if not self.current_pcap:
            return
        try:
            with PcapWriter(self.current_pcap, append=True, sync=True) as pcap:
                pcap.write(packet)
        except Exception as e:
            print(f"[!] PCAP Write Error: {e}")

    def finalize_testcase(self, bug_detected, crash_detected):
        print("[+] BUG or CRASH detected")

        """Called at the end of each testcase after querying the agent."""
        if not self.current_pcap or not os.path.exists(self.current_pcap):
            return

        if bug_detected or crash_detected:
            # Move the temporary PCAP to the persistent directory
            prefix = "crash" if crash_detected else "bug"
            saved_path = os.path.join(self.pcap_dir, f"{prefix}_testcase_{self.testcase_index}.pcap")
            shutil.move(self.current_pcap, saved_path)
            print(f"[+] Significant event detected! Saved PCAP to: {saved_path}")
        else:
            # Clean up the testcase PCAP to save space
            os.remove(self.current_pcap)
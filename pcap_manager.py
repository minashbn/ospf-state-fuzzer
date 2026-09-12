import os
import shutil
from typing import Optional
from scapy.utils import PcapWriter

class PcapManager:
    _instance: Optional["PcapManager"] = None

    # تعریف Type Hint برای Attributeهای کلاس جهت رفع خطای Pylance
    pcap_dir: str
    tmp_dir: str
    testcase_index: int
    current_pcap: Optional[str]

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(PcapManager, cls).__new__(cls)
            # مقداردهی اولیه فیلدها
            cls._instance.pcap_dir = "pcaps_output"
            cls._instance.tmp_dir = "pcaps_tmp"
            cls._instance.testcase_index = 0
            cls._instance.current_pcap = None
            
            os.makedirs(cls._instance.pcap_dir, exist_ok=True)
            os.makedirs(cls._instance.tmp_dir, exist_ok=True)
        return cls._instance

    def rotate_pcap(self):
        """Called at the beginning of each Boofuzz test case."""
        self.testcase_index += 1
        # ساخت آدرس فایل جاری
        self.current_pcap = os.path.join(self.tmp_dir, "current_test.pcap")
        
        # پاکسازی فایل تست‌کیس قبلی
        if os.path.exists(self.current_pcap):
            try:
                os.remove(self.current_pcap)
            except OSError as e:
                print(f"[!] Warning cleaning temporary PCAP: {e}")

    def write_packet(self, packet):
        """Writes a packet (incoming/outgoing) to the temporary PCAP."""
        if not self.current_pcap:
            return
        try:
            with PcapWriter(self.current_pcap, append=True, sync=True) as pcap:
                pcap.write(packet)
        except Exception as e:
            print(f"[!] PCAP Write Error: {e}")

    def finalize_testcase(self, bug_detected: bool, crash_detected: bool, bugs=None):
        """Called at the end of each testcase after querying the agent."""
        if not self.current_pcap or not os.path.exists(self.current_pcap):
            return

        if bug_detected or crash_detected:
            print("[+] BUG or CRASH detected")
            if bugs:
                print(f"[!] OSPF PROTOCOL VULNERABILITY DETECTED!\n     Full Execution State: {bugs}")
                
            prefix = "crash" if crash_detected else "bug"
            saved_path = os.path.join(self.pcap_dir, f"{prefix}_testcase_{self.testcase_index}.pcap")
            shutil.move(self.current_pcap, saved_path)
            print(f"[+] Significant event detected! Saved PCAP to: {saved_path}")
        else:
            # پاکسازی PCAP در صورت عدم وجود کرش/باگ برای صرفه‌جویی در فضای دیسک
            try:
                os.remove(self.current_pcap)
            except OSError:
                pass
        
        # ریست کردن وضعیت current_pcap برای تست بعدی
        self.current_pcap = None
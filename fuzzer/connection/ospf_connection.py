import socket
import time
import select
import sys
import struct
import requests
from boofuzz.connections import ITargetConnection
from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello
from scapy.utils import PcapWriter
from pcap_manager import PcapManager

import threading


ETH_P_IP = 0x0800
IPPROTO_OSPF = 89

EXPECTED_OSPF_TYPES = {
    1: 1,  # wait for Hello packet in init fuzzing
    2: 1,  # wait for Hello packet in 2way fuzzing
    3: 2,  # wait for DBD packet in exstart fuzzing
    4: 2,  # wait for DBD packet in exchange fuzzing
    5: 3,  # to do
}

class SimpleRawOSPF(ITargetConnection):
    def __init__(self, interface,fuzzing_state, target_ip=None, response_timeout=5.0, hello_interval=40.0,agent_url="http://127.0.0.1:5000"):
        self.interface = interface
        self.target_ip = target_ip
        self.response_timeout = response_timeout
        self.hello_interval = hello_interval

        self._sock = None
        self._expecting_response = True

        self.agent_url = agent_url # <-- Store monitor endpoint

        #save packet for status api
        self.last_sent_packet = None
        self.last_recv_packet = None

        #fuzzing state
        self.fuzzing_state = fuzzing_state
        
    def info(self): # type: ignore
        return f"Raw OSPF over {self.interface} with Heartbeat"

    def open(self):
            
            try:
                # Find the local IP attached to this interface
                import fcntl
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    self.our_ip = socket.inet_ntoa(fcntl.ioctl(
                        s.fileno(),
                        0x8915,  # SIOCGIFADDR
                        struct.pack('256s', bytes(self.interface[:15], 'utf-8'))
                    )[20:24])
                except Exception:
                    self.our_ip = "192.168.56.102"  # Fallback IP
                finally:
                    s.close()

                # Create a raw packet socket to capture IP traffic at layer 2
                self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_IP))
                self._sock.bind((self.interface, 0))
                self._sock.setblocking(False)
                
                # --- Enable Promiscuous Mode to capture Multicast OSPF packets without Wireshark ---
                SOL_PACKET = 263
                PACKET_ADD_MEMBERSHIP = 1
                PACKET_MR_PROMISC = 1

                try:
                    # Get the system interface index for the given interface name
                    if_index = socket.if_nametoindex(self.interface)
                    
                    # Pack the struct packet_mreq: {ifindex, mr_type, mr_alen, mr_address}
                    mreq = struct.pack("IHH8s", if_index, PACKET_MR_PROMISC, 0, b"")
                    
                    # Apply promiscuous membership option to the socket
                    self._sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)
                    print(f"[+] Promiscuous mode enabled on {self.interface}")
                except Exception as e:
                    print(f"[!] Warning: Failed to set promiscuous mode: {e}")
                # ---------------------------------------------------------------------------------

                print(f"[+] Bound to {self.interface}. Local IP: {self.our_ip}")
                return True

            except PermissionError:
                print("[!!!] Run as root (raw sockets required)")
                sys.exit(1)
            except Exception as e:
                print(f"[!!!] Socket open failed: {e}")
                sys.exit(1)
    
    def close(self):
        """Called by Boofuzz at the END of every testcase."""
        # 1. Close down the raw socket cleanly
        if self._sock:
            self._sock.close()
            self._sock = None

        # 2. Ask the monitoring agent if a bug happened during this testcase
        bug_detected = False
        crash_detected = False
     


    def get_mac_address(self,ifname):
        """Retrieve the raw MAC address of the given network interface."""
        import fcntl
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            info = fcntl.ioctl(
                s.fileno(), 
                0x8927,  # SIOCGIFHWADDR
                struct.pack('256s', bytes(ifname, 'utf-8')[:15])
            )
            return info[18:24]
        except Exception as e:
            print(f"[!!!] Failed to get MAC for {ifname}: {e}")
            sys.exit(1)
        finally:
            s.close()

    def calculate_ip_checksum(self,header):
        """Calculate the IPv4 header checksum."""
        if len(header) % 2 != 0:
            header += b'\x00'
        checksum = 0
        for i in range(0, len(header), 2):
            word = (header[i] << 8) + header[i+1]
            checksum += word
        while (checksum >> 16) > 0:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        checksum = ~checksum & 0xFFFF
        return checksum
    
    def send(self, data):
        if self._sock:
            # تخلیه هوشمند بافر: فقط پکت‌های ارسالی قبلی خودمان را پاک می‌کنیم
            while True:
                try:
                    # خواندن بدون توقف پکت متقاضی
                    pkt_in_buffer = self._sock.recv(65535, socket.MSG_DONTWAIT)

                        
                except (BlockingIOError, socket.error):
                    break

        try:
            import fcntl
            # 1. Retrieve Source IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                src_ip_bytes = fcntl.ioctl(
                    s.fileno(),
                    0x8915,  # SIOCGIFADDR
                    struct.pack('256s', bytes(self.interface[:15], 'utf-8'))
                )[20:24]
            except Exception:
                # Fallback static IP if ioctl fails
                src_ip_bytes = socket.inet_aton("192.168.56.102")
            finally:
                s.close()

            dst_ip_bytes = socket.inet_aton("224.0.0.5")

            # 2. Construct IPv4 Header
            # Version/IHL: 0x45 (IPv4, 20 bytes)
            # TOS: 0xc0 (Internetwork Control)
            # Total Length: 20 + len(data)
            # Identification: 0x1234 (Arbitrary for OSPF)
            # Flags/Fragment Offset: 0x0000
            # TTL: 0x01 (Standard for OSPF)
            # Protocol: 89 (OSPF)
            # Checksum: 0 (Initial)
            
            total_length = 20 + len(data)
            
            ip_header_no_csum = struct.pack(
                "!BBHHHBBH4s4s",
                0x45, 0xc0, total_length, 0x1234, 0x0000, 
                0x01, 89, 0, src_ip_bytes, dst_ip_bytes
            )

            # Calculate and pack the IP checksum
            ip_csum = self.calculate_ip_checksum(ip_header_no_csum)
            ip_header = struct.pack(
                "!BBHHHBBH4s4s",
                0x45, 0xc0, total_length, 0x1234, 0x0000, 
                0x01, 89, ip_csum, src_ip_bytes, dst_ip_bytes
            )

            # 3. Construct Ethernet Header
            # OSPF Multicast MAC: 01:00:5e:00:00:05
            dst_mac_bytes = struct.pack("!6B", 0x01, 0x00, 0x5e, 0x00, 0x00, 0x05)
            src_mac_bytes = self.get_mac_address(self.interface)
            eth_type = 0x0800 # IPv4
            
            eth_header = struct.pack("!6s6sH", dst_mac_bytes, src_mac_bytes, eth_type)

            # 4. Assemble final frame and send
            final_packet = eth_header + ip_header + data
            self.last_sent_packet = final_packet
            print(self.last_sent_packet)
            if self._sock:
                self._sock.send(final_packet)

            #save as pcap

            self._expecting_response = True


        except Exception as e:
            print(f"[!!!] Send Error in wrapper: {e}")

    # ---------------------------------------------------------------------

    def recv(self, max_bytes):
        if not self._sock:
            return b""

        timeout = self.response_timeout if self._expecting_response else 1.2
        self._expecting_response = False

        start = time.time()

        while True:
            time_left = timeout - (time.time() - start)
            if time_left <= 0:
                return b""

            r, _, _ = select.select([self._sock], [], [], time_left)
            if not r:
                return b""

            try:
                frame = self._sock.recv(65535)
                self.last_recv_packet = frame
                # ---------- Ethernet ----------
                if len(frame) < 14:
                    continue

                eth_type = struct.unpack("!H", frame[12:14])[0]
                if eth_type != ETH_P_IP:
                    continue

                # ---------- IP ----------
                ip = frame[14:]
                if len(ip) < 20:
                    continue

                version_ihl = ip[0]
                ihl = (version_ihl & 0x0F) * 4
                protocol = ip[9]

                if protocol != IPPROTO_OSPF:
                    continue

                src_ip = socket.inet_ntoa(ip[12:16])
                dst_ip = socket.inet_ntoa(ip[16:20])
                if src_ip == self.our_ip:
                    continue

                if self.target_ip and src_ip != self.target_ip:
                    continue

                if len(ip) < ihl:
                    continue
                # ---------- OSPF Dynamic Filtering ----------
                ospf_payload = ip[ihl:]
                if len(ospf_payload) < 24: # Minimum length for OSPF header
                    continue
                
                self.last_recv_packet = frame
                print(
                    f"[DEBUG] Valid OSPF Response Matched from {src_ip} → {dst_ip} "
                    f"(len={len(ospf_payload)})"
                )

                print(
                    f"[DEBUG] OSPF packet {src_ip} → {dst_ip} "
                    f"(len={len(ospf_payload)})"
                )

                return ospf_payload[:max_bytes]

            except BlockingIOError:
                continue

            except Exception as e:
                print(f"[!] Recv error: {e}")
                return b""
            

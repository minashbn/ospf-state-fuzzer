# config.py

# ==========================================
# --- Fuzzer Network Settings ---
IFACE = "enp0s8" 
MULTICAST_OSPF = "224.0.0.5"
ATTACKER_IP = "192.168.56.102"

# --- OSPF Protocol Settings ---
TARGET_ROUTER_IP = "192.168.56.201" 
ATTACKER_ROUTER_ID = "3.3.3.3"


# --- Boofuzz Agent / Monitor Settings ---
TARGET_AGENT_IP  = "192.168.56.101"
AGENT_PORT = 5000

TARGET_ROUTER_ID = "2.2.2.2"
AREA_ID = "0.0.0.0"
AUTH_TYPE = 0 # 0 = Null Authentication

#Exchang fuzzing
FUZZING_PHASE = "LSA_PARSING"  # "LSA_PARSING" / "DBD_FRAMEWORK"

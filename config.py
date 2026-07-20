"""
====================================================
Network Intrusion Detection System (NIDS)
Configuration File
====================================================
"""

# ==================================================
# Packet Capture
# ==================================================

# Whether Scapy should store captured packets in memory
STORE_PACKETS = False

# Print security summary after every N packets
SUMMARY_INTERVAL = 20


# ==================================================
# ICMP Flood Detection
# ==================================================

# Maximum ICMP packets allowed within the time window
ICMP_THRESHOLD = 10

# Time window (seconds)
ICMP_TIME_WINDOW = 5


# ==================================================
# Port Scan Detection
# ==================================================

# Number of different ports accessed within the time window
PORTSCAN_THRESHOLD = 10

# Time window (seconds)
PORTSCAN_TIME_WINDOW = 5


# ==================================================
# Packet Size Detection
# ==================================================

# Packets larger than this will be flagged
LARGE_PACKET_SIZE = 1400


# ==================================================
# Overall Risk Thresholds
# ==================================================

# ALERT count required for HIGH risk
HIGH_ALERT_THRESHOLD = 5

# ALERT count required for CRITICAL risk
CRITICAL_ALERT_THRESHOLD = 10

# WARNING count required for MEDIUM risk
MEDIUM_WARNING_THRESHOLD = 10


# ==================================================
# Common Service Ports
# ==================================================

SSH_PORT = 22
TELNET_PORT = 23

FTP_PORTS = [20, 21]

HTTP_PORT = 80
HTTPS_PORT = 443

DNS_PORT = 53

SMB_PORTS = [139, 445]
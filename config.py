"""
====================================================
Network Intrusion Detection System (NIDS)
Configuration File
====================================================
"""

# ==================================================
# Network
# ==================================================

DEFAULT_INTERFACE = None

# ==================================================
# Database
# ==================================================

DATABASE_NAME = "nids.db"

STORE_PACKETS = False

AUTO_SAVE_SESSION = True

# ==================================================
# Flow Tracking
# ==================================================

FLOW_TIMEOUT = 60

# ==================================================
# Console
# ==================================================

STATUS_REFRESH_INTERVAL = 1

# ==================================================
# Detection Thresholds
# ==================================================

ICMP_THRESHOLD = 100
ICMP_TIME_WINDOW = 5

PORTSCAN_THRESHOLD = 20
PORTSCAN_TIME_WINDOW = 5

SYN_THRESHOLD = 100
UDP_THRESHOLD = 100
DNS_THRESHOLD = 100

# ==================================================
# Packet Analysis
# ==================================================

LARGE_PACKET_SIZE = 1400

# ==================================================
# Standard Ports
# ==================================================

SSH_PORT = 22

TELNET_PORT = 23

FTP_PORTS = [20, 21]

HTTP_PORT = 80

HTTPS_PORT = 443

DNS_PORT = 53

SMTP_PORT = 25

POP3_PORT = 110

IMAP_PORT = 143

# ==================================================
# Alert Settings
# ==================================================

ENABLE_ALERT_POPUP = True

# ==================================================
# Debug
# ==================================================

DEBUG = True
# ==================================================
# Security Summary
# ==================================================

SUMMARY_INTERVAL = 100          # Print summary every 100 packets

MEDIUM_WARNING_THRESHOLD = 10   # 10 warnings -> MEDIUM risk

HIGH_ALERT_THRESHOLD = 5         # 5 alerts -> HIGH risk

CRITICAL_ALERT_THRESHOLD = 15    # 15 alerts -> CRITICAL risk
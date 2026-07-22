"""
====================================================
Network Intrusion Detection System (NIDS)
Configuration File
====================================================
"""


# ==================================================
# Network Configuration
# ==================================================

DEFAULT_INTERFACE = None


# ==================================================
# Packet Storage
# ==================================================

# False because storing raw packets
# continuously consumes RAM

STORE_PACKETS = False


# ==================================================
# Database
# ==================================================

DATABASE_NAME = "nids.db"


# ==================================================
# Flow Tracking
# ==================================================

# Seconds after which a flow is considered completed

FLOW_TIMEOUT = 60



# ==================================================
# Security Summary
# ==================================================

SUMMARY_INTERVAL = 100



# ==================================================
# Detection Thresholds
# ==================================================

# ICMP Flood

ICMP_THRESHOLD = 100

ICMP_TIME_WINDOW = 5



# Port Scan

PORTSCAN_THRESHOLD = 20

PORTSCAN_TIME_WINDOW = 5



# SYN Flood

SYN_THRESHOLD = 100



# UDP Flood

UDP_THRESHOLD = 100



# DNS Flood

DNS_THRESHOLD = 100



# Large Packet

LARGE_PACKET_SIZE = 1400



# ==================================================
# Common Ports
# ==================================================

SSH_PORT = 22

TELNET_PORT = 23

FTP_PORTS = [
    20,
    21
]

HTTP_PORT = 80

HTTPS_PORT = 443

DNS_PORT = 53

SMTP_PORT = 25

POP3_PORT = 110

IMAP_PORT = 143



# ==================================================
# Risk Calculation
# ==================================================

MEDIUM_WARNING_THRESHOLD = 10

HIGH_ALERT_THRESHOLD = 5

CRITICAL_ALERT_THRESHOLD = 15



# ==================================================
# Console
# ==================================================

STATUS_REFRESH_INTERVAL = 1



# ==================================================
# Debug
# ==================================================

DEBUG = True
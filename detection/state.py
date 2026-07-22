"""
====================================================
Network Intrusion Detection System (NIDS)
Module : Runtime State

Description:
Stores runtime information used by the Detection
Engine for behaviour-based intrusion detection.
The data in this module is maintained only while
the IDS is running.
====================================================
"""

from collections import defaultdict, deque
from datetime import datetime

# ==================================================
# Session Information
# ==================================================

# Time when the IDS session started
session_start = datetime.now()


# ==================================================
# Packet History
# ==================================================

# Stores timestamps of all captured packets.
# Useful for packet-rate calculations.

packet_history = deque()


# ==================================================
# ICMP History
# ==================================================

# Stores ICMP packet timestamps for each source IP.
#
# Example:
#
# {
#     "192.168.1.10":
#         deque([
#             time1,
#             time2,
#             time3
#         ])
# }

icmp_history = defaultdict(deque)


# ==================================================
# Port Scan History
# ==================================================

# Stores destination ports accessed by each source IP.
#
# Example:
#
# {
#     "192.168.1.20":
#         deque([
#             (timestamp, 22),
#             (timestamp, 80),
#             (timestamp, 443)
#         ])
# }

port_history = defaultdict(deque)


# ==================================================
# Connection History
# ==================================================

# Stores connection attempts from each source IP.
# This will later be used for:
#
# - Brute Force Detection
# - SYN Flood Detection
# - Connection Rate Analysis

connection_history = defaultdict(deque)


# ==================================================
# Runtime Counters
# ==================================================

# Total packets processed during this session
packet_counter = 0

# Detection counters
normal_packets = 0
info_packets = 0
warning_packets = 0
alert_packets = 0
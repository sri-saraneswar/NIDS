"""
====================================================
Network Intrusion Detection System (NIDS)
Module : Analyzer
Description:
Detects Port Scanning attacks.
====================================================
"""

from collections import defaultdict
from datetime import timedelta


# Detection Parameters

TIME_WINDOW = 10          # seconds

PORT_THRESHOLD = 10       # unique ports


# Structure

# {

#   src_ip :

#       {

#         port : timestamp

#       }

# }

scan_tracker = defaultdict(dict)


def analyze_packet(packet):

    if packet["protocol"] != "TCP":
        return

    src_ip = packet["src_ip"]

    dst_port = packet["dst_port"]

    current_time = packet["timestamp"]


    # Remove old entries

    ports = scan_tracker[src_ip]

    expired_ports = []

    for port, time in ports.items():

        if current_time - time > timedelta(seconds=TIME_WINDOW):

            expired_ports.append(port)

    for port in expired_ports:

        del ports[port]


    # Store latest port

    ports[dst_port] = current_time


    # Detection

    if len(ports) >= PORT_THRESHOLD:

        print("\n")
        print("="*60)

        print("ALERT : PORT SCAN DETECTED")

        print(f"Source IP      : {src_ip}")

        print(f"Ports Scanned  : {len(ports)}")

        print(f"Time Window    : {TIME_WINDOW} seconds")

        print("Severity       : HIGH")

        print("="*60)

        # Reset after alert

        scan_tracker[src_ip].clear()
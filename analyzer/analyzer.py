"""
====================================================
Network Intrusion Detection System (NIDS)
Module : Packet Analyzer

Description:
Receives packet information from the Capture Module,
passes it to the Detection Engine, and displays
detailed packet analysis.
====================================================
"""

from detection.detection import detect, summary_required
from detection.statistics import security_summary

# ==================================================
# Packet Counter
# ==================================================

packet_id = 0


# ==================================================
# Analyze Packet
# ==================================================

def analyze_packet(packet_info):
    """
    Analyzes a captured packet by sending it to the
    Detection Engine and displaying the result.
    """

    global packet_id

    packet_id += 1

    # --------------------------------------------------
    # Run Detection Engine
    # --------------------------------------------------

    result = detect(packet_info)

    # --------------------------------------------------
    # Display Packet Analysis
    # --------------------------------------------------

    print("\n")
    print("=" * 65)
    print(f"{'PACKET ANALYSIS':^65}")
    print("=" * 65)

    print(f"Packet ID        : {packet_id}")
    print(f"Timestamp        : {packet_info['timestamp']}")
    print(f"Source IP        : {packet_info['src_ip']}")
    print(f"Destination IP   : {packet_info['dst_ip']}")
    print(f"Protocol         : {packet_info['protocol']}")

    if packet_info["src_port"] is not None:
        print(f"Source Port      : {packet_info['src_port']}")

    if packet_info["dst_port"] is not None:
        print(f"Destination Port : {packet_info['dst_port']}")

    print(f"Packet Size      : {packet_info['packet_size']} Bytes")

    print("-" * 65)

    print(f"Status           : {result['status']}")
    print(f"Severity         : {result['severity']}")
    print(f"Rule ID          : {result['rule_id']}")
    print(f"Attack           : {result['attack']}")
    print(f"Reason           : {result['reason']}")

    print("=" * 65)

    # --------------------------------------------------
    # Print Security Summary
    # --------------------------------------------------

    if summary_required():
        security_summary()
"""
====================================================
Network Intrusion Detection System (NIDS)
Module : Packet Analyzer
Description:
Receives packet information from the Capture Module,
invokes the Detection Engine, and displays analysis.
====================================================
"""

from detection.detection import detect


def analyze_packet(packet_info):

    status, reason = detect(packet_info)

    print("\n========== Packet Analysis ==========")
    print(f"Status : {status}")
    print(f"Reason : {reason}")
    print("=====================================")
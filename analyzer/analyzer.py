"""
====================================================
Network Intrusion Detection System (NIDS)
Module : Packet Analyzer
Description:
Coordinates flow tracking, detection,
statistics and console output.
====================================================
"""

from flow.flow_tracker import update_flow

from detection.detection import detect

from console.console_manager import (
    display_live_status,
    display_alert
)

packet_id = 0


def analyze_packet(packet_info):

    global packet_id

    packet_id += 1

    # ------------------------------------
    # Update Flow
    # ------------------------------------

    flow = update_flow(packet_info)

    # Temporary Debug Output
    print("\n========== FLOW ==========")
    print(f"Flow ID     : {flow.flow_id}")
    print(f"Source      : {flow.src_ip}:{flow.src_port}")
    print(f"Destination : {flow.dst_ip}:{flow.dst_port}")
    print(f"Protocol    : {flow.protocol}")
    print(f"Packets     : {flow.packet_count}")
    print(f"Bytes       : {flow.bytes}")
    print(f"Status      : {flow.status}")
    print("==========================\n")

    # Store Flow ID with packet
    packet_info["flow_id"] = flow.flow_id

    # ------------------------------------
    # Detection
    # ------------------------------------

    result = detect(packet_info)

    # ------------------------------------
    # Console Output
    # ------------------------------------

    if result["status"] == "ALERT":

        display_alert(packet_info, result)

    else:

        display_live_status()
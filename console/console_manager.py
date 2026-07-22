"""
====================================================
Network Intrusion Detection System (NIDS)
Module : Console Manager
Description:
Handles all console output.
====================================================
"""

import detection.statistics as stats


# ==================================================
# Startup Screen
# ==================================================

def display_startup(interface):

    print("\n")
    print("=" * 70)
    print("          NETWORK INTRUSION DETECTION SYSTEM")
    print("=" * 70)

    print(f"Monitoring Interface : {interface}")
    print("Status               : Monitoring Network")
    print("Press CTRL + C to stop")

    print("=" * 70)


# ==================================================
# Live Status
# ==================================================

def display_live_status():

    alerts = stats.status_counter["ALERT"]

    warnings = stats.status_counter["WARNING"]

    risk = stats.calculate_risk()

    print(
        f"\rPackets : {stats.total_packets:<8}"
        f"Alerts : {alerts:<5}"
        f"Warnings : {warnings:<5}"
        f"Risk : {risk:<10}",
        end="",
        flush=True
    )


# ==================================================
# Alert Panel
# ==================================================

def display_alert(packet_info, result):

    print("\n")
    print("=" * 70)
    print("                 🚨 NETWORK ALERT 🚨")
    print("=" * 70)

    print(f"Time           : {packet_info['timestamp']}")

    print(f"Source IP      : {packet_info['src_ip']}")

    print(f"Destination IP : {packet_info['dst_ip']}")

    print(f"Protocol       : {packet_info['protocol']}")

    if packet_info["src_port"] is not None:
        print(f"Source Port    : {packet_info['src_port']}")

    if packet_info["dst_port"] is not None:
        print(f"Destination Port : {packet_info['dst_port']}")

    print(f"Severity       : {result['severity']}")

    print(f"Attack         : {result['attack']}")

    print(f"Reason         : {result['reason']}")

    print("=" * 70)

    display_live_status()
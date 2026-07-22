"""
====================================================
Network Intrusion Detection System (NIDS)

Module : Console Manager

Displays:
- Startup
- Live Status
- Alerts

====================================================
"""


import detection.statistics as stats





# ==========================================
# Startup Display
# ==========================================

def display_startup(interface):


    print("\n")


    print("="*60)

    print(
        "      NETWORK INTRUSION DETECTION SYSTEM"
    )

    print("="*60)



    print(
        f"Monitoring Interface : {interface}"
    )


    print(
        "Status : Monitoring Network"
    )


    print(
        "Press CTRL+C to stop"
    )


    print("="*60)







# ==========================================
# Live Status
# ==========================================

def display_live_status():


    alerts = stats.status_counter["ALERT"]


    warnings = stats.status_counter["WARNING"]



    print(

        f"\rPackets : {stats.total_packets:<8}"

        f" Alerts : {alerts:<5}"

        f" Warnings : {warnings:<5}"

        f" Risk : {stats.calculate_risk()}",

        end="",

        flush=True

    )








# ==========================================
# Alert Display
# ==========================================

def display_alert(packet_info,result):


    print("\n")

    print("="*60)

    print(
        "              🚨 NETWORK ALERT 🚨"
    )

    print("="*60)



    print(
        f"Time : {packet_info['timestamp']}"
    )


    print(
        f"Source IP : {packet_info['src_ip']}"
    )


    print(
        f"Destination IP : {packet_info['dst_ip']}"
    )


    print(
        f"Protocol : {packet_info['protocol']}"
    )


    print(
        f"Severity : {result['severity']}"
    )


    print(
        f"Attack : {result['attack']}"
    )


    print(
        f"Reason : {result['reason']}"
    )


    print("="*60)
"""
====================================================
Network Intrusion Detection System (NIDS)

Module : Packet Analyzer

<<<<<<< HEAD
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
=======
Connects:
- Flow Tracking
- Detection Engine
- Session Tracking
- Statistics Engine
- Console Output

====================================================
"""


# ==================================================
# Flow Tracking
# ==================================================

from flow.flow_tracker import (

    update_flow,

    get_total_flow_count,

    get_active_flow_count,

    get_completed_flow_count

)



# ==================================================
# Detection Engine
# ==================================================

from detection.detection import detect



# ==================================================
# Console Output
# ==================================================

from console.console_manager import (

    display_live_status,

    display_alert

)
>>>>>>> e73906848d73f55ab94d301e6455a8cf66336400



# ==================================================
# Statistics Engine
# ==================================================

from detection.statistics import (

    update_statistics

)



# ==================================================
# Session Management
# ==================================================

from session.session_manager import (

    update_packet,

    update_flows,

    update_alert,

    update_risk

)



# ==================================================
# Packet Counter
# ==================================================

packet_id = 0


<<<<<<< HEAD
# ==================================================
# Analyze Packet
=======



# ==================================================
# Packet Analyzer
>>>>>>> e73906848d73f55ab94d301e6455a8cf66336400
# ==================================================

def analyze_packet(packet_info):
    """
    Analyzes a captured packet by sending it to the
    Detection Engine and displaying the result.
    """

    global packet_id


    packet_id += 1

<<<<<<< HEAD
    # --------------------------------------------------
    # Run Detection Engine
    # --------------------------------------------------

    result = detect(packet_info)

    # --------------------------------------------------
    # Display Packet Analysis
    # --------------------------------------------------
=======


    # ==========================================
    # 1. FLOW UPDATE
    # ==========================================


    flow = update_flow(packet_info)



    packet_info["flow_id"] = flow.flow_id





    # ==========================================
    # 2. SESSION UPDATE
    # ==========================================


    update_packet()



    update_flows(

        get_total_flow_count(),

        get_active_flow_count(),

        get_completed_flow_count()

    )







    # ==========================================
    # 3. DETECTION ENGINE
    # ==========================================


    result = detect(packet_info)







    # ==========================================
    # 4. STATISTICS UPDATE
    # ==========================================


    update_statistics(

        packet_info,

        result

    )







    # ==========================================
    # 5. ALERT HANDLING
    # ==========================================

>>>>>>> e73906848d73f55ab94d301e6455a8cf66336400

    print("\n")
    print("=" * 65)
    print(f"{'PACKET ANALYSIS':^65}")
    print("=" * 65)

<<<<<<< HEAD
    print(f"Packet ID        : {packet_id}")
    print(f"Timestamp        : {packet_info['timestamp']}")
    print(f"Source IP        : {packet_info['src_ip']}")
    print(f"Destination IP   : {packet_info['dst_ip']}")
    print(f"Protocol         : {packet_info['protocol']}")
=======


        update_alert()



        update_risk(

            result["severity"]

        )



        display_alert(

            packet_info,

            result

        )


>>>>>>> e73906848d73f55ab94d301e6455a8cf66336400

    if packet_info["src_port"] is not None:
        print(f"Source Port      : {packet_info['src_port']}")

<<<<<<< HEAD
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
=======


        display_live_status()





    # ==========================================
    # RETURN RESULT
    # ==========================================


    return result
>>>>>>> e73906848d73f55ab94d301e6455a8cf66336400

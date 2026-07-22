"""
====================================================
Network Intrusion Detection System (NIDS)

Module : Packet Analyzer

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
# Statistics Engine
# ==================================================

from detection.statistics import update_statistics


# ==================================================
# Console Output
# ==================================================

from console.console_manager import (

    display_live_status,

    display_alert

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


# ==================================================
# Packet Analyzer
# ==================================================

def analyze_packet(packet_info):

    global packet_id

    packet_id += 1

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
    # 3. DETECTION
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

    if result["status"] == "ALERT":

        update_alert()

        update_risk(

            result["severity"]

        )

        display_alert(

            packet_info,

            result

        )

    else:

        display_live_status()

    return result
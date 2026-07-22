"""
====================================================
Network Intrusion Detection System (NIDS)
Module : Packet Analyzer
Description:
Coordinates flow tracking, detection,
statistics, database logging and console output.
====================================================
"""

from flow.flow_tracker import (
    update_flow,
    get_total_flow_count,
    get_active_flow_count,
    get_completed_flow_count
)

from detection.detection import (
    detect,
    summary_required
)

from detection.statistics import security_summary

from console.console_manager import (
    display_live_status,
    display_alert
)

from session.session_manager import (
    update_packet,
    update_flows,
    update_alert,
    update_risk,
    get_current_session
)

from database.database import (
    save_packet,
    save_flow,
    save_alert
)


packet_id = 0


def analyze_packet(packet_info):

    global packet_id

    packet_id += 1

    # ------------------------------------
    # Update/Create Flow
    # ------------------------------------

    flow = update_flow(packet_info)

    packet_info["flow_id"] = flow.flow_id

    # ------------------------------------
    # Update Session Statistics
    # ------------------------------------

    update_packet()

    update_flows(
        get_total_flow_count(),
        get_active_flow_count(),
        get_completed_flow_count()
    )

    # ------------------------------------
    # Current Session
    # ------------------------------------

    session = get_current_session()

    session_id = None

    if session is not None:
        session_id = session.session_id

    # ------------------------------------
    # Save Packet
    # ------------------------------------

    save_packet(packet_info, session_id)

    # ------------------------------------
    # Save Flow
    # ------------------------------------

    save_flow(flow, session_id)

    # ------------------------------------
    # Detection Engine
    # ------------------------------------

    result = detect(packet_info)

    # ------------------------------------
    # Alerts
    # ------------------------------------

    if result["status"] == "ALERT":

        update_alert()

        update_risk(result["severity"])

        save_alert(
            packet_info,
            result,
            session_id
        )

        display_alert(
            packet_info,
            result
        )

    else:

        display_live_status()
    # ------------------------------------
# Print Security Summary
# ------------------------------------

    if summary_required():

        security_summary()
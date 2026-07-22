"""
====================================================
Network Intrusion Detection System (NIDS)
Module : Flow Tracker
Description:
Creates, updates and manages communication flows.
Uses Flow objects instead of dictionaries.
====================================================
"""

from datetime import datetime

import flow.flow_statistics as flow_stats

from flow.flow import Flow

from config import FLOW_TIMEOUT


# ==================================================
# Cleanup Expired Flows
# ==================================================

def cleanup_flows():
    """
    Move inactive flows to completed flows.
    """

    current_time = datetime.now()

    expired = []

    for flow_key, flow in flow_stats.active_flows.items():

        idle_time = (

            current_time -

            flow.last_seen

        ).total_seconds()

        if idle_time >= FLOW_TIMEOUT:

            expired.append(flow_key)

    for flow_key in expired:

        flow = flow_stats.active_flows.pop(flow_key)

        flow.close()

        flow_stats.completed_flows.append(flow)

        flow_stats.active_flow_count -= 1

        flow_stats.completed_flow_count += 1


# ==================================================
# Update Flow
# ==================================================

def update_flow(packet_info):
    """
    Create or update a communication flow.

    Returns
    -------
    Flow
    """

    cleanup_flows()

    flow_key = (

        packet_info["src_ip"],

        packet_info["dst_ip"],

        packet_info["src_port"],

        packet_info["dst_port"],

        packet_info["protocol"]

    )

    # ----------------------------------------------
    # Existing Flow
    # ----------------------------------------------

    if flow_key in flow_stats.active_flows:

        flow = flow_stats.active_flows[flow_key]

        flow.update(

            packet_info["packet_size"]

        )

        return flow

    # ----------------------------------------------
    # New Flow
    # ----------------------------------------------

    flow_stats.total_flows += 1

    flow_stats.active_flow_count += 1

    flow = Flow(

        flow_id=f"FLOW-{flow_stats.total_flows:05}",

        src_ip=packet_info["src_ip"],

        dst_ip=packet_info["dst_ip"],

        src_port=packet_info["src_port"],

        dst_port=packet_info["dst_port"],

        protocol=packet_info["protocol"],

        packet_size=packet_info["packet_size"]

    )

    flow_stats.active_flows[flow_key] = flow

    # Communication Statistics

    flow_stats.source_counter[flow.src_ip] += 1

    flow_stats.destination_counter[flow.dst_ip] += 1

    flow_stats.protocol_counter[flow.protocol] += 1

    return flow


# ==================================================
# Helper Functions
# ==================================================

def get_total_flow_count():

    return flow_stats.total_flows


def get_active_flow_count():

    return flow_stats.active_flow_count


def get_completed_flow_count():

    return flow_stats.completed_flow_count


def get_active_flows():

    return flow_stats.active_flowsS


def get_completed_flows():

    return flow_stats.completed_flows


def get_top_talkers(limit=5):

    return flow_stats.source_counter.most_common(limit)


def get_protocol_statistics():

    return dict(flow_stats.protocol_counter)
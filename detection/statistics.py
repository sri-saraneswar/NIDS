"""
=========================================================
Network Intrusion Detection System (NIDS)

Module : Detection Statistics

Stores runtime IDS statistics.

    Packets
    Protocols
    Bytes
    Alerts
    Risk
    Attack Types
    Top Attackers
    Top Targets
    Host Traffic

=========================================================
"""


from collections import defaultdict



# =====================================================
# Runtime Statistics
# =====================================================


statistics = {

    "packets": 0,

    "alerts": 0,

    "warnings": 0,

    "risk": "LOW",

    "high": 0,

    "medium": 0,

    "low": 0,

    "critical": 0,

    "attack_types": {},

    "top_attackers": {},

    "top_targets": {},

    "total_bytes": 0,

    "protocol_counts": {},

    "host_traffic": {}

}





# =====================================================
# Packet Counter
# =====================================================


def update_packet_count():
    """Increment the global packet counter."""

    statistics["packets"] += 1





# =====================================================
# Protocol and Byte Tracking
# =====================================================


def update_protocol(protocol, packet_size):
    """
    Track protocol distribution and byte totals.

    Called for every packet from the analyzer.

    Args:
        protocol: Protocol name (TCP, UDP, ICMP, ARP, etc.)
        packet_size: Size of the packet in bytes.
    """

    # Protocol count
    statistics["protocol_counts"].setdefault(
        protocol, 0
    )
    statistics["protocol_counts"][protocol] += 1

    # Byte tracking
    statistics["total_bytes"] += packet_size





# =====================================================
# Host Traffic Tracking
# =====================================================


def update_host_traffic(src_ip, dst_ip):
    """
    Track packets per host for top communicating hosts.

    Args:
        src_ip: Source IP address.
        dst_ip: Destination IP address.
    """

    statistics["host_traffic"].setdefault(
        src_ip, 0
    )
    statistics["host_traffic"][src_ip] += 1

    if dst_ip:
        statistics["host_traffic"].setdefault(
            dst_ip, 0
        )
        statistics["host_traffic"][dst_ip] += 1





# =====================================================
# Update Attack Statistics
# =====================================================


def update_statistics(events):
    """
    Update attack-related statistics from detection events.

    Only processes STARTED events to avoid double-counting.

    Args:
        events: List of event dicts with 'status' and 'attack' keys.
    """

    levels = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4
    }


    for event in events:

        if event["status"] != "STARTED":
            continue


        attack = event["attack"]

        severity = attack["severity"]


        statistics["alerts"] += 1


        # Severity count

        if severity == "LOW":
            statistics["low"] += 1

        elif severity == "MEDIUM":
            statistics["medium"] += 1

        elif severity == "HIGH":
            statistics["high"] += 1

        elif severity == "CRITICAL":
            statistics["critical"] += 1


        # Highest risk

        if levels.get(severity, 0) > levels.get(
            statistics["risk"], 0
        ):
            statistics["risk"] = severity


        # Attack types

        name = attack["attack_type"]

        statistics["attack_types"].setdefault(
            name, 0
        )
        statistics["attack_types"][name] += 1


        # Top attacker

        attacker = attack["source_ip"]

        statistics["top_attackers"].setdefault(
            attacker, 0
        )
        statistics["top_attackers"][attacker] += 1


        # Target IP

        target = attack["destination_ip"]

        statistics["top_targets"].setdefault(
            target, 0
        )
        statistics["top_targets"][target] += 1





# =====================================================
# Get Statistics
# =====================================================


def get_statistics():
    """Return the current statistics dictionary."""

    return statistics





# =====================================================
# Get Top Communicating Hosts
# =====================================================


def get_top_hosts(count=10):
    """
    Return the top N communicating hosts by packet count.

    Args:
        count: Number of top hosts to return.

    Returns:
        List of (ip, packet_count) tuples sorted descending.
    """

    hosts = statistics["host_traffic"]

    sorted_hosts = sorted(
        hosts.items(),
        key=lambda x: x[1],
        reverse=True
    )

    return sorted_hosts[:count]





# =====================================================
# Reset
# =====================================================


def reset_statistics():
    """Reset all statistics to initial values."""

    statistics.clear()

    statistics.update({

        "packets": 0,

        "alerts": 0,

        "warnings": 0,

        "risk": "LOW",

        "high": 0,

        "medium": 0,

        "low": 0,

        "critical": 0,

        "attack_types": {},

        "top_attackers": {},

        "top_targets": {},

        "total_bytes": 0,

        "protocol_counts": {},

        "host_traffic": {}

    })
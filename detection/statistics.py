"""
====================================================
Network Intrusion Detection System (NIDS)
Module : Statistics Engine

Description:
Maintains network statistics and generates
overall security summaries.
====================================================
"""

from collections import Counter

from config import (
    SUMMARY_INTERVAL,
    HIGH_ALERT_THRESHOLD,
    CRITICAL_ALERT_THRESHOLD,
    MEDIUM_WARNING_THRESHOLD
)

# ==================================================
# Global Statistics Counters
# ==================================================

total_packets = 0

protocol_counter = Counter()

status_counter = Counter()

attack_counter = Counter()

source_counter = Counter()

destination_counter = Counter()


# ==================================================
# Update Statistics
# ==================================================

def update_statistics(packet_info, result):
    """
    Updates IDS statistics for every processed packet.
    """

    global total_packets

    total_packets += 1

    # Protocol statistics
    protocol_counter[packet_info["protocol"]] += 1

    # Packet status statistics
    status_counter[result["status"]] += 1

    # Attack statistics
    if result["attack"] != "None":
        attack_counter[result["attack"]] += 1

    # Source IP statistics
    source_counter[packet_info["src_ip"]] += 1

    # Destination IP statistics
    destination_counter[packet_info["dst_ip"]] += 1


# ==================================================
# Calculate Overall Risk
# ==================================================

def calculate_risk():
    """
    Calculates the current network risk level.
    """

    alerts = status_counter["ALERT"]
    warnings = status_counter["WARNING"]

    if alerts >= CRITICAL_ALERT_THRESHOLD:
        return "CRITICAL"

    elif alerts >= HIGH_ALERT_THRESHOLD:
        return "HIGH"

    elif warnings >= MEDIUM_WARNING_THRESHOLD:
        return "MEDIUM"

    else:
        return "LOW"


# ==================================================
# Display Security Summary
# ==================================================

def security_summary():
    """
    Displays an overall security summary.
    """

    print("\n")
    print("=" * 60)
    print("              NETWORK SECURITY SUMMARY")
    print("=" * 60)

    print(f"Total Packets      : {total_packets}")

    print("\nPacket Status")
    print(f"Normal             : {status_counter['NORMAL']}")
    print(f"Info               : {status_counter['INFO']}")
    print(f"Warning            : {status_counter['WARNING']}")
    print(f"Alert              : {status_counter['ALERT']}")

    print("\nProtocols")
    print(f"TCP                : {protocol_counter['TCP']}")
    print(f"UDP                : {protocol_counter['UDP']}")
    print(f"ICMP               : {protocol_counter['ICMP']}")
    print(f"OTHER              : {protocol_counter['OTHER']}")

    print("\nTop Source IPs")

    if source_counter:
        for ip, count in source_counter.most_common(5):
            print(f"{ip:20} {count}")
    else:
        print("No data available")

    print("\nTop Destination IPs")

    if destination_counter:
        for ip, count in destination_counter.most_common(5):
            print(f"{ip:20} {count}")
    else:
        print("No data available")

    print("\nDetected Attacks")

    if attack_counter:
        for attack, count in attack_counter.items():
            print(f"{attack:20} {count}")
    else:
        print("None")

    print("\nOverall Risk")
    print(calculate_risk())

    print("=" * 60)


# ==================================================
# Summary Trigger
# ==================================================

def should_print_summary():
    """
    Returns True whenever the configured summary
    interval has been reached.
    """

    if total_packets == 0:
        return False

    return total_packets % SUMMARY_INTERVAL == 0
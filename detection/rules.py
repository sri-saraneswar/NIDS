"""
====================================================
Network Intrusion Detection System (NIDS)
Module : Detection Rules

Description:
Contains all rule-based and behaviour-based
intrusion detection logic.
====================================================
"""

from datetime import datetime

from detection.state import (
    icmp_history,
    port_history
)

from config import (
    ICMP_THRESHOLD,
    ICMP_TIME_WINDOW,
    PORTSCAN_THRESHOLD,
    PORTSCAN_TIME_WINDOW,
    LARGE_PACKET_SIZE,
    SSH_PORT,
    TELNET_PORT,
    FTP_PORTS,
    HTTP_PORT,
    HTTPS_PORT
)


# ==================================================
# Detection Rules
# ==================================================

def detect_rules(packet_info):
    """
    Applies IDS detection rules to a packet.

    Parameters
    ----------
    packet_info : dict

    Returns
    -------
    dict
        Detection result.
    """

    protocol = packet_info["protocol"]
    src_ip = packet_info["src_ip"]
    dst_ip = packet_info["dst_ip"]

    src_port = packet_info["src_port"]
    dst_port = packet_info["dst_port"]

    packet_size = packet_info["packet_size"]

    current_time = datetime.now()

    # --------------------------------------------------
    # Default Result
    # --------------------------------------------------

    result = {

        "status": "NORMAL",

        "severity": "LOW",

        "rule_id": "NIDS-000",

        "attack": "None",

        "reason": "Normal Network Traffic"

    }

    # ==================================================
    # RULE 1 : ICMP Flood Detection
    # ==================================================

    if protocol == "ICMP":

        history = icmp_history[src_ip]

        history.append(current_time)

        while history:

            age = (current_time - history[0]).total_seconds()

            if age > ICMP_TIME_WINDOW:
                history.popleft()
            else:
                break

        if len(history) >= ICMP_THRESHOLD:

            return {

                "status": "ALERT",

                "severity": "HIGH",

                "rule_id": "NIDS-001",

                "attack": "ICMP Flood",

                "reason":
                    f"{len(history)} ICMP packets received "
                    f"from {src_ip} within "
                    f"{ICMP_TIME_WINDOW} seconds"

            }

    # ==================================================
    # RULE 2 : Port Scan Detection
    # ==================================================

    if dst_port is not None:

        history = port_history[src_ip]

        history.append((current_time, dst_port))

        while history:

            age = (current_time - history[0][0]).total_seconds()

            if age > PORTSCAN_TIME_WINDOW:
                history.popleft()
            else:
                break

        unique_ports = {

            port

            for _, port in history

        }

        if len(unique_ports) >= PORTSCAN_THRESHOLD:

            return {

                "status": "ALERT",

                "severity": "HIGH",

                "rule_id": "NIDS-002",

                "attack": "Port Scan",

                "reason":
                    f"{len(unique_ports)} different ports "
                    f"accessed by {src_ip}"

            }

    # ==================================================
    # RULE 3 : Telnet Traffic
    # ==================================================

    if dst_port == TELNET_PORT:

        return {

            "status": "WARNING",

            "severity": "MEDIUM",

            "rule_id": "NIDS-003",

            "attack": "Telnet",

            "reason": "Insecure Telnet Connection"

        }

    # ==================================================
    # RULE 4 : FTP Traffic
    # ==================================================

    if dst_port in FTP_PORTS:

        return {

            "status": "WARNING",

            "severity": "MEDIUM",

            "rule_id": "NIDS-004",

            "attack": "FTP",

            "reason": "FTP Traffic (Plaintext Credentials)"

        }

    # ==================================================
    # RULE 5 : SSH Traffic
    # ==================================================

    if dst_port == SSH_PORT:

        return {

            "status": "INFO",

            "severity": "LOW",

            "rule_id": "NIDS-005",

            "attack": "SSH",

            "reason": "Secure SSH Traffic"

        }

    # ==================================================
    # RULE 6 : HTTP Traffic
    # ==================================================

    if dst_port == HTTP_PORT:

        return {

            "status": "INFO",

            "severity": "LOW",

            "rule_id": "NIDS-006",

            "attack": "HTTP",

            "reason": "HTTP Web Traffic"

        }

    # ==================================================
    # RULE 7 : HTTPS Traffic
    # ==================================================

    if dst_port == HTTPS_PORT:

        return {

            "status": "INFO",

            "severity": "LOW",

            "rule_id": "NIDS-007",

            "attack": "HTTPS",

            "reason": "Encrypted HTTPS Traffic"

        }

    # ==================================================
    # RULE 8 : Broadcast Traffic
    # ==================================================

    if dst_ip.endswith(".255"):

        return {

            "status": "INFO",

            "severity": "LOW",

            "rule_id": "NIDS-008",

            "attack": "Broadcast",

            "reason": "Broadcast Network Traffic"

        }

    # ==================================================
    # RULE 9 : Large Packet Detection
    # ==================================================

    if packet_size > LARGE_PACKET_SIZE:

        return {

            "status": "WARNING",

            "severity": "MEDIUM",

            "rule_id": "NIDS-009",

            "attack": "Large Packet",

            "reason": f"Packet Size = {packet_size} bytes"

        }

    # ==================================================
    # Default Result
    # ==================================================

    return result
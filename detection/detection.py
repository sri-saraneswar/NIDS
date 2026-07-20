"""
====================================================
Network Intrusion Detection System (NIDS)
Module : Detection Engine
Description:
Applies rule-based detection on captured packets.
====================================================
"""


def detect(packet_info):

    status = "NORMAL"
    reason = "No suspicious activity detected"

    protocol = packet_info["protocol"]
    dst_port = packet_info["dst_port"]
    packet_size = packet_info["packet_size"]

    # -------------------------------
    # Rule 1 : ICMP Detection
    # -------------------------------
    if protocol == "ICMP":
        status = "ALERT"
        reason = "ICMP Packet Detected"

    # -------------------------------
    # Rule 2 : Telnet
    # -------------------------------
    elif dst_port == 23:
        status = "ALERT"
        reason = "Telnet Connection Detected"

    # -------------------------------
    # Rule 3 : FTP
    # -------------------------------
    elif dst_port in [20, 21]:
        status = "ALERT"
        reason = "FTP Connection Detected"

    # -------------------------------
    # Rule 4 : SSH
    # -------------------------------
    elif dst_port == 22:
        reason = "SSH Traffic"

    # -------------------------------
    # Rule 5 : HTTP
    # -------------------------------
    elif dst_port == 80:
        reason = "HTTP Traffic"

    # -------------------------------
    # Rule 6 : HTTPS
    # -------------------------------
    elif dst_port == 443:
        reason = "HTTPS Traffic"

    # -------------------------------
    # Rule 7 : Large Packet
    # -------------------------------
    if packet_size > 1500:
        status = "ALERT"
        reason = "Large Packet Detected"

    return status, reason
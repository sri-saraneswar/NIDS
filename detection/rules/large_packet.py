"""
=========================================================
Network Intrusion Detection System (NIDS)

Module : Large Packet Detection

Detects unusually large network packets.

Uses a sliding window to avoid alerting
on every single oversized packet.

=========================================================
"""


from datetime import datetime


from config import (
    LARGE_PACKET_SIZE,
    LARGE_PACKET_THRESHOLD,
    LARGE_PACKET_TIME_WINDOW
)


from detection.state import large_packet_history





def detect_large_packet(packet):
    """
    Detect excessive large packets from a single source.

    Only triggers when a source sends more than
    LARGE_PACKET_THRESHOLD packets exceeding
    LARGE_PACKET_SIZE within the time window.

    Args:
        packet: Packet dictionary with protocol info.

    Returns:
        Attack dict if threshold exceeded, else None.
    """


    packet_size = packet.get(
        "packet_size",
        0
    )


    # Normal sized packet

    if packet_size < LARGE_PACKET_SIZE:
        return None



    src_ip = packet["src_ip"]

    dst_ip = packet["dst_ip"]


    now = datetime.now()


    history = large_packet_history[src_ip]



    # Remove expired entries

    history[:] = [
        timestamp
        for timestamp in history
        if (
            now - timestamp
        ).total_seconds()
        <= LARGE_PACKET_TIME_WINDOW
    ]



    # Add current packet

    history.append(now)



    # Below threshold

    if len(history) < LARGE_PACKET_THRESHOLD:
        return None



    return {


        "attack_key": (
            src_ip,
            "LARGE_PACKET"
        ),


        "attack_type":
            "Large Packet Flood",


        "severity":
            "LOW",


        "source_ip":
            src_ip,


        "destination_ip":
            dst_ip,


        "details": {

            "avg_packet_size":
                packet_size,

            "large_packets":
                len(history),

            "threshold":
                LARGE_PACKET_SIZE,

            "time_window":
                LARGE_PACKET_TIME_WINDOW

        }

    }
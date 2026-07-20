"""
====================================================
Network Intrusion Detection System (NIDS)
Module : Packet Capture

Description:
Captures live network packets from the selected
network interface, extracts important information,
and forwards it to the Analyzer Module.
====================================================
"""

from datetime import datetime

from scapy.all import (
    sniff,
    IP,
    TCP,
    UDP,
    ICMP,
    get_if_list
)

from analyzer.analyzer import analyze_packet
from config import STORE_PACKETS


# ==================================================
# Display Available Network Interfaces
# ==================================================

def display_interfaces():
    """
    Displays all available network interfaces.
    """

    interfaces = get_if_list()

    print("\nAvailable Network Interfaces\n")

    for index, interface in enumerate(interfaces, start=1):
        print(f"{index}. {interface}")

    return interfaces


# ==================================================
# Select Network Interface
# ==================================================

def select_interface():
    """
    Allows the user to select a network interface.
    """

    interfaces = display_interfaces()

    while True:

        try:
            choice = int(input("\nSelect Interface : "))

            if 1 <= choice <= len(interfaces):
                return interfaces[choice - 1]

            print("Invalid selection. Please try again.")

        except ValueError:
            print("Please enter a valid number.")


# ==================================================
# Process Captured Packet
# ==================================================

def process_packet(packet):
    """
    Extracts useful information from each captured packet
    and sends it to the Analyzer Module.
    """

    # Ignore non-IP packets
    if IP not in packet:
        return

    timestamp = datetime.now()

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    protocol = "OTHER"

    src_port = None
    dst_port = None

    # TCP Packet
    if TCP in packet:

        protocol = "TCP"

        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    # UDP Packet
    elif UDP in packet:

        protocol = "UDP"

        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    # ICMP Packet
    elif ICMP in packet:

        protocol = "ICMP"

    packet_info = {

        "timestamp": timestamp,

        "src_ip": src_ip,

        "dst_ip": dst_ip,

        "protocol": protocol,

        "src_port": src_port,

        "dst_port": dst_port,

        "packet_size": len(packet)

    }

    # Send packet to analyzer
    analyze_packet(packet_info)


# ==================================================
# Start Packet Capture
# ==================================================

def start_capture():
    """
    Starts live packet capture using Scapy.
    """

    interface = select_interface()

    print("\n")
    print("=" * 60)
    print("Starting Network IDS")
    print(f"Listening Interface : {interface}")
    print("Press CTRL + C to stop")
    print("=" * 60)

    try:

        sniff(
            iface=interface,
            prn=process_packet,
            store=STORE_PACKETS
        )

    except KeyboardInterrupt:

        print("\n")
        print("=" * 60)
        print("Stopping Packet Capture...")
        print("Thank you for using the NIDS.")
        print("=" * 60)

    except Exception as error:

        print("\nAn error occurred while capturing packets.")
        print(f"Error: {error}")
        
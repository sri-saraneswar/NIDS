"""
====================================================
Network Intrusion Detection System (NIDS)
Module : Packet Capture
Description:
Captures live network packets, extracts important
information and forwards it to the Analyzer Module.
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
from console.console_manager import display_startup
from config import STORE_PACKETS


# ==================================================
# Display Available Interfaces
# ==================================================

def display_interfaces():

    interfaces = get_if_list()

    print("\nAvailable Network Interfaces\n")

    for index, interface in enumerate(interfaces, start=1):

        print(f"{index}. {interface}")

    return interfaces


# ==================================================
# Select Interface
# ==================================================

def select_interface():

    interfaces = display_interfaces()

    while True:

        try:

            choice = int(input("\nSelect Interface : "))

            if 1 <= choice <= len(interfaces):

                return interfaces[choice - 1]

            print("Invalid selection.")

        except ValueError:

            print("Please enter a valid number.")


# ==================================================
# Process Captured Packet
# ==================================================

def process_packet(packet):

    # Ignore non-IP packets
    if IP not in packet:
        return

    timestamp = datetime.now()

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    protocol = "OTHER"

    src_port = None
    dst_port = None

    if TCP in packet:

        protocol = "TCP"

        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif UDP in packet:

        protocol = "UDP"

        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

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

    # Send packet to Analyzer
    analyze_packet(packet_info)


# ==================================================
# Start Packet Capture
# ==================================================

def start_capture():
    """
    Starts live packet capture using Scapy.
    """

    interface = select_interface()

    # Display startup screen
    display_startup(interface)

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
"""
====================================================
Network Intrusion Detection System (NIDS)
Module      : Packet Capture
Description :
Captures network packets, extracts important
information, and forwards it to the Analyzer Module.
====================================================
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
from datetime import datetime

from analyzer.analyzer import analyze_packet

# Packet counter
packet_count = 0


def process_packet(packet):
    """
    Extracts required information from each captured packet
    and forwards it to the analyzer.
    """

    global packet_count

    # Ignore non-IP packets
    if IP not in packet:
        return

    packet_count += 1

    timestamp = datetime.now()

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    packet_size = len(packet)

    protocol = "OTHER"
    src_port = None
    dst_port = None

    # Determine protocol and ports
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

    # Store packet details
    packet_info = {
        "packet_number": packet_count,
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
        "packet_size": packet_size
    }

    # Display packet information
    print("\n==================================================")
    print(f"              PACKET #{packet_count}")
    print("==================================================")
    print(f"Time        : {timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Source IP   : {src_ip}")
    print(f"Destination : {dst_ip}")
    print(f"Protocol    : {protocol}")

    if src_port is not None:
        print(f"Source Port : {src_port}")

    if dst_port is not None:
        print(f"Dest Port   : {dst_port}")

    print(f"Packet Size : {packet_size} bytes")
    print("==================================================")

    # Send packet information to Analyzer Module
    analyze_packet(packet_info)


def start_capture():
    """
    Displays available interfaces and starts packet capture.
    """

    print("\n==================================================")
    print("     NETWORK INTRUSION DETECTION SYSTEM")
    print("           Packet Capture Module")
    print("==================================================")

    interfaces = get_if_list()

    print("\nAvailable Network Interfaces\n")

    for index, interface in enumerate(interfaces, start=1):
        print(f"{index}. {interface}")

    # Get valid interface selection
    while True:
        try:
            choice = int(input("\nSelect Interface Number : "))

            if 1 <= choice <= len(interfaces):
                break

            print("Invalid selection. Please try again.")

        except ValueError:
            print("Please enter a valid number.")

    selected_interface = interfaces[choice - 1]

    print(f"\nListening on interface: {selected_interface}")
    print("Press CTRL + C to stop capturing.\n")

    try:
        sniff(
            iface=selected_interface,
            prn=process_packet,
            store=False
        )

    except KeyboardInterrupt:
        print("\n\nPacket capture stopped successfully.")
"""
====================================================
Network Intrusion Detection System (NIDS)
Module      : Packet Capture
Description : Captures packets from the selected
              network interface and forwards
              packet information to the Analyzer.
====================================================
"""

from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list

from analyzer.analyzer import analyze_packet

# Packet counter for display
packet_count = 0


def process_packet(packet):
    """
    Process each captured packet and extract
    useful information for the analyzer.
    """

    global packet_count

    # Ignore packets without IP layer
    if IP not in packet:
        return

    packet_count += 1

    # Timestamp
    timestamp = datetime.now()

    # Basic IP information
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    packet_size = len(packet)

    # Default values
    protocol = "OTHER"
    src_port = None
    dst_port = None

    # Detect protocol and ports
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

    # Store packet information
    packet_info = {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
        "packet_size": packet_size
    }

    # Display packet in readable format
    print("\n" + "=" * 55)
    print(f"PACKET #{packet_count}")
    print("=" * 55)
    print(f"Time        : {timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Source IP   : {src_ip}")
    print(f"Destination : {dst_ip}")
    print(f"Protocol    : {protocol}")

    if src_port is not None:
        print(f"Source Port : {src_port}")

    if dst_port is not None:
        print(f"Dest Port   : {dst_port}")

    print(f"Packet Size : {packet_size} bytes")
    print("=" * 55)

    # Send packet information to analyzer
    analyze_packet(packet_info)


def start_capture():
    """
    Display available interfaces, allow user selection,
    and start packet capture.
    """

    print("\n" + "=" * 55)
    print("   NETWORK INTRUSION DETECTION SYSTEM (NIDS)")
    print("             Packet Capture Module")
    print("=" * 55)

    # Get available interfaces
    interfaces = get_if_list()

    print("\nAvailable Interfaces:\n")

    for i, iface in enumerate(interfaces, start=1):
        print(f"{i}. {iface}")

    # User selects interface
    while True:
        try:
            choice = int(input("\nSelect Interface Number : "))

            if 1 <= choice <= len(interfaces):
                break
            else:
                print("Invalid selection. Please choose a valid number.")

        except ValueError:
            print("Please enter a numeric value.")

    selected_interface = interfaces[choice - 1]

    print("\n" + "=" * 55)
    print(f"Listening on interface: {selected_interface}")
    print("Press CTRL + C to stop capturing packets")
    print("=" * 55)

    try:
        sniff(
            iface=selected_interface,
            prn=process_packet,
            store=False
        )

    except KeyboardInterrupt:
        print("\n\nPacket capture stopped by user.")
        print(f"Total packets captured: {packet_count}")
        print("Exiting NIDS Packet Capture Module.")
"""
====================================================
Network Intrusion Detection System (NIDS)
Module : Packet Capture
Author : Team
Description:
Captures live packets using Scapy and extracts
basic packet information.
====================================================
"""

# Import required libraries
from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
from datetime import datetime


# Function to process every captured packet
def process_packet(packet):

    # Check whether the packet contains an IP layer
    if IP in packet:

        # Current timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Extract IP information
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        packet_size = len(packet)

        print("\n" + "=" * 60)
        print(f"Time           : {timestamp}")
        print(f"Source IP      : {src_ip}")
        print(f"Destination IP : {dst_ip}")
        print(f"Packet Size    : {packet_size} Bytes")

        # Check protocol
        if TCP in packet:
            print("Protocol       : TCP")
            print(f"Source Port    : {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")

        elif UDP in packet:
            print("Protocol       : UDP")
            print(f"Source Port    : {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")

        elif ICMP in packet:
            print("Protocol       : ICMP")

        else:
            print("Protocol       : Other")

        print("=" * 60)


# ---------------------- Main Program ----------------------

print("\nAvailable Network Interfaces:\n")

interfaces = get_if_list()

for index, iface in enumerate(interfaces):
    print(f"{index + 1}. {iface}")

try:
    choice = int(input("\nEnter the interface number: "))

    if choice < 1 or choice > len(interfaces):
        print("Invalid interface number.")
        exit()

    selected_interface = interfaces[choice - 1]

    print("\nStarting Packet Capture...")
    print(f"Listening on interface: {selected_interface}")
    print("Press Ctrl + C to stop.\n")

    sniff(
        iface=selected_interface,
        prn=process_packet,
        store=False
    )

except KeyboardInterrupt:
    print("\nPacket capture stopped.")

except ValueError:
    print("Please enter a valid number.")
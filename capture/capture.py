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
from scapy.all import sniff, IP, TCP, UDP, ICMP
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

        # Convert protocol number into protocol name
        protocol_map = {
            1: "ICMP",
            6: "TCP",
            17: "UDP"
        }

        protocol = protocol_map.get(packet[IP].proto, "OTHER")

        # Default values
        src_port = "-"
        dst_port = "-"

        # TCP Packet
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        # UDP Packet
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        # ICMP Packet
        elif ICMP in packet:
            src_port = "-"
            dst_port = "-"

        # Display packet information
        print("=" * 60)
        print(f"Time             : {timestamp}")
        print(f"Source IP        : {src_ip}")
        print(f"Destination IP   : {dst_ip}")
        print(f"Protocol         : {protocol}")
        print(f"Source Port      : {src_port}")
        print(f"Destination Port : {dst_port}")
        print(f"Packet Size      : {packet_size} Bytes")
        print("=" * 60)


# Function to start packet capture
def start_capture():

    print("\n==============================================")
    print("      Network Intrusion Detection System")
    print("          Packet Capture Started")
    print(" Press CTRL + C to Stop Capturing Packets")
    print("==============================================\n")

    sniff(
        iface="vboxnet0",      # Host-Only Interface
        prn=process_packet,    # Function to process each packet
        store=False            # Don't store packets in memory
    )


# Main Function
if __name__ == "__main__":
    start_capture()

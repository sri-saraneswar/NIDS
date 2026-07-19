<<<<<<< HEAD
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
=======


from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP


>>>>>>> 17d75bf58e310396a36e28a4d1d1437e5d6298fb
def process_packet(packet):
    """
    Process each captured packet and display its details.
    """

<<<<<<< HEAD
    # Check whether the packet contains an IP layer
    if IP in packet:

        # -------------------------------
        # Basic Packet Information
        # -------------------------------

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        packet_size = len(packet)

        # Convert protocol number into protocol name
=======
    # Check if packet contains an IP layer
    if IP in packet:

        # Extract IP information
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        packet_size = len(packet)

        # Convert protocol numbers into names
>>>>>>> 17d75bf58e310396a36e28a4d1d1437e5d6298fb
        protocol_map = {
            1: "ICMP",
            6: "TCP",
            17: "UDP"
        }

<<<<<<< HEAD
        protocol = protocol_map.get(packet[IP].proto, "OTHER")

        # Default values
        src_port = "-"
        dst_port = "-"

        # -------------------------------
        # TCP Packet
        # -------------------------------
=======
        protocol_name = protocol_map.get(protocol, str(protocol))

        # Default port values
        src_port = "-"
        dst_port = "-"

        # Extract TCP ports
>>>>>>> 17d75bf58e310396a36e28a4d1d1437e5d6298fb
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

<<<<<<< HEAD
        # -------------------------------
        # UDP Packet
        # -------------------------------
=======
        # Extract UDP ports
>>>>>>> 17d75bf58e310396a36e28a4d1d1437e5d6298fb
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

<<<<<<< HEAD
        # -------------------------------
        # ICMP Packet
        # -------------------------------
        elif ICMP in packet:
            src_port = "-"
            dst_port = "-"

        # -------------------------------
        # Display Packet Information
        # -------------------------------

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
=======
        # Display packet information
        print("\n" + "=" * 60)
        print("Packet Captured")
        print("=" * 60)
        print(f"Source IP        : {src_ip}")
        print(f"Destination IP   : {dst_ip}")
        print(f"Protocol         : {protocol_name}")
        print(f"Source Port      : {src_port}")
        print(f"Destination Port : {dst_port}")
        print(f"Packet Size      : {packet_size} bytes")
        print("=" * 60)


>>>>>>> 17d75bf58e310396a36e28a4d1d1437e5d6298fb
def start_capture():
    """
    Start live packet capture.
    """

<<<<<<< HEAD
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
=======
    print("=" * 60)
    print("      NETWORK IDS - PHASE 2 : PACKET CAPTURE")
    print("=" * 60)
    print("Capturing live network packets...")
    print("Press CTRL + C to stop.\n")

    sniff(
        prn=process_packet,
        store=False
    )
>>>>>>> 17d75bf58e310396a36e28a4d1d1437e5d6298fb

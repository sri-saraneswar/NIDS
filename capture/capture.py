

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP


def process_packet(packet):
    """
    Process each captured packet and display its details.
    """

    # Check if packet contains an IP layer
    if IP in packet:

        # Extract IP information
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        packet_size = len(packet)

        # Convert protocol numbers into names
        protocol_map = {
            1: "ICMP",
            6: "TCP",
            17: "UDP"
        }

        protocol_name = protocol_map.get(protocol, str(protocol))

        # Default port values
        src_port = "-"
        dst_port = "-"

        # Extract TCP ports
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        # Extract UDP ports
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

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


def start_capture():
    """
    Start live packet capture.
    """

    print("=" * 60)
    print("      NETWORK IDS - PHASE 2 : PACKET CAPTURE")
    print("=" * 60)
    print("Capturing live network packets...")
    print("Press CTRL + C to stop.\n")

    sniff(
        prn=process_packet,
        store=False
    )
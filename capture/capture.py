# Import Scapy modules required for packet capturing and protocol analysis
from scapy.all import sniff, IP, TCP, UDP, ICMP

# Function to process each captured packet
def process_packet(packet):

    # Check if the packet contains an IP layer
    if IP in packet:

        # Get the source IP address
        src_ip = packet[IP].src

        # Get the destination IP address
        dst_ip = packet[IP].dst

        # Get the protocol number (TCP/UDP/ICMP)
        protocol = packet[IP].proto

        # Calculate the total packet size in bytes
        packet_size = len(packet)

        # Print a separator for readability
        print("=" * 40)

        # Display the source IP address
        print("Source IP      :", src_ip)

        # Display the destination IP address
        print("Destination IP :", dst_ip)

        # Display the protocol number
        print("Protocol       :", protocol)

        # Display the packet size
        print("Packet Size    :", packet_size, "bytes")

        # Check if the packet is TCP
        if TCP in packet:

            # Display the TCP destination port
            print("TCP Port :", packet[TCP].dport)

        # Check if the packet is UDP
        elif UDP in packet:

            # Display the UDP destination port
            print("UDP Port :", packet[UDP].dport)

        # Check if the packet is ICMP
        elif ICMP in packet:

            # Display that it is an ICMP packet
            print("ICMP Packet")

# Function to start packet capturing
def start_capture():

    # Display a startup message
    print("Starting IDS Packet Capture...")

    # Capture packets continuously and process each packet
    sniff(prn=process_packet, store=False)
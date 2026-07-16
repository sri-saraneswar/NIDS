from scapy.all import sniff, IP, TCP, UDP, ICMP

def process_packet(packet):

    if IP in packet:

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        packet_size = len(packet)

        print("=" * 40)
        print(f"Source IP      : {src_ip}")
        print(f"Destination IP : {dst_ip}")
        print(f"Protocol       : {protocol}")
        print(f"Packet Size    : {packet_size} bytes")

        if TCP in packet:
            print(f"TCP Port : {packet[TCP].dport}")

        elif UDP in packet:
            print(f"UDP Port : {packet[UDP].dport}")

        elif ICMP in packet:
            print("ICMP Packet")

def start_capture():
    print("Starting IDS Packet Capture...")
    sniff(prn=process_packet, store=False)
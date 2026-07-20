"""
====================================================
Network Intrusion Detection System (NIDS)
Module : Packet Capture
Description:
Captures packets and forwards packet
information to the Analyzer Module.
====================================================
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
from datetime import datetime

from analyzer.analyzer import analyze_packet


def process_packet(packet):

    if IP not in packet:
        return

    timestamp = datetime.now()

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    packet_size = len(packet)

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

        "packet_size": packet_size

    }

    print("\n--------------------------------------------")
    print(packet_info)
    print("--------------------------------------------")

    analyze_packet(packet_info)


print("\nAvailable Interfaces\n")

interfaces = get_if_list()

for i, iface in enumerate(interfaces):

    print(f"{i+1}. {iface}")

choice = int(input("\nSelect Interface : "))

selected_interface = interfaces[choice-1]

print(f"\nListening on {selected_interface}...\n")

sniff(

    iface=selected_interface,

    prn=process_packet,

    store=False

)
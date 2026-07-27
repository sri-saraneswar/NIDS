"""
====================================================
Network Intrusion Detection System (NIDS)

Module : Packet Capture

Captures live network traffic using Scapy
and forwards packet information to Analyzer
via a thread-safe Queue.

Features:
    Concurrent Multi-Interface Sniffing
    Thread-Safe Packet Queue
    Universal Protocol Extraction
    Promiscuous mode capture

====================================================
"""


import queue
import threading
from datetime import datetime


from scapy.all import (
    sniff,
    Ether,
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP,
    ARP,
    DNS,
    get_if_list
)


from analyzer.analyzer import analyze_packet



# ==================================================
# Globals
# ==================================================


_stop_flag = False

packet_queue = queue.Queue()

_capture_threads = []
_worker_thread = None



# ==================================================
# Show Available Interfaces
# ==================================================


def show_interfaces():
    """
    Display available network interfaces
    and let the user select one or ALL.

    Returns:
        String (interface name) or "ALL"
    """

    interfaces = get_if_list()


    print("\n")

    print("=" * 60)

    print("  Available Network Interfaces")

    print("=" * 60)


    print("  0. Monitor ALL Interfaces")

    for index, interface in enumerate(
        interfaces,
        start=1
    ):

        print(
            f"  {index}. {interface}"
        )


    print()


    while True:

        try:

            choice = int(
                input(
                    "  Select Interface : "
                )
            )

            if choice == 0:
                return "ALL"

            if 1 <= choice <= len(interfaces):

                return interfaces[choice - 1]

            else:

                print(
                    "  Invalid Interface"
                )

        except ValueError:

            print(
                "  Enter a valid number"
            )





# ==================================================
# Extract Universal Packet Information
# ==================================================


def process_packet(packet, interface):
    """
    Extract metadata from ANY raw Scapy packet
    and push it to the queue.

    Args:
        packet: Raw Scapy packet object.
        interface: Name of the interface it was captured on.
    """

    if _stop_flag:
        return


    try:

        packet_info = {
            "timestamp": datetime.now(),
            "interface": interface,
            "src_ip": "Unknown",
            "dst_ip": "Unknown",
            "src_port": 0,
            "dst_port": 0,
            "protocol": "Raw",
            "packet_size": len(packet),
            "flags": ""
        }

        
        # 1. Network Layer (IP/IPv6/ARP/MAC)
        if IP in packet:
            packet_info["src_ip"] = packet[IP].src
            packet_info["dst_ip"] = packet[IP].dst
            packet_info["protocol"] = "IPv4"
            
        elif IPv6 in packet:
            packet_info["src_ip"] = packet[IPv6].src
            packet_info["dst_ip"] = packet[IPv6].dst
            packet_info["protocol"] = "IPv6"
            
        elif ARP in packet:
            packet_info["src_ip"] = packet[ARP].psrc
            packet_info["dst_ip"] = packet[ARP].pdst
            packet_info["protocol"] = "ARP"
            
        elif Ether in packet:
            packet_info["src_ip"] = packet[Ether].src
            packet_info["dst_ip"] = packet[Ether].dst
            packet_info["protocol"] = "Ethernet"


        # 2. Transport Layer (TCP/UDP/ICMP)
        if TCP in packet:
            packet_info["protocol"] = "TCP"
            packet_info["src_port"] = packet[TCP].sport
            packet_info["dst_port"] = packet[TCP].dport
            packet_info["flags"] = str(packet[TCP].flags)
            
        elif UDP in packet:
            packet_info["protocol"] = "UDP"
            packet_info["src_port"] = packet[UDP].sport
            packet_info["dst_port"] = packet[UDP].dport
            
        elif ICMP in packet:
            packet_info["protocol"] = "ICMP"
            packet_info["icmp_type"] = packet[ICMP].type
            packet_info["icmp_code"] = packet[ICMP].code


        # 3. Application Layer Overrides
        if DNS in packet:
            packet_info["protocol"] = "DNS"
            
        if TCP in packet:
            if packet[TCP].sport == 80 or packet[TCP].dport == 80:
                packet_info["protocol"] = "HTTP"
            elif packet[TCP].sport == 443 or packet[TCP].dport == 443:
                packet_info["protocol"] = "HTTPS"
            elif packet[TCP].sport == 22 or packet[TCP].dport == 22:
                packet_info["protocol"] = "SSH"
            elif packet[TCP].sport == 21 or packet[TCP].dport == 21:
                packet_info["protocol"] = "FTP"


        # 4. Push to Thread-Safe Queue
        packet_queue.put(packet_info)


    except Exception as error:
        pass





# ==================================================
# Analyzer Worker Thread
# ==================================================


def _analyzer_worker():
    """
    Background daemon thread that continuously
    pulls packets from the Queue and feeds
    them to the Detection Analyzer.
    """
    
    while not _stop_flag:
        try:
            # Block for 1 second so we can check stop_flag
            packet_info = packet_queue.get(timeout=1.0)
            analyze_packet(packet_info)
            packet_queue.task_done()
        except queue.Empty:
            continue
        except Exception:
            pass





# ==================================================
# Start Capture
# ==================================================


def start_capture(interfaces):
    """
    Begin concurrent sniffing on all given interfaces.
    Starts the analyzer queue worker.

    Args:
        interfaces: A single interface string, or a list of interfaces, or "ALL".
    """

    global _stop_flag, _worker_thread, _capture_threads
    _stop_flag = False
    _capture_threads = []


    # 1. Start Analyzer Worker
    _worker_thread = threading.Thread(
        target=_analyzer_worker,
        daemon=True,
        name="AnalyzerWorker"
    )
    _worker_thread.start()


    # 2. Determine Interfaces
    if interfaces == "ALL":
        target_interfaces = get_if_list()
    elif isinstance(interfaces, str):
        target_interfaces = [interfaces]
    else:
        target_interfaces = interfaces


    # 3. Spawn Sniff Threads
    try:

        for iface in target_interfaces:
            
            thread = threading.Thread(
                target=sniff,
                kwargs={
                    "iface": iface,
                    "prn": lambda p, i=iface: process_packet(p, i),
                    "store": False,
                    "promisc": True,
                    "stop_filter": lambda p: _stop_flag
                },
                daemon=True,
                name=f"Sniff-{iface}"
            )
            
            _capture_threads.append(thread)
            thread.start()

        
        # Block main thread until interrupted
        for thread in _capture_threads:
            while thread.is_alive() and not _stop_flag:
                thread.join(timeout=1.0)


    except KeyboardInterrupt:

        raise

    except Exception as error:

        print(
            f"\n[CAPTURE ERROR] {error}"
        )





# ==================================================
# Stop Capture
# ==================================================


def stop_capture():
    """Set the stop flag to terminate sniffing."""

    global _stop_flag

    _stop_flag = True
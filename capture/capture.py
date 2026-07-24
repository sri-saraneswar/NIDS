"""
====================================================
Network Intrusion Detection System (NIDS)

Module : Packet Capture

Captures live network traffic using Scapy
and forwards packet information to Analyzer.

Features:
    Interface selection
    Packet extraction (IP, TCP, UDP, ICMP, ARP)
    Promiscuous mode capture
    Graceful stop via flag

====================================================
"""


from datetime import datetime


from scapy.all import (

    sniff,

    IP,

    TCP,

    UDP,

    ICMP,

    ARP,

    get_if_list

)


from analyzer.analyzer import analyze_packet



# ==================================================
# Stop Flag
# ==================================================


_stop_flag = False



# ==================================================
# Show Available Interfaces
# ==================================================


def show_interfaces():
    """
    Display available network interfaces
    and let the user select one.

    Returns:
        Selected interface name string.
    """

    interfaces = get_if_list()


    print("\n")

    print("=" * 60)

    print("  Available Network Interfaces")

    print("=" * 60)


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
# Extract Packet Information
# ==================================================


def process_packet(packet):
    """
    Extract metadata from a raw Scapy packet
    and forward it to the analyzer.

    Handles:
        ARP packets
        IP packets (TCP, UDP, ICMP)

    Args:
        packet: Raw Scapy packet object.
    """

    if _stop_flag:
        return


    try:


        packet_info = {

            "timestamp":
                datetime.now(),

            "src_ip":
                "",

            "dst_ip":
                "",

            "src_port":
                0,

            "dst_port":
                0,

            "protocol":
                "",

            "packet_size":
                len(packet),

            "flags":
                ""

        }



        # ==========================================
        # ARP Traffic
        # ==========================================

        if ARP in packet:

            packet_info["protocol"] = "ARP"

            packet_info["src_ip"] = packet[ARP].psrc

            packet_info["dst_ip"] = packet[ARP].pdst

            analyze_packet(
                packet_info
            )

            return



        # ==========================================
        # IP Traffic
        # ==========================================

        if IP not in packet:

            return


        packet_info["src_ip"] = packet[IP].src

        packet_info["dst_ip"] = packet[IP].dst



        # ==========================================
        # TCP
        # ==========================================

        if TCP in packet:

            packet_info["protocol"] = "TCP"

            packet_info["src_port"] = packet[TCP].sport

            packet_info["dst_port"] = packet[TCP].dport

            # Required for:
            #
            # SYN Scan
            # FIN Scan
            # NULL Scan
            # XMAS Scan

            packet_info["flags"] = str(
                packet[TCP].flags
            )



        # ==========================================
        # UDP
        # ==========================================

        elif UDP in packet:

            packet_info["protocol"] = "UDP"

            packet_info["src_port"] = packet[UDP].sport

            packet_info["dst_port"] = packet[UDP].dport



        # ==========================================
        # ICMP
        # ==========================================

        elif ICMP in packet:

            packet_info["protocol"] = "ICMP"

            packet_info["icmp_type"] = packet[ICMP].type

            packet_info["icmp_code"] = packet[ICMP].code


        else:

            return



        # ==========================================
        # Send to Analyzer
        # ==========================================

        analyze_packet(
            packet_info
        )



    except Exception as error:

        print(
            f"\n[CAPTURE ERROR] {error}"
        )





# ==================================================
# Start Capture
# ==================================================


def start_capture(interface):
    """
    Begin sniffing packets on the given interface.

    Runs until KeyboardInterrupt is raised
    or the stop flag is set.

    Args:
        interface: Network interface name to sniff on.
    """

    global _stop_flag

    _stop_flag = False


    try:

        sniff(

            iface=interface,

            prn=process_packet,

            store=False,

            promisc=True,

            stop_filter=lambda p: _stop_flag

        )


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
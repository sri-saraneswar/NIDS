"""
====================================================
Network Intrusion Detection System (NIDS)

Module : Packet Capture

Description:
<<<<<<< HEAD
Captures live network packets from the selected
network interface, extracts important information,
and forwards it to the Analyzer Module.
=======
Captures live network packets using Scapy,
extracts required packet information,
and forwards packets to Analyzer Module.

>>>>>>> e73906848d73f55ab94d301e6455a8cf66336400
====================================================
"""


from datetime import datetime


from scapy.all import (
    sniff,
    IP,
    TCP,
    UDP,
    ICMP,
    get_if_list
)


from analyzer.analyzer import analyze_packet
<<<<<<< HEAD
from config import STORE_PACKETS


# ==================================================
# Display Available Network Interfaces
=======


from console.console_manager import display_startup


from config import (
    STORE_PACKETS,
    DEFAULT_INTERFACE
)



# ==================================================
# Display Network Interfaces
>>>>>>> e73906848d73f55ab94d301e6455a8cf66336400
# ==================================================

def display_interfaces():
    """
    Displays all available network interfaces.
    """

    interfaces = get_if_list()


    print("\nAvailable Network Interfaces\n")

<<<<<<< HEAD
    for index, interface in enumerate(interfaces, start=1):
        print(f"{index}. {interface}")
=======

    for index, interface in enumerate(
        interfaces,
        start=1
    ):

        print(
            f"{index}. {interface}"
        )

>>>>>>> e73906848d73f55ab94d301e6455a8cf66336400

    return interfaces




# ==================================================
# Select Network Interface
# ==================================================

def select_interface():
    """
    Allows the user to select a network interface.
    """

    if DEFAULT_INTERFACE:

        return DEFAULT_INTERFACE



    interfaces = display_interfaces()



    while True:


        try:
<<<<<<< HEAD
            choice = int(input("\nSelect Interface : "))

            if 1 <= choice <= len(interfaces):
                return interfaces[choice - 1]

            print("Invalid selection. Please try again.")

        except ValueError:
            print("Please enter a valid number.")
=======


            choice = int(
                input(
                    "\nSelect Interface : "
                )
            )


            if 1 <= choice <= len(interfaces):

                return interfaces[choice-1]


            else:

                print(
                    "Invalid Selection"
                )


        except ValueError:


            print(
                "Enter a valid number"
            )



>>>>>>> e73906848d73f55ab94d301e6455a8cf66336400


# ==================================================
# Packet Processing
# ==================================================

def process_packet(packet):
    """
    Extracts useful information from each captured packet
    and sends it to the Analyzer Module.
    """


    # Ignore non-IP packets

    if IP not in packet:

        return



    timestamp = datetime.now()



    src_ip = packet[IP].src

    dst_ip = packet[IP].dst



    protocol = "OTHER"



    src_port = None

    dst_port = None

<<<<<<< HEAD
    # TCP Packet
=======



    # -----------------------------
    # TCP
    # -----------------------------

>>>>>>> e73906848d73f55ab94d301e6455a8cf66336400
    if TCP in packet:


        protocol = "TCP"


        src_port = packet[TCP].sport

        dst_port = packet[TCP].dport

<<<<<<< HEAD
    # UDP Packet
=======



    # -----------------------------
    # UDP
    # -----------------------------

>>>>>>> e73906848d73f55ab94d301e6455a8cf66336400
    elif UDP in packet:


        protocol = "UDP"


        src_port = packet[UDP].sport

        dst_port = packet[UDP].dport

<<<<<<< HEAD
    # ICMP Packet
=======



    # -----------------------------
    # ICMP
    # -----------------------------

>>>>>>> e73906848d73f55ab94d301e6455a8cf66336400
    elif ICMP in packet:


        protocol = "ICMP"




    packet_info = {


        "timestamp":
            timestamp,


        "src_ip":
            src_ip,


        "dst_ip":
            dst_ip,


        "protocol":
            protocol,


        "src_port":
            src_port,


        "dst_port":
            dst_port,


        "packet_size":
            len(packet)

    }

<<<<<<< HEAD
    # Send packet to analyzer
    analyze_packet(packet_info)
=======


    # Send packet for analysis

    analyze_packet(
        packet_info
    )



>>>>>>> e73906848d73f55ab94d301e6455a8cf66336400


# ==================================================
# Start Capture
# ==================================================

def start_capture():


    interface = select_interface()

<<<<<<< HEAD
    print("\n")
    print("=" * 60)
    print("Starting Network IDS")
    print(f"Listening Interface : {interface}")
    print("Press CTRL + C to stop")
    print("=" * 60)
=======
>>>>>>> e73906848d73f55ab94d301e6455a8cf66336400


    display_startup(
        interface
    )


<<<<<<< HEAD
        print("\n")
        print("=" * 60)
        print("Stopping Packet Capture...")
        print("Thank you for using the NIDS.")
        print("=" * 60)

    except Exception as error:

        print("\nAn error occurred while capturing packets.")
        print(f"Error: {error}")
        
=======

    sniff(

        iface=interface,

        prn=process_packet,

        store=STORE_PACKETS

    )
>>>>>>> e73906848d73f55ab94d301e6455a8cf66336400

"""
====================================================
Network Intrusion Detection System (NIDS)

Module : Packet Capture

Captures live network traffic and forwards
packet information to Analyzer.

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



from session.session_manager import (

    start_session,

    stop_session,

    get_session_summary,

    get_attack_summary

)



from database.database import create_database



from console.console_manager import (

    display_session_summary,

    display_attack_history

)





# ==================================================
# Show Interfaces
# ==================================================

def show_interfaces():


    interfaces = get_if_list()



    print("\n")

    print("=" * 60)

    print("Available Network Interfaces")

    print("=" * 60)



    for index, interface in enumerate(

        interfaces,

        start=1

    ):

        print(

            f"{index}. {interface}"

        )



    print()



    while True:


        try:


            choice = int(

                input(

                    "Select Interface : "

                )

            )



            if 1 <= choice <= len(interfaces):


                return interfaces[choice-1]



            else:


                print(

                    "Invalid Interface"

                )



        except ValueError:


            print(

                "Enter a valid number"

            )







# ==================================================
# Extract Packet Information
# ==================================================

def process_packet(packet):


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

            "\n[CAPTURE ERROR]",

            error

        )








# ==================================================
# Start Capture
# ==================================================

def start_capture():


    # Initialize DB

    create_database()



    interface = show_interfaces()



    start_session()





    print("\n")

    print("=" * 65)

    print("NETWORK INTRUSION DETECTION SYSTEM")

    print("=" * 65)



    print(

        f"Listening Interface : {interface}"

    )


    print(

        "Promiscuous Mode    : ENABLED"

    )


    print(

        "Press CTRL + C to stop"

    )


    print("=" * 65)







    try:



        sniff(


            iface=interface,



            prn=process_packet,



            store=False,



            promisc=True


        )






    except KeyboardInterrupt:



        print("\n")

        print(

            "Stopping IDS..."

        )



        stop_session()



        print("\n")



        display_session_summary(

            get_session_summary()

        )



        display_attack_history(

            get_attack_summary()

        )
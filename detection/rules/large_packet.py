"""
=========================================================
Network Intrusion Detection System (NIDS)

Module : Large Packet Detection

Detects unusually large network packets.

=========================================================
"""


from config import LARGE_PACKET_SIZE





# =====================================================
# Large Packet Detection
# =====================================================

def detect_large_packet(packet):

    """
    Detect packets larger than configured limit.

    Example:

    Packet Size : 6500 bytes
    Threshold   : 4000 bytes

    Alert Generated
    """



    packet_size = packet.get(

        "packet_size",

        0

    )



    # ---------------------------------------------
    # Normal packet
    # ---------------------------------------------

    if packet_size < LARGE_PACKET_SIZE:

        return None





    # ---------------------------------------------
    # Suspicious packet
    # ---------------------------------------------


    return {


        "attack_key": (

            packet["src_ip"],

            "LARGE_PACKET"

        ),



        "attack_type":

            "Large Packet",



        "severity":

            "LOW",



        "source_ip":

            packet["src_ip"],



        "destination_ip":

            packet["dst_ip"],



        "details": {


            "packet_size":

                packet_size,


            "threshold":

                LARGE_PACKET_SIZE,


            "protocol":

                packet.get(

                    "protocol",

                    "UNKNOWN"

                )

        }

    }
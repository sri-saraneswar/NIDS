"""
=========================================================
Network Intrusion Detection System (NIDS)

Module : ARP Detection

Detects abnormal ARP activity.

=========================================================
"""


from datetime import datetime


from config import (

    ARP_THRESHOLD,

    ARP_TIME_WINDOW

)


from detection.state import arp_history





def detect_arp(packet):


    if packet.get("protocol") != "ARP":

        return None





    src_ip = packet["src_ip"]

    dst_ip = packet["dst_ip"]



    now = datetime.now()



    history = arp_history[src_ip]





    # Remove old ARP events

    history[:] = [

        timestamp

        for timestamp in history

        if (

            now - timestamp

        ).total_seconds()

        <= ARP_TIME_WINDOW

    ]





    history.append(now)





    # Normal ARP traffic

    if len(history) < ARP_THRESHOLD:

        return None





    return {


        "attack_key": (

            src_ip,

            "ARP_SCAN"

        ),



        "attack_type":

            "ARP Scan Activity",



        "severity":

            "MEDIUM",



        "source_ip":

            src_ip,



        "destination_ip":

            dst_ip,



        "details": {


            "requests":

                len(history),



            "time_window":

                ARP_TIME_WINDOW

        }

    }
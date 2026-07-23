"""
=========================================================
Network Intrusion Detection System (NIDS)

Module : ICMP Flood Detection

Detects excessive ICMP Echo Requests
from a single source.

=========================================================
"""


from datetime import datetime


from config import (

    ICMP_FLOOD_THRESHOLD,

    ICMP_TIME_WINDOW

)


from detection.state import icmp_history





def detect_icmp_flood(packet):


    # Only ICMP

    if packet["protocol"] != "ICMP":

        return None





    # Only Echo Request

    # Ignore replies

    if packet.get("icmp_type") != 8:

        return None






    src_ip = packet["src_ip"]


    dst_ip = packet["dst_ip"]



    now = datetime.now()






    # Store timestamps per source

    history = icmp_history[src_ip]







    # ==========================================
    # Remove expired packets
    # ==========================================


    history[:] = [

        timestamp

        for timestamp in history


        if (

            now - timestamp

        ).total_seconds()

        <= ICMP_TIME_WINDOW

    ]







    # Add current packet

    history.append(now)







    # ==========================================
    # Threshold Check
    # ==========================================


    if len(history) < ICMP_FLOOD_THRESHOLD:


        return None







    return {


        "attack_key":

            (

                src_ip,

                "ICMP_FLOOD"

            ),



        "attack_type":

            "ICMP Flood",



        "severity":

            "HIGH",



        "source_ip":

            src_ip,



        "destination_ip":

            dst_ip,



        "details":{


            "packet_count":

                len(history),



            "time_window":

                ICMP_TIME_WINDOW

        }

    }
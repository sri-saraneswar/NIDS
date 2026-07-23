"""
=========================================================
Network Intrusion Detection System (NIDS)

Module : DNS Detection

Detects abnormal DNS request frequency.

=========================================================
"""


from datetime import datetime


from config import (

    DNS_PORTS,

    DNS_THRESHOLD,

    DNS_TIME_WINDOW

)


from detection.state import dns_history





def detect_dns(packet):


    if packet.get("protocol") != "UDP":

        return None





    if packet.get("dst_port") not in DNS_PORTS:

        return None





    src_ip = packet["src_ip"]

    dst_ip = packet["dst_ip"]



    now = datetime.now()



    history = dns_history[src_ip]





    # Remove expired DNS requests

    history[:] = [

        timestamp

        for timestamp in history

        if (

            now - timestamp

        ).total_seconds()

        <= DNS_TIME_WINDOW

    ]





    history.append(now)





    # Normal DNS request

    if len(history) < DNS_THRESHOLD:

        return None





    return {


        "attack_key": (

            src_ip,

            "DNS_FLOOD"

        ),



        "attack_type":

            "DNS Flood Activity",



        "severity":

            "MEDIUM",



        "source_ip":

            src_ip,



        "destination_ip":

            dst_ip,



        "details": {


            "dns_requests":

                len(history),



            "time_window":

                DNS_TIME_WINDOW

        }

    }
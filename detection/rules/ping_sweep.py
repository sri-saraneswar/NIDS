"""
=========================================================
Network Intrusion Detection System (NIDS)

Module : Ping Sweep Detection

Detects ICMP Echo Requests sent to multiple hosts.

=========================================================
"""


from datetime import datetime


from config import (

    PING_SWEEP_THRESHOLD,

    PING_SWEEP_TIME_WINDOW

)


from detection.state import ping_sweep_history







def detect_ping_sweep(packet):


    # Only ICMP

    if packet["protocol"] != "ICMP":

        return None




    # Only Echo Request

    # Ignore Echo Reply

    if packet.get("icmp_type") != 8:

        return None






    src_ip = packet["src_ip"]


    dst_ip = packet["dst_ip"]



    now = datetime.now()



    history = ping_sweep_history[src_ip]







    # ==========================================
    # Remove old entries
    # ==========================================


    expired = set()



    for ip, timestamp in history:



        if (

            now - timestamp

        ).total_seconds() > PING_SWEEP_TIME_WINDOW:



            expired.add(

                (ip,timestamp)

            )





    for item in expired:


        history.remove(item)








    # ==========================================
    # Store destination host
    # ==========================================


    history.add(

        (

            dst_ip,

            now

        )

    )







    # Count unique targets


    unique_hosts = {


        ip

        for ip,_ in history

    }








    if len(unique_hosts) < PING_SWEEP_THRESHOLD:


        return None







    return {


        "attack_key":

            (

                src_ip,

                "PING_SWEEP"

            ),



        "attack_type":

            "ICMP Ping Sweep",



        "severity":

            "HIGH",



        "source_ip":

            src_ip,



        "destination_ip":

            dst_ip,



        "details":{


            "hosts_scanned":

                sorted(unique_hosts),



            "host_count":

                len(unique_hosts),



            "time_window":

                PING_SWEEP_TIME_WINDOW

        }

    }
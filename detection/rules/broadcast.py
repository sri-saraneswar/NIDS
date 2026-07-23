"""
=========================================================
Network Intrusion Detection System (NIDS)

Module : Broadcast Detection

=========================================================
"""


from datetime import datetime


from config import (

    BROADCAST_THRESHOLD,

    BROADCAST_TIME_WINDOW,

    BROADCAST_IPS

)


from detection.state import broadcast_history





def detect_broadcast(packet):


    dst_ip = packet.get(

        "dst_ip"

    )



    if not dst_ip:

        return None





    # Check broadcast destination


    if (

        dst_ip not in BROADCAST_IPS

        and

        not dst_ip.endswith(".255")

    ):

        return None





    src_ip = packet["src_ip"]



    now = datetime.now()



    history = broadcast_history[src_ip]





    history[:] = [

        timestamp

        for timestamp in history

        if (

            now - timestamp

        ).total_seconds()

        <= BROADCAST_TIME_WINDOW

    ]





    history.append(now)





    if len(history) < BROADCAST_THRESHOLD:

        return None





    return {



        "attack_key":(

            src_ip,

            "BROADCAST"

        ),



        "attack_type":

            "Broadcast Storm",



        "severity":

            "LOW",



        "source_ip":

            src_ip,



        "destination_ip":

            dst_ip,



        "details":{


            "packet_count":

                len(history),



            "time_window":

                BROADCAST_TIME_WINDOW

        }

    }
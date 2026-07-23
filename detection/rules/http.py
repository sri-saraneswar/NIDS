"""
=========================================================
Network Intrusion Detection System (NIDS)

Module : HTTP Detection

Detects HTTP flood behaviour.

=========================================================
"""


from datetime import datetime


from config import (

    HTTP_PORTS,

    HTTP_THRESHOLD,

    HTTP_TIME_WINDOW

)


from detection.state import http_history




def detect_http(packet):


    if packet["protocol"] != "TCP":

        return None



    if packet.get("dst_port") not in HTTP_PORTS:

        return None



    src_ip = packet["src_ip"]

    dst_ip = packet["dst_ip"]



    now = datetime.now()



    history = http_history[src_ip]



    history[:] = [

        t for t in history

        if (now-t).total_seconds()
        <= HTTP_TIME_WINDOW

    ]



    history.append(now)




    if len(history) < HTTP_THRESHOLD:

        return None




    return {


        "attack_key":

        (
            src_ip,
            "HTTP_FLOOD"
        ),



        "attack_type":

        "HTTP Flood",



        "severity":

        "MEDIUM",



        "source_ip":

        src_ip,



        "destination_ip":

        dst_ip,



        "details":
        {

            "requests":
            len(history),

            "time_window":
            HTTP_TIME_WINDOW

        }

    }
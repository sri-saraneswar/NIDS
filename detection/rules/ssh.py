"""
=========================================================
Network Intrusion Detection System (NIDS)

Module : SSH Detection

Detects SSH brute force attempts.

=========================================================
"""


from datetime import datetime


from config import (

    SSH_PORTS,

    SSH_THRESHOLD,

    SSH_TIME_WINDOW

)


from detection.state import ssh_history





def detect_ssh(packet):


    if packet["protocol"] != "TCP":

        return None



    if packet.get("dst_port") not in SSH_PORTS:

        return None



    src_ip = packet["src_ip"]

    dst_ip = packet["dst_ip"]



    now = datetime.now()



    history = ssh_history[src_ip]



    history[:] = [

        t for t in history

        if (now-t).total_seconds()
        <= SSH_TIME_WINDOW

    ]



    history.append(now)




    if len(history) < SSH_THRESHOLD:

        return None




    return {


        "attack_key":

        (
            src_ip,
            "SSH_BRUTE_FORCE"
        ),



        "attack_type":

        "SSH Brute Force",



        "severity":

        "HIGH",



        "source_ip":

        src_ip,



        "destination_ip":

        dst_ip,



        "details":
        {

            "connection_attempts":

            len(history),


            "time_window":

            SSH_TIME_WINDOW

        }

    }
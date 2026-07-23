"""
=========================================================
Network Intrusion Detection System (NIDS)

Module : FTP Detection

Detects FTP brute force activity.

=========================================================
"""

from datetime import datetime

from config import (
    FTP_PORTS,
    FTP_THRESHOLD,
    FTP_TIME_WINDOW
)

from detection.state import ftp_history



def detect_ftp(packet):

    if packet["protocol"] != "TCP":
        return None


    if packet.get("dst_port") not in FTP_PORTS:
        return None


    src_ip = packet["src_ip"]
    dst_ip = packet["dst_ip"]


    now = datetime.now()


    history = ftp_history[src_ip]


    history[:] = [

        t for t in history

        if (now - t).total_seconds()
        <= FTP_TIME_WINDOW

    ]


    history.append(now)



    if len(history) < FTP_THRESHOLD:
        return None



    return {


        "attack_key":
        (
            src_ip,
            "FTP_BRUTE_FORCE"
        ),


        "attack_type":
        "FTP Brute Force",


        "severity":
        "MEDIUM",


        "source_ip":
        src_ip,


        "destination_ip":
        dst_ip,


        "details":
        {

            "login_attempts":
            len(history),

            "time_window":
            FTP_TIME_WINDOW

        }

    }
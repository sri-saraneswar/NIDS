"""
=========================================================
Network Intrusion Detection System (NIDS)

Module : TCP XMAS Scan Detection

=========================================================
"""


from datetime import datetime


from config import (

    XMAS_SCAN_THRESHOLD,

    XMAS_SCAN_TIME_WINDOW

)


from detection.state import xmas_scan_history





def detect_xmas_scan(packet):


    if packet["protocol"] != "TCP":

        return None





    flags = packet.get(

        "flags",

        ""

    )





    # XMAS = FIN + PSH + URG


    if not (

        "F" in flags

        and

        "P" in flags

        and

        "U" in flags

    ):

        return None





    src_ip = packet["src_ip"]

    dst_ip = packet["dst_ip"]

    dst_port = packet["dst_port"]



    now = datetime.now()



    history = xmas_scan_history[src_ip]





    history[:] = [

        item

        for item in history

        if (

            now-item["time"]

        ).total_seconds()

        <= XMAS_SCAN_TIME_WINDOW

    ]





    history.append({

        "port":

            dst_port,

        "time":

            now

    })





    unique_ports = {


        item["port"]

        for item in history

    }





    if len(unique_ports) < XMAS_SCAN_THRESHOLD:

        return None





    return {



        "attack_key":(

            src_ip,

            "XMAS_SCAN"

        ),



        "attack_type":

            "TCP XMAS Scan",



        "severity":

            "HIGH",



        "source_ip":

            src_ip,



        "destination_ip":

            dst_ip,



        "details":{


            "ports_scanned":

                sorted(unique_ports),



            "port_count":

                len(unique_ports),



            "packet_count":

                len(history)

        }

    }
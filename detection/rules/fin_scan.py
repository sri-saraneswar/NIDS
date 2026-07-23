"""
=========================================================
Network Intrusion Detection System (NIDS)

Module : TCP FIN Scan Detection

=========================================================
"""


from datetime import datetime


from config import (

    FIN_SCAN_THRESHOLD,

    FIN_SCAN_TIME_WINDOW

)


from detection.state import fin_scan_history





def detect_fin_scan(packet):


    if packet["protocol"] != "TCP":

        return None




    flags = packet.get(

        "flags",

        ""

    )



    if flags != "F":

        return None





    src_ip = packet["src_ip"]


    dst_ip = packet["dst_ip"]


    dst_port = packet["dst_port"]



    now = datetime.now()



    history = fin_scan_history[src_ip]





    history[:] = [

        item

        for item in history

        if (

            now-item["time"]

        ).total_seconds()

        <= FIN_SCAN_TIME_WINDOW

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





    if len(unique_ports) < FIN_SCAN_THRESHOLD:

        return None





    return {



        "attack_key":(

            src_ip,

            "FIN_SCAN"

        ),



        "attack_type":

            "TCP FIN Scan",



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
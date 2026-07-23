"""
=========================================================
Network Intrusion Detection System (NIDS)

Module : TCP NULL Scan Detection

=========================================================
"""


from datetime import datetime


from config import (

    NULL_SCAN_THRESHOLD,

    NULL_SCAN_TIME_WINDOW

)


from detection.state import null_scan_history





def detect_null_scan(packet):


    if packet["protocol"] != "TCP":

        return None




    flags = packet.get(

        "flags",

        ""

    )



    # NULL scan means no TCP flags

    if flags not in ("", "0"):

        return None





    src_ip = packet["src_ip"]

    dst_ip = packet["dst_ip"]

    dst_port = packet["dst_port"]



    now = datetime.now()



    history = null_scan_history[src_ip]





    history[:] = [

        item

        for item in history

        if (

            now - item["time"]

        ).total_seconds()

        <= NULL_SCAN_TIME_WINDOW

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





    if len(unique_ports) < NULL_SCAN_THRESHOLD:

        return None





    return {



        "attack_key":(

            src_ip,

            "NULL_SCAN"

        ),



        "attack_type":

            "TCP NULL Scan",



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
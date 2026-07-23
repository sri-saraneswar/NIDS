"""
=========================================================
Network Intrusion Detection System (NIDS)

Module : TCP SYN Scan Detection

=========================================================
"""


from datetime import datetime


from config import (

    SYN_SCAN_THRESHOLD,

    SYN_SCAN_TIME_WINDOW

)


from detection.state import syn_scan_history





def detect_syn_scan(packet):


    if packet["protocol"] != "TCP":

        return None




    flags = packet.get(

        "flags",

        ""

    )



    # SYN only

    if flags != "S":

        return None





    src_ip = packet["src_ip"]


    dst_ip = packet["dst_ip"]


    dst_port = packet["dst_port"]



    now = datetime.now()



    history = syn_scan_history[src_ip]





    # Remove expired entries


    history[:] = [

        item

        for item in history

        if (

            now - item["time"]

        ).total_seconds()

        <= SYN_SCAN_TIME_WINDOW

    ]





    history.append({


        "port":dst_port,


        "time":now


    })





    unique_ports = {


        item["port"]

        for item in history

    }





    if len(unique_ports) < SYN_SCAN_THRESHOLD:


        return None





    return {



        "attack_key":(

            src_ip,

            "SYN_SCAN"

        ),



        "attack_type":

            "TCP SYN Port Scan",



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
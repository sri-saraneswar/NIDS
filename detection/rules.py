"""
====================================================
Network Intrusion Detection System (NIDS)

Module : Detection Rules

Contains IDS detection logic.

====================================================
"""


from datetime import datetime



from detection.state import (
    icmp_history,
    port_history,
    syn_history,
    udp_history
)



from config import (
    ICMP_THRESHOLD,
    ICMP_TIME_WINDOW,

    PORTSCAN_THRESHOLD,
    PORTSCAN_TIME_WINDOW,

    LARGE_PACKET_SIZE,

    SSH_PORT,
    TELNET_PORT,
    FTP_PORTS,

    HTTP_PORT,
    HTTPS_PORT
)



# ==================================================
# Detection Rules
# ==================================================

def detect_rules(packet_info):


    protocol = packet_info["protocol"]

    src_ip = packet_info["src_ip"]

    dst_ip = packet_info["dst_ip"]

    dst_port = packet_info["dst_port"]

    packet_size = packet_info["packet_size"]



    current_time = datetime.now()



    result = {


        "status":"NORMAL",

        "severity":"LOW",

        "rule_id":"NIDS-000",

        "attack":"None",

        "reason":"Normal Network Traffic"

    }



    # =============================================
    # ICMP Flood Detection
    # =============================================

    if protocol == "ICMP":


        history = icmp_history[src_ip]


        history.append(current_time)



        while history:


            if (

                current_time -

                history[0]

            ).total_seconds() > ICMP_TIME_WINDOW:


                history.popleft()


            else:

                break



        if len(history) >= ICMP_THRESHOLD:


            return {


                "status":"ALERT",

                "severity":"HIGH",

                "rule_id":"NIDS-001",

                "attack":"ICMP Flood",

                "reason":
                f"{len(history)} ICMP packets from {src_ip}"

            }




    # =============================================
    # Port Scan Detection
    # =============================================


    if dst_port:


        history = port_history[src_ip]


        history.append(
            (
                current_time,
                dst_port
            )
        )



        while history:


            if (

                current_time -

                history[0][0]

            ).total_seconds() > PORTSCAN_TIME_WINDOW:


                history.popleft()


            else:

                break




        unique_ports = {


            port

            for _,port in history

        }



        if len(unique_ports) >= PORTSCAN_THRESHOLD:


            return {


                "status":"ALERT",

                "severity":"HIGH",

                "rule_id":"NIDS-002",

                "attack":"Port Scan",

                "reason":
                f"{len(unique_ports)} ports accessed"

            }




    # =============================================
    # Telnet
    # =============================================

    if dst_port == TELNET_PORT:


        return {


            "status":"WARNING",

            "severity":"MEDIUM",

            "rule_id":"NIDS-003",

            "attack":"Telnet",

            "reason":"Insecure Telnet Traffic"

        }





    # =============================================
    # FTP
    # =============================================

    if dst_port in FTP_PORTS:


        return {


            "status":"WARNING",

            "severity":"MEDIUM",

            "rule_id":"NIDS-004",

            "attack":"FTP",

            "reason":"Plaintext FTP Communication"

        }





    # =============================================
    # SSH
    # =============================================

    if dst_port == SSH_PORT:


        return {


            "status":"INFO",

            "severity":"LOW",

            "rule_id":"NIDS-005",

            "attack":"SSH",

            "reason":"Secure SSH Traffic"

        }





    # =============================================
    # HTTP
    # =============================================

    if dst_port == HTTP_PORT:


        return {


            "status":"INFO",

            "severity":"LOW",

            "rule_id":"NIDS-006",

            "attack":"HTTP",

            "reason":"Web Traffic"

        }





    # =============================================
    # HTTPS
    # =============================================

    if dst_port == HTTPS_PORT:


        return {


            "status":"INFO",

            "severity":"LOW",

            "rule_id":"NIDS-007",

            "attack":"HTTPS",

            "reason":"Encrypted Web Traffic"

        }





    # =============================================
    # Large Packet
    # =============================================

    if packet_size > LARGE_PACKET_SIZE:


        return {


            "status":"WARNING",

            "severity":"MEDIUM",

            "rule_id":"NIDS-008",

            "attack":"Large Packet",

            "reason":
            f"Packet size {packet_size}"

        }

    return result
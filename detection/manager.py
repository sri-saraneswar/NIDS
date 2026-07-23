"""
=========================================================
Network Intrusion Detection System (NIDS)

Module : Detection Manager

Runs all detection rules.

Pipeline:

Packet
   |
   ↓
Detection Manager
   |
   ↓
Individual Rules
   |
   ↓
Attack Events

=========================================================
"""


# =========================================================
# Import Detection Rules
# =========================================================


from detection.rules.syn_scan import detect_syn_scan

from detection.rules.fin_scan import detect_fin_scan

from detection.rules.null_scan import detect_null_scan

from detection.rules.xmas_scan import detect_xmas_scan


from detection.rules.icmp_flood import detect_icmp_flood

from detection.rules.ping_sweep import detect_ping_sweep


from detection.rules.broadcast import detect_broadcast

from detection.rules.large_packet import detect_large_packet


from detection.rules.arp import detect_arp

from detection.rules.dns import detect_dns

from detection.rules.http import detect_http

from detection.rules.ftp import detect_ftp

from detection.rules.ssh import detect_ssh





# =========================================================
# Detection Rule Registry
# =========================================================


RULES = [

    detect_syn_scan,

    detect_fin_scan,

    detect_null_scan,

    detect_xmas_scan,


    detect_icmp_flood,

    detect_ping_sweep,


    detect_broadcast,

    detect_large_packet,


    detect_arp,


    detect_dns,

    detect_http,

    detect_ftp,

    detect_ssh

]





# =========================================================
# Execute Detection Pipeline
# =========================================================


def detect_attacks(packet):

    """
    Runs every detection rule.

    Input:

        packet = {

            src_ip,
            dst_ip,
            protocol,
            ports,
            flags

        }


    Output:

        [

          {

            attack_type,
            severity,
            source_ip

          }

        ]

    """



    detected_attacks = []





    for rule in RULES:


        try:


            result = rule(packet)



            # Rule detected attack

            if result:


                detected_attacks.append(

                    result

                )



        except Exception as error:


            print(

                "[DETECTION RULE FAILED]",

                rule.__name__,

                "->",

                error

            )



            continue





    return detected_attacks
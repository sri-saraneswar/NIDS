"""
====================================================
Network Intrusion Detection System

Detection Controller

====================================================
"""


from detection.rules import detect_rules


from detection.statistics import update_statistics




def detect(packet_info):


    result = detect_rules(packet_info)



    update_statistics(

        packet_info,

        result

    )


    return result
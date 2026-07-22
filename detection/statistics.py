"""
====================================================
Detection Statistics

Maintains IDS statistics.

====================================================
"""


from collections import Counter



from config import (
    HIGH_ALERT_THRESHOLD,
    CRITICAL_ALERT_THRESHOLD,
    MEDIUM_WARNING_THRESHOLD
)



total_packets = 0


status_counter = Counter()


protocol_counter = Counter()


attack_counter = Counter()




def update_statistics(packet_info,result):


    global total_packets


    total_packets += 1



    status_counter[
        result["status"]
    ] += 1



    protocol_counter[
        packet_info["protocol"]
    ] += 1



    if result["attack"] != "None":


        attack_counter[
            result["attack"]
        ] += 1






def calculate_risk():


    alerts = status_counter["ALERT"]


    warnings = status_counter["WARNING"]



    if alerts >= CRITICAL_ALERT_THRESHOLD:

        return "CRITICAL"



    elif alerts >= HIGH_ALERT_THRESHOLD:

        return "HIGH"



    elif warnings >= MEDIUM_WARNING_THRESHOLD:

        return "MEDIUM"



    return "LOW"
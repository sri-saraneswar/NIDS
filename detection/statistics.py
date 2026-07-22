"""
====================================================
Network Intrusion Detection System (NIDS)

Module : Statistics Engine

Maintains IDS statistics and security summaries.

====================================================
"""


from collections import Counter


from config import (
    SUMMARY_INTERVAL,
    HIGH_ALERT_THRESHOLD,
    CRITICAL_ALERT_THRESHOLD,
    MEDIUM_WARNING_THRESHOLD
)



# ==================================================
# Global Statistics
# ==================================================

total_packets = 0


status_counter = Counter()


protocol_counter = Counter()


attack_counter = Counter()


source_counter = Counter()


destination_counter = Counter()





# ==================================================
# Update Statistics
# ==================================================

def update_statistics(packet_info, result):

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


    source_counter[
        packet_info["src_ip"]
    ] += 1


    destination_counter[
        packet_info["dst_ip"]
    ] += 1



    # ==============================
    # Summary Trigger
    # ==============================

    if should_print_summary():

        security_summary()





# ==================================================
# Risk Calculation
# ==================================================

def calculate_risk():


    alerts = status_counter["ALERT"]

    warnings = status_counter["WARNING"]



    if alerts >= CRITICAL_ALERT_THRESHOLD:

        return "CRITICAL"


    elif alerts >= HIGH_ALERT_THRESHOLD:

        return "HIGH"


    elif warnings >= MEDIUM_WARNING_THRESHOLD:

        return "MEDIUM"


    else:

        return "LOW"





# ==================================================
# Security Summary
# ==================================================

def security_summary():


    print("\n")

    print("="*60)

    print("          NETWORK SECURITY SUMMARY")

    print("="*60)



    print(
        f"Total Packets : {total_packets}"
    )


    print("\nPacket Status")

    print(
        f"Normal  : {status_counter['NORMAL']}"
    )

    print(
        f"Info    : {status_counter['INFO']}"
    )

    print(
        f"Warning : {status_counter['WARNING']}"
    )

    print(
        f"Alert   : {status_counter['ALERT']}"
    )



    print("\nProtocols")


    for protocol,count in protocol_counter.items():

        print(
            f"{protocol} : {count}"
        )



    print("\nDetected Attacks")


    if attack_counter:


        for attack,count in attack_counter.items():

            print(
                f"{attack} : {count}"
            )


    else:

        print("None")



    print("\nOverall Risk:")

    print(
        calculate_risk()
    )


    print("="*60)





# ==================================================
# Summary Trigger
# ==================================================

def should_print_summary():


    if total_packets == 0:

        return False



    return (
        total_packets %
        SUMMARY_INTERVAL
        ==
        0
    )
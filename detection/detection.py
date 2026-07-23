"""
=========================================================
Network Intrusion Detection System (NIDS)

Module : Detection Engine

Pipeline:

Packet
 |
 v
Detection Rules
 |
 v
Threshold Manager
 |
 v
Statistics

=========================================================
"""


from detection.rules_manager import detect_attacks


from detection.threshold_manager import (

    process_attacks,

    cleanup_finished_attacks

)


from detection.statistics import (

    update_statistics

)





# =====================================================
# Main Detection Function
# =====================================================


def detect(packet):


    result = {


        "alerts":[],

        "finished":[]

    }





    # ==========================================
    # Run All Rules
    # ==========================================


    attacks = detect_attacks(packet)





    if attacks:


        events = process_attacks(

            attacks

        )



        result["alerts"] = events



        update_statistics(

            events

        )







    # ==========================================
    # Check Finished Attacks
    # ==========================================


    finished = cleanup_finished_attacks()



    result["finished"] = finished





    return result
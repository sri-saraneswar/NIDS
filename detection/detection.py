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


from detection.manager import detect_attacks


from detection.threshold import (

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


        "status":"OK",

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



        if events:


            result["status"] = "ALERT"



        update_statistics(

            events

        )







    # ==========================================
    # Check Finished Attacks
    # ==========================================


    finished = cleanup_finished_attacks()



    result["finished"] = finished





    return result

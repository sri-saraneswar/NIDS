"""
=========================================================
Network Intrusion Detection System (NIDS)

Module : Detection Statistics

Stores runtime IDS statistics.

=========================================================
"""


statistics = {


    "packets":0,


    "alerts":0,


    "warnings":0,


    "risk":"LOW",


    "high":0,


    "medium":0,


    "low":0,


    "critical":0,


    "attack_types":{},


    "top_attackers":{},


    "top_targets":{}

}





# =====================================================
# Packet Counter
# =====================================================


def update_packet_count():


    statistics["packets"] += 1







# =====================================================
# Update Attack Statistics
# =====================================================


def update_statistics(events):


    levels = {


        "LOW":1,

        "MEDIUM":2,

        "HIGH":3,

        "CRITICAL":4

    }





    for event in events:



        if event["status"] != "STARTED":

            continue




        attack = event["attack"]



        severity = attack["severity"]





        statistics["alerts"] += 1





        # Severity count


        if severity == "LOW":

            statistics["low"] += 1



        elif severity == "MEDIUM":

            statistics["medium"] += 1



        elif severity == "HIGH":

            statistics["high"] += 1



        elif severity == "CRITICAL":

            statistics["critical"] += 1





        # Highest risk


        if levels[severity] > levels[statistics["risk"]]:

            statistics["risk"] = severity





        # Attack types


        name = attack["attack_type"]



        statistics["attack_types"].setdefault(

            name,

            0

        )



        statistics["attack_types"][name]+=1





        # Top attacker


        attacker = attack["source_ip"]



        statistics["top_attackers"].setdefault(

            attacker,

            0

        )


        statistics["top_attackers"][attacker]+=1





        # Target IP


        target = attack["destination_ip"]



        statistics["top_targets"].setdefault(

            target,

            0

        )


        statistics["top_targets"][target]+=1







# =====================================================
# Get Statistics
# =====================================================


def get_statistics():


    return statistics







# =====================================================
# Reset
# =====================================================


def reset_statistics():


    statistics.clear()



    statistics.update({


        "packets":0,


        "alerts":0,


        "warnings":0,


        "risk":"LOW",


        "high":0,


        "medium":0,


        "low":0,


        "critical":0,


        "attack_types":{},


        "top_attackers":{},


        "top_targets":{}

    })
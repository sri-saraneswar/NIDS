"""
=========================================================
Network Intrusion Detection System (NIDS)

Module : Attack Threshold Manager

Controls attack lifecycle.

STARTED
ONGOING
FINISHED

=========================================================
"""


from datetime import datetime


from config import ATTACK_TIMEOUT


from detection.state import (

    active_attacks,

    attack_history,

    next_alert_id

)





# =====================================================
# Process Detected Attacks
# =====================================================


def process_attacks(attacks):


    events = []


    now = datetime.now()



    for attack in attacks:


        attack_key = attack["attack_key"]



        # =============================================
        # New Attack
        # =============================================


        if attack_key not in active_attacks:


            attack["alert_id"] = next_alert_id()


            attack["start_time"] = now


            attack["last_seen"] = now


            attack["packet_count"] = 1


            attack["status"] = "ACTIVE"



            active_attacks[attack_key] = attack



            events.append({

                "status":"STARTED",

                "attack":attack

            })





        # =============================================
        # Existing Attack
        # =============================================


        else:


            existing = active_attacks[attack_key]



            existing["last_seen"] = now


            existing["packet_count"] += 1



            existing["details"] = attack.get(

                "details",

                existing.get(

                    "details",

                    {}

                )

            )



            # Severity escalation

            existing["severity"] = escalate_severity(

                existing["severity"],

                existing["packet_count"]

            )




            events.append({

                "status":"ONGOING",

                "attack":existing

            })



    return events





# =====================================================
# Severity Escalation
# =====================================================


def escalate_severity(

        severity,

        packets

):


    if packets > 500:


        return "CRITICAL"



    elif packets > 100:


        if severity in [

            "LOW",

            "MEDIUM"

        ]:

            return "HIGH"



    return severity







# =====================================================
# Cleanup Finished Attacks
# =====================================================


def cleanup_finished_attacks():


    now = datetime.now()


    finished=[]


    remove=[]




    for key,attack in active_attacks.items():



        idle = (

            now -

            attack["last_seen"]

        ).total_seconds()



        if idle >= ATTACK_TIMEOUT:



            attack["end_time"]=now



            attack["duration"]=(

                attack["end_time"]

                -

                attack["start_time"]

            ).total_seconds()



            attack["status"]="FINISHED"



            finished.append(attack)



            attack_history.append(attack)



            remove.append(key)





    for key in remove:


        del active_attacks[key]



    return finished
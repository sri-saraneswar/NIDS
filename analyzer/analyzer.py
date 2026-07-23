"""
====================================================
Network Intrusion Detection System (NIDS)

Module : Packet Analyzer

Pipeline

Packet
   |
   ↓
Flow Tracker
   |
   ↓
Detection Engine
   |
   ↓
Session Manager
   |
   ↓
Database
   |
   ↓
Alert System


====================================================
"""


# ==================================================
# Flow Tracker
# ==================================================

from flow.flow_tracker import (

    update_flow,

    cleanup_flows,

    get_total_flow_count,

    get_active_flow_count,

    get_completed_flow_count,

    get_completed_flows,

    remove_completed_flow

)


# ==================================================
# Detection Engine
# ==================================================

from detection.detection import detect



# ==================================================
# Statistics
# ==================================================

from detection.statistics import (

    update_packet_count,

    get_statistics

)



# ==================================================
# Session Manager
# ==================================================

from session.session_manager import (

    update_packet,

    update_flows,

    update_attack,

    update_attack_packet,

    finish_attack,

    update_risk,

    get_current_session

)



# ==================================================
# Database
# ==================================================

from database.database import (

    save_alert,

    save_flow,

    save_suspicious_packet

)



# ==================================================
# Console
# ==================================================

from console.console_manager import (

    display_alert,

    display_attack_progress,

    display_finished_attack,

    display_live_status

)





# ==================================================
# Analyze Packet
# ==================================================

def analyze_packet(packet):


    try:


        # ==========================================
        # Packet Count
        # ==========================================

        update_packet_count()

        update_packet()



        # ==========================================
        # Flow Tracking
        # ==========================================

        flow = update_flow(packet)


        packet["flow_id"] = flow.flow_id



        # Cleanup expired flows

        cleanup_flows()



        # ==========================================
        # Update Flow Statistics
        # ==========================================

        update_flows(

            get_total_flow_count(),

            get_active_flow_count(),

            get_completed_flow_count()

        )



        # ==========================================
        # Detection Engine
        # ==========================================

        result = detect(packet)



        session = get_current_session()



        # ==========================================
        # Live Status
        # Only display when alert happens
        # ==========================================

        if result["status"] == "ALERT":


            display_live_status(

                get_statistics()

            )



        # ==========================================
        # Handle Active Alerts
        # ==========================================


        for event in result["alerts"]:


            attack = event["attack"]



            # ----------------------------------
            # New Attack
            # ----------------------------------

            if event["status"] == "STARTED":



                update_attack(

                    attack

                )


                update_risk(

                    attack["severity"]

                )



                display_alert(

                    packet,

                    attack

                )



                if session:



                    save_alert(

                        session.session_id,

                        attack

                    )


                    save_suspicious_packet(

                        session.session_id,

                        attack["alert_id"],

                        packet

                    )





            # ----------------------------------
            # Existing Attack
            # ----------------------------------

            elif event["status"] == "ONGOING":



                attack_key = (

                    attack["source_ip"],

                    attack["attack_type"]

                )


                update_attack_packet(

                    attack_key

                )


                display_attack_progress(

                    attack

                )





        # ==========================================
        # Finished Attacks
        # ==========================================


        for attack in result["finished"]:


            finish_attack(

                attack

            )


            display_finished_attack(

                attack

            )





        # ==========================================
        # Save Completed Flows
        # ==========================================


        if session:


            completed = get_completed_flows()



            for flow in completed:



                save_flow(

                    session.session_id,

                    flow

                )


                remove_completed_flow(

                    flow.flow_id

                )





        return result





    except Exception as error:



        print(

            "\n[ANALYZER ERROR]",

            error

        )



        return {


            "status":

            "ERROR",


            "alerts":

            [],


            "finished":

            []

        }
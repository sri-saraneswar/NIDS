"""
====================================================
Network Intrusion Detection System (NIDS)

Module : Session Manager

Controls IDS monitoring sessions.

====================================================
"""

from datetime import datetime

from session.session import Session

from database.database import save_session



# ==================================================
# Current Session
# ==================================================

current_session = None



# ==================================================
# Start Session
# ==================================================

def start_session():

    global current_session


    # Reset runtime data

    from detection.state import reset_state

    from detection.statistics import reset_statistics

    from flow.flow_tracker import reset_flows


    reset_state()

    reset_statistics()

    reset_flows()



    session_id = datetime.now().strftime(
        "SESSION-%Y%m%d-%H%M%S-%f"
    )


    current_session = Session(
        session_id
    )


    return current_session





# ==================================================
# Get Current Session
# ==================================================

def get_current_session():

    return current_session





# ==================================================
# Packet Count
# ==================================================

def update_packet():

    if current_session:

        current_session.add_packet()





# ==================================================
# Flow Statistics
# ==================================================

def update_flows(
        total,
        active,
        completed
):

    if current_session:

        current_session.update_flows(
            total,
            active,
            completed
        )





# ==================================================
# New Attack Started
# ==================================================

def update_attack(attack):

    if current_session:

        current_session.add_attack(
            attack
        )





# ==================================================
# Existing Attack Packet
# ==================================================

def update_attack_packet(
        attack_key
):

    if current_session:

        current_session.increment_attack_packet(
            attack_key
        )





# ==================================================
# Attack Finished
# ==================================================

def finish_attack(attack):

    if current_session:

        current_session.finish_attack(
            attack
        )





# ==================================================
# Risk Update
# ==================================================

def update_risk(risk):

    if current_session:

        current_session.update_risk(
            risk
        )





# ==================================================
# Stop Session
# ==================================================

def stop_session():

    global current_session


    if current_session:


        current_session.close()


        save_session(
            current_session.to_dict()
        )





# ==================================================
# Session Summary
# ==================================================

def get_session_summary():

    if current_session:

        return current_session.to_dict()


    return {}





# ==================================================
# Attack Summary
# ==================================================

def get_attack_summary():

    if current_session:

        return current_session.get_attack_summary()


    return []





# ==================================================
# Attack History
# ==================================================

def get_attack_history():

    if current_session:

        return current_session.attack_history


    return []
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

    session_id = datetime.now().strftime(
        "SESSION-%Y%m%d-%H%M%S"
    )

    current_session = Session(session_id)

    return current_session


# ==================================================
# Get Current Session
# ==================================================

def get_current_session():

    return current_session


# ==================================================
# Update Packet Count
# ==================================================

def update_packet():

    if current_session:

        current_session.add_packet()


# ==================================================
# Update Flow Statistics
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
# Update Alert Count
# ==================================================

def update_alert():

    if current_session:

        current_session.add_alert()


# ==================================================
# Update Risk Level
# ==================================================

def update_risk(risk):

    if current_session:

        current_session.update_risk(risk)


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
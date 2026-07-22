"""
====================================================
Network Intrusion Detection System (NIDS)
Module : Session Manager

Description:
Manages the current IDS monitoring session.
====================================================
"""

from datetime import datetime

from session.session import Session

# ==================================================
# Current Session
# ==================================================

current_session = None


# ==================================================
# Start Session
# ==================================================

def start_session():
    """
    Creates a new monitoring session.
    """

    global current_session

    session_id = datetime.now().strftime("SESSION-%Y%m%d-%H%M%S")

    current_session = Session(session_id)

    return current_session


# ==================================================
# Stop Session
# ==================================================
def stop_session():

    global current_session

    if current_session is not None:

        current_session.close()

        save_session(

            current_session.to_dict()

        )


# ==================================================
# Packet Counter
# ==================================================

def update_packet():

    if current_session is not None:

        current_session.add_packet()


# ==================================================
# Flow Statistics
# ==================================================

def update_flows(total, active, completed):

    if current_session is not None:

        current_session.update_flows(

            total,

            active,

            completed

        )


# ==================================================
# Alert Counter
# ==================================================

def update_alert():

    if current_session is not None:

        current_session.add_alert()


# ==================================================
# Risk Level
# ==================================================

def update_risk(risk):

    if current_session is not None:

        current_session.update_risk(risk)


# ==================================================
# Session Summary
# ==================================================

def get_session_summary():

    if current_session is None:

        return None

    return current_session.to_dict()


# ==================================================
# Current Session
# ==================================================

def get_current_session():

    return current_session
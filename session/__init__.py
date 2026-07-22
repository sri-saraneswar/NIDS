"""
====================================================
Network Intrusion Detection System (NIDS)
Module : Session Manager
Description:
Creates, updates and closes monitoring sessions.
====================================================
"""

from session.session import Session

current_session = None

session_counter = 0


# ==================================================
# Start Session
# ==================================================

def start_session():

    global current_session
    global session_counter

    session_counter += 1

    session_id = f"SESSION-{session_counter:05d}"

    current_session = Session(session_id)

    return current_session


# ==================================================
# Get Current Session
# ==================================================

def get_current_session():

    return current_session


# ==================================================
# Packet Counter
# ==================================================

def update_packet():

    if current_session:

        current_session.add_packet()


# ==================================================
# Flow Counter
# ==================================================

def update_flows(total,
                 active,
                 completed):

    if current_session:

        current_session.update_flows(
            total,
            active,
            completed
        )


# ==================================================
# Alert Counter
# ==================================================

def update_alert():

    if current_session:

        current_session.add_alert()


# ==================================================
# Risk Level
# ==================================================

def update_risk(level):

    if current_session:

        current_session.update_risk(level)


# ==================================================
# Stop Session
# ==================================================

def stop_session():

    if current_session:

        current_session.close()


# ==================================================
# Get Summary
# ==================================================

def get_session_summary():

    if current_session:

        return current_session.to_dict()

    return None
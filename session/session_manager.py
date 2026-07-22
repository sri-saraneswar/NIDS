"""
====================================================
Network Intrusion Detection System (NIDS)

Module : Session Manager

Controls IDS monitoring sessions.

====================================================
"""


from datetime import datetime



from session.session import Session



current_session = None





# ==========================================
# Start Session
# ==========================================

def start_session():


    global current_session



    session_id = (

        "SESSION-"

        +

        datetime.now()
        .strftime("%Y%m%d-%H%M%S")

    )



    current_session = Session(

        session_id

    )


    return current_session





# ==========================================
# Get Current Session
# ==========================================

def get_session():


    return current_session





# ==========================================
# Update Packet Count
# ==========================================

def update_packet():


    if current_session:

        current_session.add_packet()





# ==========================================
# Update Flows
# ==========================================

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





# ==========================================
# Update Alert
# ==========================================

def update_alert():


    if current_session:


        current_session.add_alert()





# ==========================================
# Update Risk
# ==========================================

def update_risk(risk):


    if current_session:


        current_session.update_risk(risk)





# ==========================================
# Stop Session
# ==========================================

def stop_session():


    if current_session:


        current_session.close()





# ==========================================
# Summary
# ==========================================

def get_session_summary():


    if current_session:


        return current_session.to_dict()


    return {}
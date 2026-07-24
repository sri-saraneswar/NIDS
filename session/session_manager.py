"""
====================================================
Network Intrusion Detection System (NIDS)

Module : Session Manager

Controls IDS monitoring sessions.

Provides functions to:
    Start a session
    Update packet counts
    Update flow statistics
    Track attacks
    Track protocols
    Stop and save session

====================================================
"""


from datetime import datetime


from session.session import Session


from database.database import (
    save_session,
    save_attacks
)





# ==================================================
# Current Session
# ==================================================


current_session = None





# ==================================================
# Start Session
# ==================================================


def start_session(interface=None):
    """
    Start a new monitoring session.

    Resets all runtime state and creates
    a fresh Session object.

    Args:
        interface: Network interface name being monitored.

    Returns:
        The new Session object.
    """

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


    if interface:
        current_session.interface = interface


    return current_session





# ==================================================
# Get Current Session
# ==================================================


def get_current_session():
    """Return the currently active session or None."""

    return current_session





# ==================================================
# Packet Count
# ==================================================


def update_packet():
    """Increment the session packet counter."""

    if current_session:

        current_session.add_packet()





# ==================================================
# Protocol and Byte Tracking
# ==================================================


def update_protocol(protocol, packet_size):
    """
    Track protocol distribution in the session.

    Args:
        protocol: Protocol name string.
        packet_size: Packet size in bytes.
    """

    if current_session:

        current_session.update_protocol(
            protocol,
            packet_size
        )





# ==================================================
# Flow Statistics
# ==================================================


def update_flows(
        total,
        active,
        completed
):
    """Update flow statistics in the session."""

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
    """Register a new attack in the session."""

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
    """Increment packet count for an active attack."""

    if current_session:

        current_session.increment_attack_packet(
            attack_key
        )





# ==================================================
# Attack Finished
# ==================================================


def finish_attack(attack):
    """Move a finished attack to the history."""

    if current_session:

        current_session.finish_attack(
            attack
        )





# ==================================================
# Risk Update
# ==================================================


def update_risk(risk):
    """Update the session risk level."""

    if current_session:

        current_session.update_risk(
            risk
        )





# ==================================================
# Stop Session
# ==================================================


def stop_session():
    """
    Close the current session and save to database.

    Saves both the session summary and all
    completed attack records.
    """

    global current_session


    if current_session:


        current_session.close()


        # Save session summary

        try:

            save_session(
                current_session.to_dict()
            )


            # Save attack records

            save_attacks(
                current_session.session_id,
                current_session.get_attack_summary()
            )


        except Exception as error:

            print(
                f"[DATABASE ERROR] {error}"
            )





# ==================================================
# Session Summary
# ==================================================


def get_session_summary():
    """Return the session data as a dictionary."""

    if current_session:

        return current_session.to_dict()


    return {}





# ==================================================
# Attack Summary
# ==================================================


def get_attack_summary():
    """Return a list of all attack summaries."""

    if current_session:

        return current_session.get_attack_summary()


    return []





# ==================================================
# Attack History
# ==================================================


def get_attack_history():
    """Return the raw attack history list."""

    if current_session:

        return current_session.attack_history


    return []
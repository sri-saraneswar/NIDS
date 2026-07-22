"""
====================================================
Network Intrusion Detection System (NIDS)

Main Application

Starts:
- Database
- Monitoring Session
- Packet Capture

====================================================
"""


from capture.capture import start_capture

from database.database import create_database

from session.session_manager import (
    start_session,
    stop_session,
    get_session_summary
)



def print_session_summary(summary):

    print("\n")

    print("=" * 60)
    print("              SESSION SUMMARY")
    print("=" * 60)


    print(
        f"Session ID       : {summary['session_id']}"
    )

    print(
        f"Status           : {summary['status']}"
    )

    print(
        f"Duration         : {summary['duration']:.2f} seconds"
    )


    print("-" * 60)


    print(
        f"Packets          : {summary['packets']}"
    )

    print(
        f"Total Flows      : {summary['flows']}"
    )

    print(
        f"Active Flows     : {summary['active_flows']}"
    )

    print(
        f"Completed Flows  : {summary['completed_flows']}"
    )

    print(
        f"Alerts           : {summary['alerts']}"
    )

    print(
        f"Risk Level       : {summary['risk']}"
    )


    print("=" * 60)




def main():

    print("\n")

    print("=" * 60)

    print(
        "        NETWORK INTRUSION DETECTION SYSTEM"
    )

    print("=" * 60)



    # -----------------------------
    # Database Initialization
    # -----------------------------

    create_database()

    print(
        "Database Initialized Successfully."
    )



    # -----------------------------
    # Start Session
    # -----------------------------

    session = start_session()


    print(
        f"Monitoring Session : {session.session_id}"
    )



    # -----------------------------
    # Start Capture
    # -----------------------------

    try:

        start_capture()


    except KeyboardInterrupt:


        print("\nStopping IDS...")



    finally:


        stop_session()


        summary = get_session_summary()


        print_session_summary(summary)




if __name__ == "__main__":

    main()
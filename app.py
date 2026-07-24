"""
====================================================
Network Intrusion Detection System (NIDS)

Main Application

Orchestrates:
    1. Database Initialization
    2. Interface Selection
    3. Session Start
    4. Alert System Start
    5. Live Packet Capture
    6. Graceful Shutdown
    7. Session Summary Report
    8. Database Save

====================================================
"""


import sys
import os
import threading


# Add the project root to the Python path

sys.path.insert(
    0,
    os.path.dirname(
        os.path.abspath(__file__)
    )
)


from config import IDS_VERSION, AUTHOR


from database.database import (
    create_database,
    save_statistics
)


from capture.capture import (
    show_interfaces,
    start_capture,
    stop_capture
)


from analyzer.analyzer import set_alert_manager


from alert.alert import AlertManager
from dashboard import app as flask_app


from session.session_manager import (
    start_session,
    stop_session,
    get_session_summary,
    get_attack_summary
)


from detection.statistics import (
    get_statistics,
    get_top_hosts
)


from console.console_manager import (
    display_banner,
    display_live_status,
    display_session_summary,
    display_attack_history,
    display_top_hosts,
    display_session_status,
    display_db_status
)





# ==================================================
# Main
# ==================================================


def main():
    """
    Main entry point for the NIDS application.

    Workflow:
        1. Initialize database
        2. Select network interface
        3. Start monitoring session
        4. Start alert popup system
        5. Capture packets until Ctrl+C
        6. Generate session summary report
        7. Save everything to database
    """


    # ------------------------------------------
    # Initialize Database
    # ------------------------------------------

    create_database()



    # ------------------------------------------
    # Select Network Interface
    # ------------------------------------------

    interface = show_interfaces()



    # ------------------------------------------
    # Start Session
    # ------------------------------------------

    start_session(
        interface=interface
    )



    # ------------------------------------------
    # Start Alert System
    # ------------------------------------------

    alert_manager = AlertManager()

    alert_manager.start()

    set_alert_manager(alert_manager)



    # ------------------------------------------
    # Start Dashboard Server
    # ------------------------------------------

    dashboard_thread = threading.Thread(
        target=lambda: flask_app.run(
            host="0.0.0.0",
            port=5000,
            debug=False,
            use_reloader=False
        ),
        daemon=True
    )
    
    dashboard_thread.start()



    # ------------------------------------------
    # Display Banner
    # ------------------------------------------

    display_banner(
        interface=interface,
        version=IDS_VERSION,
        author=AUTHOR
    )



    # ------------------------------------------
    # Start Capture
    # ------------------------------------------

    try:

        start_capture(interface)


    except KeyboardInterrupt:

        pass



    # ------------------------------------------
    # Graceful Shutdown
    # ------------------------------------------

    print("\n")
    print("  Stopping IDS...")
    print()


    # Stop capture

    stop_capture()


    # Stop alert popups

    alert_manager.stop()


    # Close session

    stop_session()



    # ------------------------------------------
    # Session Summary Report
    # ------------------------------------------

    summary = get_session_summary()

    stats = get_statistics()

    attacks = get_attack_summary()

    top_hosts = get_top_hosts(10)



    # Display full report

    display_session_summary(summary)

    display_attack_history(attacks)

    display_top_hosts(top_hosts)

    display_session_status(summary)



    # ------------------------------------------
    # Save Statistics to Database
    # ------------------------------------------

    db_success = True

    try:

        if summary.get("session_id"):

            save_statistics(
                summary["session_id"],
                {
                    "protocol_stats":
                        summary.get(
                            "protocol_stats", {}
                        ),

                    "attack_types":
                        summary.get(
                            "attack_types", {}
                        ),

                    "risk_stats":
                        summary.get(
                            "risk_stats", {}
                        ),

                    "top_hosts":
                        top_hosts
                }
            )

    except Exception as error:

        db_success = False

        print(
            f"  [DATABASE ERROR] {error}"
        )



    display_db_status(db_success)





# ==================================================
# Entry Point
# ==================================================


if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        print("\n")
        print("  IDS Stopped.")

    except Exception as error:

        print()
        print("=" * 60)
        print("  APPLICATION ERROR")
        print("=" * 60)
        print(f"  {error}")
        sys.exit(1)
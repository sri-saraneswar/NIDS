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


# Imports that were not used have been removed





# ==================================================
# Main
# ==================================================


def main():
    """
    Main entry point for the NIDS application.

    Workflow:
        1. Initialize database
        2. Start Dashboard Server (Foreground)
    """

    # ------------------------------------------
    # Initialize Database
    # ------------------------------------------
    create_database()

    # ------------------------------------------
    # Start Dashboard Server
    # ------------------------------------------
    print("\n  Starting NIDS Dashboard...")
    print("  Access the Web UI at http://127.0.0.1:5000\n")
    
    flask_app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
        use_reloader=False
    )





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
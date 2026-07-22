"""
====================================================
Network Intrusion Detection System (NIDS)
Main Application
====================================================
"""

from capture.capture import start_capture
from database.database import create_database


def main():
    """
    Main entry point of the Network IDS.
    """

    print("\n")
    print("=" * 60)
    print("     NETWORK INTRUSION DETECTION SYSTEM")
    print("=" * 60)

    # ---------------------------------------------
    # Initialize Database
    # ---------------------------------------------

    create_database()

    print("Database Initialized Successfully.")

    # ---------------------------------------------
    # Start Packet Capture
    # ---------------------------------------------

    start_capture()


if __name__ == "__main__":

    main()
"""
====================================================
Network Intrusion Detection System (NIDS)

Main Application

====================================================
"""

from database.database import create_database

from capture.capture import start_capture


# ==================================================
# Main
# ==================================================

def main():

    print()

    print("=" * 60)

    print("      NETWORK INTRUSION DETECTION SYSTEM")

    print("=" * 60)

    # ------------------------------------------
    # Initialize Database
    # ------------------------------------------

    create_database()

    # ------------------------------------------
    # Start IDS
    # ------------------------------------------

    start_capture()


# ==================================================
# Entry Point
# ==================================================

if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        print("\n")

        print("IDS Stopped.")

    except Exception as error:

        print()

        print("=" * 60)

        print("APPLICATION ERROR")

        print("=" * 60)

        print(error)
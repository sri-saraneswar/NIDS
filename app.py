"""
====================================================
Network Intrusion Detection System (NIDS)
Main Application
====================================================

Description:
Entry point of the Network Intrusion Detection System.
Initializes the application and starts live packet capture.
"""

from capture.capture import start_capture


# ==================================================
# Main Function
# ==================================================

def main():
    """
    Starts the Network Intrusion Detection System.
    """

    print("\n")
    print("=" * 60)
    print("        NETWORK INTRUSION DETECTION SYSTEM")
    print("=" * 60)

    start_capture()


# ==================================================
# Program Entry Point
# ==================================================

if __name__ == "__main__":
    main()
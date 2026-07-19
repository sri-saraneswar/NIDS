"""
Main entry point for the NIDS project.
Starts the Packet Capture Module.
"""

from capture.capture import start_capture


def main():
    start_capture()


if __name__ == "__main__":
    main()
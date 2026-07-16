# Import the function that starts packet capture
from capture.capture import start_capture

# Main function of the application
def main():
    # Start capturing network packets
    start_capture()

# Run the program only if this file is executed directly
if __name__ == "__main__":
    # Call the main function
    main()
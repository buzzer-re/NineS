import argparse
import socket
import struct
import os

MAX_PROC_NAME = 0x100  
SERVER_IP = "192.168.88.11" 
SERVER_PORT = 9033  


# Function to build the struct -> target_name[MAX_PROC_NAME] + data
def build_injector_data(proc_name, data):
    proc_name = proc_name.encode()
    proc_name = proc_name.ljust(MAX_PROC_NAME, b"\x00"); 
    # print(len(proc_name))

    return proc_name + data


def send_data_to_server(data, ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip, port))
            s.sendall(data)
            print(f"Sent data to {ip}:{port}")
    except Exception as e:
        print(f"Error while sending data: {e}")

# Main function
def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Send process name and data to a remote server.")
    parser.add_argument("name", type=str, help="The name of the process.")
    parser.add_argument("path", type=str, help="The path to the data file.")
    
    args = parser.parse_args()

    if not os.path.exists(args.path):
        print(f"Error: File {args.path} does not exist.")
        return

    with open(args.path, "rb") as file:
        data = file.read()

    # Build the struct with the process name and data
    injector_data = build_injector_data(args.name, data)

    # Send the data to the server
    send_data_to_server(injector_data, SERVER_IP, SERVER_PORT)

if __name__ == "__main__":
    main()

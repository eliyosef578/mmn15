import socket
import rsa
import aes
import binascii
import struct
import time


# Protocol constants

REQUEST_TYPE_SIZE = 1


# Port number

PORT = 1357


# Username

USERNAME = "eli"


# Password

PASSWORD = "password"


# File name

FILENAME = "file.txt"


# File data

FILE_DATA = "This is a file.".encode()


# AES key

AES_KEY = "1234567890abcdef".encode()


# Function to connect to the server

def connect_to_server():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("localhost", PORT))
    return client_socket


# Function to register with the server

def register_with_server(client_socket):
    request_data = b"R" + USERNAME.encode()
    print(request_data)
    client_socket.send(request_data)

    response = client_socket.recv(1)
    if response == b"S":
        print("Registered with the server successfully.")
    else:
        print("Failed to register with the server.")


# Function to send a file to the server

def send_file_to_server(client_socket):
    request_data = b"F"
    client_socket.send(request_data)

    # Send the file data to the server
    client_socket.send(FILE_DATA)

    # Send the AES key to the server
    client_socket.send(AES_KEY)

    # Receive the CRC from the server
    crc = struct.unpack(">I", client_socket.recv(4))[0]

    # Calculate the CRC of the file data
    file_crc = calculate_crc(FILE_DATA)

    # Verify the CRC
    if crc == file_crc:
        print("File sent successfully.")
    else:
        print("File send failed.")


def main():
    # Connect to the server
    client_socket = connect_to_server()

    # Register with the server
    register_with_server(client_socket)

    # Send a file to the server
    send_file_to_server(client_socket)

    # Close the connection to the server
    client_socket.close()


if __name__ == "__main__":
    main()

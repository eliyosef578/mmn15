import socket
import uuid
import sqlite3
import hashlib
import binascii
import struct
import rsa
import aes
import os
import base64
import json

# Default port
DEFAULT_PORT = 1357

# Database file name
DATABASE_FILE = "db.defensive"

# Table names
CLIENTS_TABLE_NAME = "clients"
FILES_TABLE_NAME = "files"

conn = sqlite3.connect(DATABASE_FILE)
cur = conn.cursor()

# Create the clients table if it doesn't exist
cur.execute("CREATE TABLE IF NOT EXISTS {} (id TEXT PRIMARY KEY, name TEXT NOT NULL, publicKey TEXT, lastSeen DATETIME, aesKey BLOB);".format(CLIENTS_TABLE_NAME))

conn.close()

# Maximum number of retries for file verification
MAX_RETRIES = 3

# Memory clients list
memory_clients = []

insert_client_statement = "INSERT INTO clients (id, name, publicKey, lastSeen, aesKey) VALUES (?, ?, ?, ?, ?)"


# Function to get the port from the info.port file
def get_port():
    try:
        with open("info.port", "r") as f:
            port = int(f.readline())
    except FileNotFoundError:
        print("Warning: info.port file not found. Using default port {}.".format(DEFAULT_PORT))
        port = DEFAULT_PORT
    return port

def insert_client(conn, client):
    """Inserts the client into the database.

    Args:
        conn: A connection to the database.
        client: A dictionary containing the client data.

    Returns:
        None.
    """

    # Convert the JSON object to a string.
    client_json = json.dumps(client)

    # Insert the client data into the database.
    cur = conn.cursor()
    cur.execute(insert_client_statement, (client["id"], client["name"], client["publicKey"], client["lastSeen"], client["aesKey"]))
    conn.commit()

# Function to check if the database exists
def database_exists():
    return os.path.exists(DATABASE_FILE)

# Function to load customer data from the database
def load_customer_data():
    conn = sqlite3.connect(DATABASE_FILE)
    cur = conn.cursor()

    clients = []
    for row in cur.execute("SELECT * FROM {}".format(CLIENTS_TABLE_NAME)):
        client = {
            "id": row[0],
            "name": row[1],
            "publicKey": row[2],
            "lastSeen": row[3],
            "aesKey": row[4],
        }
        client_json = json.dumps(client)
        clients.append(client_json)
        print(client_json)

    conn.close()
    return clients

# Function to store customer data in the database
def store_customer_data(client):
    conn = sqlite3.connect(DATABASE_FILE)
    cur = conn.cursor()

    cur.execute("INSERT INTO {} (id, name, publicKey, lastSeen, aesKey) VALUES (?, ?, ?, ?, ?)".format(CLIENTS_TABLE_NAME),
                (client["id"], client["name"], client["publicKey"], client["lastSeen"], client["aesKey"]))

    conn.commit()
    conn.close()

# Function to store a file in the database
def store_file(file):
    conn = sqlite3.connect(DATABASE_FILE)
    cur = conn.cursor()

    cur.execute("INSERT INTO {} (id, fileName, filePath, verified) VALUES (?, ?, ?, ?)".format(FILES_TABLE_NAME),
                (file["id"], file["fileName"], file["filePath"], file["verified"]))

    conn.commit()
    conn.close()

# Function to calculate the CRC of a file
def calculate_crc(file_path):
    with open(file_path, "rb") as f:
        data = f.read()

    crc = hashlib.crc32(data)
    return crc

# Function to verify the CRC of a file against the client
def verify_crc(file_path, client_crc):
    calculated_crc = calculate_crc(file_path)
    return calculated_crc == client_crc


def handle_client_request(client_socket, request_data):
    # Decode the request according to the protocol

    request_type = request_data[:1]
    print(request_type)
    # Handle the request

    if request_type == b"R":
        # Registration request

        username = request_data[1:256].decode()

        # Check if the username already exists
        conn = sqlite3.connect(DATABASE_FILE)
        aes_key = base64.b64encode(os.urandom(32)).decode("utf-8")
        client = {
            "id": str(uuid.uuid4()),
            "name": username,
            "publicKey": None,
            "lastSeen": None,
            "aesKey": aes_key,
        }

        # Add the client to the memory clients list
        try:
            memory_clients.append(client)
        except Exception as e:
            print(f"memory client error:  {client}")
        # Store the client data in the database
        try:
            print(client)
            client_json = json.dumps(client)
            print(client_json)
        except Exception as e:
            print(f"json dumps error:{e}")

        try:
            insert_client(conn, client)
        except Exception as e:
            print(f"Error inserting client: {e}")

        # Send the client a success message
        try:
            print(f"reqeust type is: {request_type}")
            print(load_customer_data())
            client_socket.send(b"S")
        except Exception as e:
            print(f"failed to send data to client : {e}")

    elif request_type == b"P":
        # Public key request

        publicKey = rsa.generate_public_key()

        # Send the public key to the client
        client_socket.send(publicKey.export_key())

    elif request_type == b"F":
        # File request

        # Receive the file data from the client
        fileData = client_socket.recv(1024)

        # Check if the file data is valid
        if len(fileData) < 512:
            # File is too short
            client_socket.send(b"E")
            return

        # Decrypt the encrypted file using the AES key from the client
        aesKey = binascii.unhexlify(client_socket.recv(32))
        decryptedFileData = aes.decrypt(fileData, aesKey)

        # Calculate the CRC of the decrypted file
        crc = calculate_crc(decryptedFileData)

        # Send the CRC to the client
        client_socket.send(struct.pack(">I", crc))

        # Receive the client's response
        clientResponse = client_socket.recv(1)

        # If the client's response is "Y", the file was verified successfully
        if clientResponse == b"Y":
            # Store the file in the database
            fileName = decryptedFileData[0:255].decode()
            filePath = "files/{}.enc".format(decryptedFileData[255:255 + 32])
            file = {
                "id": request_type,
                "fileName": fileName,
                "filePath": filePath,
                "verified": True,
            }
            store_file(file)

        else:
            # The file was not verified successfully
            print("File verification failed for file {}.".format(fileName))

    else:
        # Unknown request type
        print("Unknown request type: {}".format(request_type))

    # Close the client socket
    client_socket.close()



# Main function
def main():
    # Get the port number from the info.port file
    port = get_port()

    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the port
    server_socket.bind(("0.0.0.0", port))

    # Listen for incoming connections
    server_socket.listen(10)

    # Loop forever, accepting new connections
    while True:
        # Accept a new connection
        client_socket, client_address = server_socket.accept()

        # Handle the client request
        try:
            handle_client_request(client_socket, client_socket.recv(1024))
        except Exception as e:
            print(f"Error handling client request: {e}")


main()
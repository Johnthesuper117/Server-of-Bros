# a server to send and receive messages using sockets to client and vice versa with encryption
import socket
import threading
from cryptography.fernet import Fernet # for encryption and decryption
import os
import base64
import hashlib
from dotenv import load_dotenv
load_dotenv()
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load the secret key from environment variable
SECRET_KEY = os.getenv('SECRET_KEY')
if not SECRET_KEY:
    raise ValueError("No SECRET_KEY found in environment variables")

# Function to generate a Fernet key from the SECRET_KEY
def generate_fernet_key(secret_key):
    # Use SHA-256 to hash the secret key and then base64 encode it to get a 32-byte key
    sha256_hash = hashlib.sha256(secret_key.encode()).digest()
    fernet_key = base64.urlsafe_b64encode(sha256_hash)
    return fernet_key

# Generate the Fernet key
FERNET_KEY = generate_fernet_key(SECRET_KEY)

# Initialize Fernet with the generated key
fernet = Fernet(FERNET_KEY)

# Server configuration
SERVER_HOST = 'localhost'
SERVER_PORT = 50000

# Function to handle client connections
def handle_client(client_socket, client_address):
    logger.info(f"New connection from {client_address}")
    try:
        while True:
            # Receive encrypted message from client
            encrypted_message = client_socket.recv(4096)
            if not encrypted_message:
                break
            # Decrypt the message
            try:
                decrypted_message = fernet.decrypt(encrypted_message).decode()
                logger.info(f"Received from {client_address}: {decrypted_message}")
            except Exception as e:
                logger.error(f"Decryption error: {e}")
                continue
            # Echo back the message (encrypted)
            response = f"Echo: {decrypted_message}"
            encrypted_response = fernet.encrypt(response.encode())
            client_socket.sendall(encrypted_response)
    except Exception as e:
        logger.error(f"Error handling client {client_address}: {e}")
    finally:
        client_socket.close()
        logger.info(f"Connection closed for {client_address}")

# Set-up the server
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((SERVER_HOST, SERVER_PORT))
    server.listen(5)
    logger.info(f"Server listening on {SERVER_HOST}:{SERVER_PORT}")
    try:
        while True:
            client_socket, client_address = server.accept()
            client_handler = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_handler.start()
    except KeyboardInterrupt:
        logger.info("Server shutting down...")
    finally:
        server.close()

# Start the server
if __name__ == "__main__":
    start_server()

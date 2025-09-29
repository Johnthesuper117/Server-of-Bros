# a client to send and receive messages using sockets to server and vice versa with encryption
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

# Client configuration
SERVER_HOST = 'localhost'
SERVER_PORT = 50000

# Function to handle receiving messages from server
def receive_messages(client_socket):
    try:
        while True:
            # Receive encrypted message from server
            encrypted_message = client_socket.recv(4096)
            if not encrypted_message:
                break
            # Decrypt the message
            try:
                decrypted_message = fernet.decrypt(encrypted_message).decode()
                logger.info(f"Received from server: {decrypted_message}")
            except Exception as e:
                logger.error(f"Decryption error: {e}")
    except Exception as e:
        logger.error(f"Error receiving messages: {e}")
    finally:
        client_socket.close()
        logger.info("Connection closed")

# Function to start the client
def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((SERVER_HOST, SERVER_PORT))
        logger.info(f"Connected to server at {SERVER_HOST}:{SERVER_PORT}")
        # Start a thread to receive messages from server
        threading.Thread(target=receive_messages, args=(client_socket,), daemon=True).start()
        while True:
            message = input("Enter message to send (or 'exit' to quit): ")
            if message.lower() == 'exit':
                break
            # Encrypt the message
            encrypted_message = fernet.encrypt(message.encode())
            client_socket.sendall(encrypted_message)
    except Exception as e:
        logger.error(f"Error in client: {e}")
    finally:
        client_socket.close()
        logger.info("Client socket closed")

# Start the client
if __name__ == "__main__":
    start_client()
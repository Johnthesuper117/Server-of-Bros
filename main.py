#I want to make my own discord clone
# so I'm making a simple
# encrypted server that sends and recieves data like files and messages to and from HTML web clients 
# make sure it sends to index.html
# and make sure it can handle multiple clients

import socket
import threading
import os
from cryptography.fernet import Fernet
from matplotlib.pylab import broadcast # for encryption

# Generate a key for encryption
key = Fernet.generate_key()
cipher = Fernet(key)
print(f"Encryption Key: {key.decode()}")

# Server configuration
HOST = '0.0.0.0'
PORT = 8080
BUFFER_SIZE = 1024
clients = []
client_usernames = {}
client_addresses = {}

# Function to handle client connections
def handle_client(client_socket, address):
    print(f"[NEW CONNECTION] {address} connected.")
    client_socket.send("Welcome to the server! Please enter your username: ".encode())
    username = client_socket.recv(BUFFER_SIZE).decode().strip()
    client_usernames[client_socket] = username
    client_addresses[client_socket] = address
    broadcast(f"{username} has joined the chat!", client_socket)

    while True:
        try:
            encrypted_message = client_socket.recv(BUFFER_SIZE)
            if not encrypted_message:
                break
            message = cipher.decrypt(encrypted_message).decode()
            print(f"[{username}] {message}")
            broadcast(f"[{username}] {message}", client_socket)
        except Exception as e:
            print(f"[ERROR] {e}")
            break

    print(f"[DISCONNECT] {address} disconnected.")
    broadcast(f"{username} has left the chat.", client_socket)
    clients.remove(client_socket)
    del client_usernames[client_socket]
    del client_addresses[client_socket]
    client_socket.close()


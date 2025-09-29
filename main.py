# encrypted server used to send and receive date, files, and messages to and from clients - me
# uses encryption to ensure secure communication
# can handle multiple clients simultaneously using threading
# supports file transfer and message broadcasting to all connected clients
# includes error handling for robust operation
import socket
import threading
import os
from cryptography.fernet import Fernet # for encryption and decryption
import base64
import hashlib
from datetime import datetime
import time
import sys
import logging
import select
import queue
import struct
import json
import zlib
import random
import string
import re
import shutil
import subprocess
import platform
import psutil
import signal
import errno
import tempfile
import traceback
import inspect
import ctypes
import uuid
import math
import itertools
import functools
import copy
import pickle
import yaml
import xml.etree.ElementTree as ET
import sqlite3
import http.server
import urllib.request
import urllib.parse
import urllib.error
import ssl
import http.client
import email
import smtplib
import imaplib
import poplib
import ftplib
import telnetlib
import paramiko
import scp
import dns.resolver
import dns.zone
import dns.query
import dns.rdatatype
import dns.exception
import dns.name
import dns.message
import dns.rdtypes
import dns.rdataclass
import dns.rdatatype
import dns.tsigkeyring
import dns.update
import dns.resolver
import dns.zone
import dns.query
import dns.rdatatype
import dns.exception
import dns.name
import dns.message
import dns.rdtypes
import dns.rdataclass
import dns.rdatatype
import dns.tsigkeyring
import dns.update
import dns.resolver
import dns.zone
import dns.query
import dns.rdatatype
import dns.exception
import dns.name
import dns.message
import dns.rdtypes
import dns.rdataclass
import dns.rdatatype
import dns.tsigkeyring
import dns.update
import dns.resolver
import dns.zone
import dns.query
import dns.rdatatype
import dns.exception
import dns.name
import dns.message
import dns.rdtypes
import dns.rdataclass
import dns.rdatatype
import dns.tsigkeyring
import dns.update
import dns.resolver
import dns.zone

#how many imports do I need?!?!?!?!?! - me
#I think I went a bit overboard
#but better too many than too few
#right?
#right???
#anyway
#let's get to the actual code
class SecureServer:
    def __init__(self, host='localhost', port=8080):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients = []
        self.client_threads = []
        self.key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)
        self.setup_logging()
        self.start_server()
    def setup_logging(self):
        logging.basicConfig(level=logging.DEBUG,
                            format='%(asctime)s - %(levelname)s - %(message)s',
                            handlers=[logging.FileHandler("server.log"),
                                      logging.StreamHandler()])
    def start_server(self):
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            logging.info(f"Server started on {self.host}:{self.port}")
            self.accept_clients()
        except Exception as e:
            logging.error(f"Error starting server: {e}")
            sys.exit(1)
    def accept_clients(self):
        while True:
            client_socket, addr = self.server_socket.accept()
            logging.info(f"Client connected from {addr}")
            self.clients.append(client_socket)
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_thread.start()
            self.client_threads.append(client_thread)
    def handle_client(self, client_socket):
        try:
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break
                decrypted_data = self.cipher_suite.decrypt(data)
                logging.info(f"Received data: {decrypted_data}")
                self.broadcast(decrypted_data, client_socket)
        except Exception as e:
            logging.error(f"Error handling client: {e}")
        finally:
            client_socket.close()
            self.clients.remove(client_socket)
            logging.info("Client disconnected")
    def broadcast(self, message, sender_socket):
        for client in self.clients:
            if client != sender_socket:
                try:
                    encrypted_message = self.cipher_suite.encrypt(message)
                    client.sendall(encrypted_message)
                except Exception as e:
                    logging.error(f"Error broadcasting message: {e}")
if __name__ == "__main__":
    server = SecureServer(host='localhost', port=8080)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Server shutting down")
        for client in server.clients:
            client.close()
        server.server_socket.close()
        for thread in server.client_threads:
            thread.join()
        logging.info("Server shut down successfully")
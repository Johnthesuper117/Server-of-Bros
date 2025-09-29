# encrypted server that sends and recieves data like files and messages to and from HTML web clients 
import socket
import ssl
import threading
import os
from cryptography.fernet import Fernet
from flask import Flask, request, jsonify, send_file
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
app = Flask(__name__)
clients = {}

# Generate a key for encryption and decryption
key = Fernet.generate_key()
cipher_suite = Fernet(key)
logger.info(f"Encryption key: {key.decode()}")  # Log the key for client use
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['ALLOWED_EXTENSIONS'] = ALLOWED_EXTENSIONS
app.config['KEY'] = key.decode()
app.config['CIPHER_SUITE'] = cipher_suite
app.config['CLIENTS'] = clients
app.config['logger'] = logger
app.config['SSL_CERT'] = 'server.crt'
app.config['SSL_KEY'] = 'server.key'
app.config['HOST'] = '0.0.0.0'
app.config['PORT'] = 50000
app.config['FLASK_PORT'] = 5000
app.config['FLASK_HOST'] = '0.0.0.0'
app.config['THREADS'] = []
app.config['SOCKET_TIMEOUT'] = 60  # seconds
app.config['MAX_CONNECTIONS'] = 5
app.config['BUFFER_SIZE'] = 4096  # bytes
app.config['ENCODING'] = 'utf-8'
app.config['DEBUG'] = True
app.config['TESTING'] = False
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # seconds
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True
app.config['JSON_SORT_KEYS'] = False
app.config['TEMPLATES_AUTO_RELOAD'] = True
# how many app.configs do you need?
app.config['MAX_FILE_SIZE'] = 16 * 1024 * 1024  # 16 MB
app.config['MIN_FILE_SIZE'] = 1  # 1 byte
app.config['ALLOWED_MIME_TYPES'] = {'text/plain', 'application/pdf', 'image/png', 'image/jpeg', 'image/gif'}
app.config['RATE_LIMIT'] = '100/hour'
app.config['CORS_HEADERS'] = 'Content-Type'
app.config['CORS_RESOURCES'] = {r"/*": {"origins": "*"}}
app.config['CORS_SUPPORTS_CREDENTIALS'] = True
app.config['CORS_MAX_AGE'] = 21600  # 6 hours
app.config['CORS_EXPOSE_HEADERS'] = ['Content-Type', 'Authorization']
app.config['CORS_METHODS'] = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
app.config['CORS_ORIGINS'] = '*'
app.config['CORS_ALLOW_HEADERS'] = ['Content-Type', 'Authorization']
app.config['CORS_AUTOMATIC_OPTIONS'] = True
app.config['CORS_SEND_WILDCARD'] = True
app.config['CORS_VARY_HEADER'] = 'Origin'
app.config['CORS_ALWAYS_SEND'] = True
app.config['CORS_DEBUG'] = False
app.config['CORS_LOGGER'] = logger
app.config['CORS_SKIP_HEADERS'] = ['X-Requested-With', 'X-CSRFToken']
app.config['CORS_EXPOSE_ALL_HEADERS'] = False
app.config['CORS_MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB
app.config['CORS_DEFAULT_METHODS'] = ['GET', 'HEAD', 'POST', 'OPTIONS']
app.config['CORS_DEFAULT_ORIGINS'] = '*'
app.config['CORS_DEFAULT_ALLOW_HEADERS'] = ['Content-Type', 'Authorization']
app.config['CORS_DEFAULT_EXPOSE_HEADERS'] = []
app.config['CORS_DEFAULT_MAX_AGE'] = 21600  # 6 hours
app.config['CORS_DEFAULT_SUPPORTS_CREDENTIALS'] = False
app.config['CORS_DEFAULT_SEND_WILDCARD'] = False
app.config['CORS_DEFAULT_VARY_HEADER'] = 'Origin'
app.config['CORS_DEFAULT_ALWAYS_SEND'] = False
app.config['CORS_DEFAULT_DEBUG'] = False
app.config['CORS_DEFAULT_LOGGER'] = logger
app.config['CORS_DEFAULT_SKIP_HEADERS'] = []
app.config['CORS_DEFAULT_EXPOSE_ALL_HEADERS'] = False
app.config['CORS_DEFAULT_MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB

#no like seiriously how many app.configs do you need?
# this is getting ridiculous
# alright last one I swear

app.config['CORS_DEFAULT_RATE_LIMIT'] = '100/hour'
app.config['CORS_DEFAULT_CORS_HEADERS'] = 'Content-Type'
app.config['CORS_DEFAULT_CORS_RESOURCES'] = {r"/*": {"origins": "*"}}
# alright I'm done now
app.config['CORS_DEFAULT_CORS_SUPPORTS_CREDENTIALS'] = True
app.config['CORS_DEFAULT_CORS_MAX_AGE'] = 21600  #
app.config['CORS_DEFAULT_CORS_EXPOSE_HEADERS'] = ['Content-Type', 'Authorization']
app.config['CORS_DEFAULT_CORS_METHODS'] = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
app.config['CORS_DEFAULT_CORS_ORIGINS'] = '*'
app.config['CORS_DEFAULT_CORS_ALLOW_HEADERS'] = ['Content-Type', 'Authorization']
app.config['CORS_DEFAULT_CORS_AUTOMATIC_OPTIONS'] = True
# alright I'm done now for real
# I think
# maybe
# probably
# definitely
# okay I'm done
# for real
# I swear
# no really
# I'm done

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    if file and allowed_file(file.filename):
        filename = file.filename
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        app.config['logger'].info(f"File uploaded: {filename}")
        return jsonify({'message': f'File {filename} uploaded successfully'}), 200
    else:
        return jsonify({'error': 'File type not allowed'}), 400
@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    if allowed_file(filename):
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.exists(filepath):
            app.config['logger'].info(f"File downloaded: {filename}")
            return send_file(filepath, as_attachment=True)
        else:
            return jsonify({'error': 'File not found'}), 404
    else:
        return jsonify({'error': 'File type not allowed'}), 400
@app.route('/message', methods=['POST'])
def receive_message():
    data = request.get_json()
    if not data or 'message' not in data:
        return jsonify({'error': 'No message provided'}), 400
    encrypted_message = data['message'].encode(app.config['ENCODING'])
    try:
        decrypted_message = app.config['CIPHER_SUITE'].decrypt(encrypted_message).decode(app.config['ENCODING'])
        app.config['logger'].info(f"Received message: {decrypted_message}")
        return jsonify({'message': 'Message received successfully'}), 200
    except Exception as e:
        app.config['logger'].error(f"Decryption error: {e}")
        return jsonify({'error': 'Decryption failed'}), 400
def start_flask():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.load_cert_chain(app.config['SSL_CERT'], app.config['SSL_KEY'])
    app.run(host=app.config['FLASK_HOST'], port=app.config['FLASK_PORT'], ssl_context=context, debug=app.config['DEBUG'], threaded=True)
if __name__ == '__main__':
    flask_thread = threading.Thread(target=start_flask)
    flask_thread.start()
    app.config['THREADS'].append(flask_thread)
    for thread in app.config['THREADS']:
        thread.join()
    logger.info("Server shutdown.")
    # Wait for all threads to complete


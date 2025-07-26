from flask import Flask, render_template, request, jsonify, session
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
from datetime import datetime, timedelta
import json
import base64
import secrets
from functools import wraps
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import uuid
import ssl
import eventlet

# Patch for eventlet SSL support
eventlet.monkey_patch()

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_urlsafe(32)
CORS(app, origins="*")

# Initialize SocketIO without async_mode for eventlet
socketio = SocketIO(app, cors_allowed_origins="*")

# Store active authentication requests
auth_requests = {}

# In production, store these in a database
DEVICE_KEYS = {
    'esp32_XXXXXXXXXX': """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEK2aTwJYDOYhneZtlRhAJEW0qXhP1
hg5A6FR8Z3GQmhEWP1zw9pBCxqHmT8ggfbT8WIs7zj8ej5EZpZnJ5H9IkQ==
-----END PUBLIC KEY-----"""
}

def verify_device_signature(device_id, payload_b64, signature_b64):
    """Verify ECDSA signature from ESP32 device"""
    if device_id not in DEVICE_KEYS:
        return False

    try:
        # Load public key
        public_key = serialization.load_pem_public_key(
            DEVICE_KEYS[device_id].encode(),
            backend=default_backend()
        )

        # Decode payload and signature
        payload = base64.b64decode(payload_b64)
        signature = base64.b64decode(signature_b64)

        # Parse payload to verify timestamp
        payload_data = json.loads(payload)
        timestamp = datetime.fromisoformat(payload_data['timestamp'].replace('Z', '+00:00'))

        # Check if timestamp is recent (within 5 minutes)
        if abs((datetime.utcnow() - timestamp.replace(tzinfo=None)).total_seconds()) > 300:
            return False

        # Verify signature
        public_key.verify(
            signature,
            payload,
            ec.ECDSA(hashes.SHA256())
        )

        return payload_data

    except (InvalidSignature, json.JSONDecodeError, KeyError, ValueError):
        return False

@app.route('/')
def index():
    return render_template('login.html')

@socketio.on('connect')
def handle_connect():
    print(f'Client connected: {request.sid}')
    emit('connected', {'data': 'Connected to authentication server'})

@socketio.on('disconnect')
def handle_disconnect():
    print(f'Client disconnected: {request.sid}')
    # Clean up any pending auth requests
    auth_requests.pop(request.sid, None)

@socketio.on('request_auth')
def handle_auth_request(data):
    """Handle authentication request from web client"""
    auth_id = str(uuid.uuid4())

    auth_requests[auth_id] = {
        'session_id': request.sid,
        'timestamp': datetime.utcnow(),
        'status': 'pending'
    }

    # Clean up old requests
    cleanup_auth_requests()

    emit('auth_requested', {
        'auth_id': auth_id,
        'message': 'Please look at the ESP32 camera for authentication'
    })

def cleanup_auth_requests():
    """Remove authentication requests older than 5 minutes"""
    current_time = datetime.utcnow()
    expired = []

    for auth_id, req in auth_requests.items():
        if (current_time - req['timestamp']).total_seconds() > 300:
            expired.append(auth_id)

    for auth_id in expired:
        auth_requests.pop(auth_id, None)

@app.route('/auth/verify', methods=['POST'])
def verify_token():
    """Verify authentication token from ESP32"""
    try:
        data = request.get_json()

        if not all(k in data for k in ['token', 'device_id']):
            return jsonify({'error': 'Missing required fields'}), 400

        # Verify device signature
        payload_data = verify_device_signature(
            data['device_id'],
            data['token']['payload'],
            data['token']['signature']
        )

        if not payload_data:
            return jsonify({'error': 'Invalid signature or expired token'}), 401

        # Extract user information
        user_id = payload_data['user_id']
        device_id = payload_data['device_id']

        # Find matching auth request (in production, match by additional criteria)
        for auth_id, auth_req in list(auth_requests.items()):
            if auth_req['status'] == 'pending':
                # Update auth request
                auth_req['status'] = 'authenticated'
                auth_req['user_id'] = user_id
                auth_req['device_id'] = device_id

                # Notify web client via WebSocket
                socketio.emit('auth_success', {
                    'auth_id': auth_id,
                    'user_id': user_id,
                    'device_id': device_id,
                    'message': f'Successfully authenticated as {user_id}'
                }, room=auth_req['session_id'])

                # Create session
                session['user_id'] = user_id
                session['device_id'] = device_id
                session['authenticated'] = True

                return jsonify({
                    'status': 'success',
                    'user_id': user_id,
                    'session_token': secrets.token_urlsafe(32)
                }), 200

        return jsonify({'error': 'No pending authentication request'}), 404

    except Exception as e:
        print(f"Error in verify_token: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/dashboard')
def dashboard():
    if not session.get('authenticated'):
        return redirect('/')

    return render_template('dashboard.html', user_id=session.get('user_id'))

if __name__ == '__main__':
    # Create SSL context for development
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

    # For development, create self-signed certificate
    # In production, use proper certificates
    try:
        context.load_cert_chain('cert.pem', 'key.pem')
    except FileNotFoundError:
        print("Certificate files not found. Running without SSL.")
        print("To create self-signed certificates, run:")
        print("openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes")

        # Run without SSL for now
        socketio.run(app, debug=True, host='0.0.0.0', port=5000)
    else:
        # Run with SSL
        socketio.run(app, debug=True, host='0.0.0.0', port=5000,
                     keyfile='key.pem', certfile='cert.pem')
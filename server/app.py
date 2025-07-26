from flask import Flask, render_template, request, jsonify, session
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
import base64
import json
import time
import uuid
from datetime import datetime, timedelta
from threading import Lock

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this###############################################################'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Thread-safe storage for pending authentications
pending_auths = {}
auth_lock = Lock()

# Store public keys for registered devices
DEVICE_KEYS = {
    "device_001": """-----BEGIN PUBLIC KEY-----
########################################################################################################################
-----END PUBLIC KEY-----"""
}

@app.route('/')
def index():
    return render_template('login.html')

@socketio.on('connect')
def handle_connect():
    print(f'Client connected: {request.sid}')
    emit('connected', {'status': 'Connected to authentication server'})

@socketio.on('disconnect')
def handle_disconnect():
    print(f'Client disconnected: {request.sid}')
    # Clean up any pending authentications
    with auth_lock:
        pending_auths.pop(request.sid, None)

@socketio.on('request_auth')
def handle_auth_request(data):
    """Client requests authentication"""
    auth_id = str(uuid.uuid4())

    with auth_lock:
        pending_auths[auth_id] = {
            'session_id': request.sid,
            'timestamp': datetime.now(),
            'status': 'pending'
        }

    emit('auth_requested', {
        'auth_id': auth_id,
        'message': 'Waiting for biometric authentication...'
    })

    # Set timeout to clean up after 60 seconds
    socketio.start_background_task(cleanup_auth_request, auth_id)

def cleanup_auth_request(auth_id):
    """Remove auth request after timeout"""
    socketio.sleep(60)
    with auth_lock:
        if auth_id in pending_auths and pending_auths[auth_id]['status'] == 'pending':
            session_id = pending_auths[auth_id]['session_id']
            pending_auths.pop(auth_id, None)
            socketio.emit('auth_timeout', {'message': 'Authentication timeout'}, room=session_id)

@app.route('/auth/verify', methods=['POST'])
def verify_token():
    """ESP32 sends authentication token here"""
    try:
        data = request.json
        token = data.get('token')
        device_id = data.get('device_id')
        auth_id = data.get('auth_id')  # Optional: link to specific auth request

        # Decode token
        token_data = json.loads(base64.b64decode(token['payload']))
        signature = base64.b64decode(token['signature'])

        # Verify timestamp
        token_time = datetime.fromisoformat(token_data['timestamp'])
        if datetime.now() - token_time > timedelta(seconds=60):
            return jsonify({'status': 'error', 'message': 'Token expired'}), 401

        # Verify signature
        public_key_pem = DEVICE_KEYS.get(device_id)
        if not public_key_pem:
            return jsonify({'status': 'error', 'message': 'Unknown device'}), 401

        public_key = serialization.load_pem_public_key(public_key_pem.encode())

        # Verify ECDSA signature
        try:
            public_key.verify(
                signature,
                token['payload'].encode(),
                ec.ECDSA(hashes.SHA256())
            )
        except InvalidSignature:
            return jsonify({'status': 'error', 'message': 'Invalid signature'}), 401

        # Find pending authentication request
        with auth_lock:
            # If auth_id provided, find specific request
            if auth_id and auth_id in pending_auths:
                auth_request = pending_auths[auth_id]
                session_id = auth_request['session_id']
                pending_auths[auth_id]['status'] = 'completed'
            else:
                # Find most recent pending request
                recent_auth = None
                for aid, auth in pending_auths.items():
                    if auth['status'] == 'pending':
                        if not recent_auth or auth['timestamp'] > recent_auth['timestamp']:
                            recent_auth = auth
                            auth_id = aid

                if not recent_auth:
                    return jsonify({'status': 'error', 'message': 'No pending authentication'}), 400

                session_id = recent_auth['session_id']
                pending_auths[auth_id]['status'] = 'completed'

        # Notify client via WebSocket
        socketio.emit('auth_success', {
            'user_id': token_data['user_id'],
            'device_id': device_id,
            'message': 'Authentication successful'
        }, room=session_id)

        # Clean up
        with auth_lock:
            pending_auths.pop(auth_id, None)

        return jsonify({
            'status': 'success',
            'message': 'Authentication successful',
            'user_id': token_data['user_id']
        })

    except Exception as e:
        print(f"Error in verify_token: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 400

@app.route('/dashboard')
def dashboard():
    if not session.get('authenticated'):
        return redirect('/')
    return render_template('dashboard.html', user_id=session.get('user_id'))

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, ssl_context='adhoc')
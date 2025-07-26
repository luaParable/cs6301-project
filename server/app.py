from flask import Flask, render_template, request, jsonify, session
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.exceptions import InvalidSignature
import base64
import json
import time
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'

# Store public keys for registered devices (in production, use database)
DEVICE_KEYS = {
    "device_001": """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
-----END PUBLIC KEY-----"""
}

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/auth/verify', methods=['POST'])
def verify_token():
    try:
        data = request.json
        token = data.get('token')
        device_id = data.get('device_id')

        # Decode token
        token_data = json.loads(base64.b64decode(token['payload']))
        signature = base64.b64decode(token['signature'])

        # Verify timestamp (token valid for 60 seconds)
        token_time = datetime.fromisoformat(token_data['timestamp'])
        if datetime.now() - token_time > timedelta(seconds=60):
            return jsonify({'status': 'error', 'message': 'Token expired'}), 401

        # Verify signature
        public_key_pem = DEVICE_KEYS.get(device_id)
        if not public_key_pem:
            return jsonify({'status': 'error', 'message': 'Unknown device'}), 401

        public_key = serialization.load_pem_public_key(public_key_pem.encode())

        try:
            public_key.verify(
                signature,
                token['payload'].encode(),
                ec.ECDSA(hashes.SHA256())
            )
        except InvalidSignature:
            return jsonify({'status': 'error', 'message': 'Invalid signature'}), 401

        # Authentication successful
        session['user_id'] = token_data['user_id']
        session['authenticated'] = True

        return jsonify({
            'status': 'success',
            'message': 'Authentication successful',
            'user_id': token_data['user_id']
        })

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@app.route('/dashboard')
def dashboard():
    if not session.get('authenticated'):
        return redirect('/')
    return f"<h1>Welcome User {session['user_id']}!</h1><a href='/logout'>Logout</a>"

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000, ssl_context='adhoc')
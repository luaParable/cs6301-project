import eventlet
eventlet.monkey_patch()

import threading
import time
from app import app, socketio

def run_https():
    """Run HTTPS server on port 5000"""
    print("Starting HTTPS server on https://192.168.4.37:5000")
    socketio.run(app, debug=False, host='0.0.0.0', port=5000,
                 keyfile='key.pem', certfile='cert.pem')

def run_http():
    """Run HTTP server on port 5001"""
    print("Starting HTTP server on http://192.168.4.37:5001")
    socketio.run(app, debug=False, host='0.0.0.0', port=5001)

if __name__ == '__main__':
    import os

    # Check if certificates exist
    cert_exists = os.path.exists('cert.pem') and os.path.exists('key.pem')

    if cert_exists:
        # Run both HTTP and HTTPS
        https_thread = threading.Thread(target=run_https)
        https_thread.daemon = True
        https_thread.start()

        time.sleep(1)  # Give HTTPS time to start

        print("\nBoth servers running:")
        print("- HTTPS: https://192.168.4.37:5000")
        print("- HTTP: http://192.168.4.37:5001")
        print("\nPress Ctrl+C to stop\n")

        # Run HTTP in main thread
        run_http()
    else:
        print("Certificate files not found. Running HTTP only.")
        print("To enable HTTPS, create certificates with:")
        print("openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes")
        run_http()
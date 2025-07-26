# TinyML Authentication System

A biometric authentication system using ESP32 with camera module and Flask server.

## Prerequisites

- Python 3.11
- ESP32 with camera module
- WiFi network (both ESP32 and computer must be on same network)
- OpenSSL (for certificate generation)

## Server Setup

### 1. Clone Repository

```
git clone https://github.com/luaParable/cs6301-project.git
cd cs6301-project/server
```

### 2. Create Virtual Environment

```
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS/Linux
source .venv/bin/activate
```

### 3. Install Dependencies

```
pip install -r requirements.txt
```

### 4. Find Your IP Address

```
# Windows
ipconfig

# macOS/Linux
ifconfig
```

### 5. Generate SSL Certificate. Use your IP Adress as the common name in setup.

```
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

### 6. Run Server

A. Single Protocol (Will only run HTTPS if certificates exist, otherwise HTTP)
```
cd server
python app.py
```

B. Dual Protocol (Will run both HTTP and HTTPS servers at 5000 and 5001 ports)
```
cd server
python run_servers.py
```

## ESP32 Setup

### 1. Update WiFi credentials in ESP32 code

```
const char* ssid = "YOUR_WIFI_SSID";
const char* password = "YOUR_WIFI_PASSWORD";
```

### 2. Update server URL with your IP

```
const char* serverUrl = "https://YOUR_IP:5000/auth/verify";
```

### 3. Upload code to ESP32 using Arduino IDE or PlatformIO

## Testing

1. Access web interface at `https://YOUR_IP:5000` (accept self-signed certificate warning)
2. Click "Request Authentication"
3. Look at ESP32 camera for face recognition
4. Check console for authentication status

## Troubleshooting

- **Connection refused**: Check Windows Firewall, allow port 5000
- **SSL errors**: Ensure certificate CN matches your IP address
- **ESP32 can't connect**: Verify both devices on same network
- **No camera feed**: Check ESP32 camera connections

## Security Notes

- Self-signed certificates are for development only
- Use proper SSL certificates in production
- Store device public keys securely
- Implement proper session management for production use

The server will be accessible at:
- **HTTPS**: `https://your.ip.address:5000` (recommended for production)
- **HTTP**: `http://your.ip.address:5000` (if you want to skip SSL for testing)


# For Yogeswar!

The team member with the ESP32 camera needs to:

## 1. After you have set up the system based on the README above to work with your information:

## 2. Flash ESP32

Using Arduino IDE or PlatformIO:
- Connect ESP32 via USB
- Select correct board (ESP32-CAM or similar)
- Select correct COM port
- Upload the code

## 3. Start Flask Server

On your computer:
```
cd server
python app.py
```

## 4. Test Authentication Flow

1. **Open browser** on any device on same network: `https://your.ip.address:5000`
2. **Accept certificate warning** (it's self-signed)
3. **Click "Request Authentication"** button on webpage
4. **Position yourself** in front of ESP32 camera
5. **Watch serial monitor** (Arduino IDE: Tools > Serial Monitor, 115200 baud) for debug output
6. **Check browser** for authentication success message

The ESP32 will detect faces, generate authentication tokens, and send them to your Flask server automatically when someone looks at the camera during an active authentication request.
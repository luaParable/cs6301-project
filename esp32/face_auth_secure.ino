#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <base64.h>
#include <uECC.h>
#include "mbedtls/sha256.h"
#include "esp_camera.h"
#include <face_recognition_inferencing.h>
#include <Preferences.h>  // For secure storage
#include "esp_system.h"
#include "esp_efuse.h"

// WiFi credentials
const char* ssid = "YOUR_WIFI_SSID";
const char* password = "YOUR_WIFI_PASSWORD";
const char* serverUrl = "https://YOUR_SERVER_IP:5000/auth/verify";

// NVS namespace for secure storage
Preferences preferences;
const char* NVS_NAMESPACE = "auth_keys";

// Camera pins (same as before)
#define PWDN_GPIO_NUM     32
// ... (other pin definitions)

// Security parameters
#define KEY_DERIVATION_ITERATIONS 10000
#define SALT_SIZE 16

// Device info
char deviceId[32];
uint8_t privateKey[32];
uint8_t publicKey[64];

// Secure key management class
class SecureKeyManager {
private:
    uint8_t deviceSecret[32];
    uint8_t salt[SALT_SIZE];

public:
    SecureKeyManager() {
        // Initialize hardware RNG
        bootloader_random_enable();
    }

    bool initialize() {
        preferences.begin(NVS_NAMESPACE, false);

        // Check if keys exist
        if (!preferences.isKey("private_key")) {
            Serial.println("Generating new key pair...");
            return generateAndStoreKeys();
        } else {
            Serial.println("Loading existing keys...");
            return loadKeys();
        }
    }

    bool generateAndStoreKeys() {
        const struct uECC_Curve_t * curve = uECC_secp256r1();

        // Generate random salt
        esp_fill_random(salt, SALT_SIZE);

        // Generate key pair
        if (!uECC_make_key(publicKey, privateKey, curve)) {
            Serial.println("Key generation failed!");
            return false;
        }

        // Derive encryption key from device-specific data
        deriveDeviceSecret();

        // Encrypt private key before storage
        uint8_t encryptedKey[32];
        encryptData(privateKey, encryptedKey, 32);

        // Store encrypted key and salt
        preferences.putBytes("private_key", encryptedKey, 32);
        preferences.putBytes("public_key", publicKey, 64);
        preferences.putBytes("salt", salt, SALT_SIZE);

        // Generate device ID from chip ID
        uint64_t chipId = ESP.getEfuseMac();
        sprintf(deviceId, "esp32_%llX", chipId);
        preferences.putString("device_id", deviceId);

        preferences.end();
        return true;
    }

    bool loadKeys() {
        // Load encrypted key and salt
        uint8_t encryptedKey[32];

        size_t keyLen = preferences.getBytes("private_key", encryptedKey, 32);
        size_t pubLen = preferences.getBytes("public_key", publicKey, 64);
        size_t saltLen = preferences.getBytes("salt", salt, SALT_SIZE);
        preferences.getString("device_id", deviceId, sizeof(deviceId));

        if (keyLen != 32 || pubLen != 64 || saltLen != SALT_SIZE) {
            Serial.println("Invalid key data!");
            return false;
        }

        // Derive decryption key
        deriveDeviceSecret();

        // Decrypt private key
        decryptData(encryptedKey, privateKey, 32);

        preferences.end();
        return true;
    }

private:
    void deriveDeviceSecret() {
        // Use chip-specific data for key derivation
        uint8_t chipId[8];
        esp_efuse_mac_get_default(chipId);

        // Simple KDF using SHA256 (in production, use PBKDF2)
        mbedtls_sha256_context ctx;
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_starts(&ctx, 0);
        mbedtls_sha256_update(&ctx, chipId, 8);
        mbedtls_sha256_update(&ctx, salt, SALT_SIZE);

        // Multiple iterations
        uint8_t temp[32];
        for (int i = 0; i < KEY_DERIVATION_ITERATIONS; i++) {
            mbedtls_sha256_update(&ctx, (i == 0) ? chipId : temp, (i == 0) ? 8 : 32);
            mbedtls_sha256_finish(&ctx, temp);
            mbedtls_sha256_starts(&ctx, 0);
        }

        mbedtls_sha256_finish(&ctx, deviceSecret);
        mbedtls_sha256_free(&ctx);
    }

    void encryptData(uint8_t* input, uint8_t* output, size_t len) {
        // XOR encryption with derived key (in production, use AES)
        for (size_t i = 0; i < len; i++) {
            output[i] = input[i] ^ deviceSecret[i % 32];
        }
    }

    void decryptData(uint8_t* input, uint8_t* output, size_t len) {
        // XOR decryption (same as encryption for XOR)
        encryptData(input, output, len);
    }
};

SecureKeyManager keyManager;

// RNG function for uECC
static int RNG(uint8_t *dest, unsigned size) {
    esp_fill_random(dest, size);
    return 1;
}

void setup() {
    Serial.begin(115200);
    Serial.println("Secure Face Recognition Authentication System");

    // Initialize secure key storage
    if (!keyManager.initialize()) {
        Serial.println("Failed to initialize secure storage!");
        return;
    }

    // Initialize uECC
    uECC_set_rng(&RNG);

    // Display device info
    Serial.printf("Device ID: %s\n", deviceId);
    displayPublicKey();

    // Initialize camera
    if (!initCamera()) {
        Serial.println("Camera initialization failed!");
        return;
    }

    // Connect to WiFi
    connectWiFi();

    // Initialize Edge Impulse
    if (ei_camera_init() == false) {
        Serial.println("Failed to initialize Camera!");
        return;
    }

    // Configure time via NTP for accurate timestamps
    configTime(0, 0, "pool.ntp.org", "time.nist.gov");
}

void connectWiFi() {
    WiFi.begin(ssid, password);
    Serial.print("Connecting to WiFi");

    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }

    Serial.println("\nWiFi connected");
    Serial.print("IP address: ");
    Serial.println(WiFi.localIP());
}

void displayPublicKey() {
    Serial.println("\n=== ECDSA Public Key (PEM format) ===");
    Serial.println("Add this to your server's DEVICE_KEYS:");

    // Generate PEM formatted public key
    uint8_t der[91];
    size_t derLen = createDERPublicKey(der);

    Serial.println("-----BEGIN PUBLIC KEY-----");
    String b64 = base64::encode(der, derLen);

    for (int i = 0; i < b64.length(); i += 64) {
        Serial.println(b64.substring(i, min(i + 64, (int)b64.length())));
    }

    Serial.println("-----END PUBLIC KEY-----");
    Serial.println("=====================================\n");
}

size_t createDERPublicKey(uint8_t* der) {
    size_t derLen = 0;

    // DER header for EC public key
    der[derLen++] = 0x30; // SEQUENCE
    der[derLen++] = 0x59; // length
    der[derLen++] = 0x30; // SEQUENCE
    der[derLen++] = 0x13; // length

    // Algorithm identifier
    der[derLen++] = 0x06; // OID
    der[derLen++] = 0x07; // length

    // ecPublicKey OID: 1.2.840.10045.2.1
    uint8_t ecPubKeyOID[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};
    memcpy(&der[derLen], ecPubKeyOID, sizeof(ecPubKeyOID));
    derLen += sizeof(ecPubKeyOID);

    // Curve OID
    der[derLen++] = 0x06; // OID
    der[derLen++] = 0x08; // length

    // prime256v1 OID: 1.2.840.10045.3.1.7
    uint8_t prime256v1OID[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
    memcpy(&der[derLen], prime256v1OID, sizeof(prime256v1OID));
    derLen += sizeof(prime256v1OID);

    // Public key
    der[derLen++] = 0x03; // BIT STRING
    der[derLen++] = 0x42; // length
    der[derLen++] = 0x00; // padding
    der[derLen++] = 0x04; // uncompressed point

    // Copy public key
    memcpy(&der[derLen], publicKey, 64);
    derLen += 64;

    return derLen;
}

// Main loop and authentication functions
void loop() {
    static unsigned long lastAuthTime = 0;
    unsigned long currentTime = millis();

    // Rate limiting: wait at least 5 seconds between auth attempts
    if (currentTime - lastAuthTime < 5000) {
        delay(100);
        return;
    }

    // Run face recognition
    if (performFaceRecognition()) {
        lastAuthTime = currentTime;
    }

    delay(100);
}

bool performFaceRecognition() {
    ei::signal_t signal;
    signal.total_length = EI_CLASSIFIER_INPUT_WIDTH * EI_CLASSIFIER_INPUT_HEIGHT;
    signal.get_data = &ei_camera_get_data;

    if (ei_camera_capture((size_t)EI_CLASSIFIER_INPUT_WIDTH, (size_t)EI_CLASSIFIER_INPUT_HEIGHT, snapshot_buf) == false) {
        return false;
    }

    ei_impulse_result_t result = { 0 };
    EI_IMPULSE_ERROR err = run_classifier(&signal, &result, debug_nn);

    if (err != EI_IMPULSE_OK) {
        return false;
    }

    return processInferenceResults(&result);
}

bool processInferenceResults(ei_impulse_result_t* result) {
    int maxIndex = -1;
    float maxConfidence = 0;

    for (size_t ix = 0; ix < EI_CLASSIFIER_LABEL_COUNT; ix++) {
        if (result->classification[ix].value > maxConfidence) {
            maxConfidence = result->classification[ix].value;
            maxIndex = ix;
        }
    }

    if (maxConfidence >= CONFIDENCE_THRESHOLD && maxIndex >= 0) {
        Serial.printf("Authenticated user: %s (confidence: %.2f%%)\n",
                     knownUsers[maxIndex], maxConfidence * 100);

        if (performLivenessCheck()) {
            sendSecureAuthToken(knownUsers[maxIndex]);
            return true;
        }
    }

    return false;
}

void sendSecureAuthToken(const char* userId) {
    // Create secure token payload
    StaticJsonDocument<384> payload;
    payload["user_id"] = userId;
    payload["device_id"] = deviceId;
    payload["timestamp"] = getISO8601Time();
    payload["nonce"] = esp_random();

    // Add device fingerprint
    payload["fingerprint"]["chip_id"] = String((uint32_t)ESP.getEfuseMac());
    payload["fingerprint"]["flash_size"] = ESP.getFlashChipSize();
    payload["fingerprint"]["sdk_version"] = ESP.getSdkVersion();

    String payloadStr;
    serializeJson(payload, payloadStr);

    // Sign payload
    uint8_t signature[64];
    if (!signPayload(payloadStr.c_str(), signature)) {
        return;
    }

    // Create request
    HTTPClient https;
    WiFiClientSecure client;

    // For production, use proper certificate validation
    client.setInsecure();

    https.begin(client, serverUrl);
    https.addHeader("Content-Type", "application/json");
    https.addHeader("X-Device-ID", deviceId);

    StaticJsonDocument<768> request;
    request["token"]["payload"] = base64::encode((uint8_t*)payloadStr.c_str(), payloadStr.length());
    request["token"]["signature"] = base64::encode(signature, 64);
    request["device_id"] = deviceId;

    String requestStr;
    serializeJson(request, requestStr);

    Serial.println("Sending secure authentication token...");
    int httpCode = https.POST(requestStr);

    if (httpCode > 0) {
        String response = https.getString();
        Serial.printf("Server response (%d): %s\n", httpCode, response.c_str());
    }

    https.end();
}

bool signPayload(const char* payload, uint8_t* signature) {
    const struct uECC_Curve_t * curve = uECC_secp256r1();

    // Hash the payload
    uint8_t hash[32];
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, (const unsigned char*)payload, strlen(payload));
    mbedtls_sha256_finish(&ctx, hash);
    mbedtls_sha256_free(&ctx);

    // Sign the hash
    if (!uECC_sign(privateKey, hash, 32, signature, curve)) {
        Serial.println("ECDSA signing failed!");
        return false;
    }

    Serial.println("Payload signed successfully");
    return true;
}

String getISO8601Time() {
    struct tm timeinfo;
    if (!getLocalTime(&timeinfo)) {
        // Fallback if NTP not available
        return "2024-01-01T00:00:00Z";
    }

    char timestamp[30];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &timeinfo);
    return String(timestamp);
}

// Edge Impulse camera functions
bool ei_camera_init() {
    if (is_initialised) return true;

    snapshot_buf = (uint8_t*)malloc(EI_CAMERA_RAW_FRAME_BUFFER_COLS * EI_CAMERA_RAW_FRAME_BUFFER_ROWS * EI_CAMERA_FRAME_BYTE_SIZE);
    if(snapshot_buf == nullptr) {
        Serial.println("ERR: Failed to allocate snapshot buffer!");
        return false;
    }

    is_initialised = true;
    return true;
}

void ei_camera_deinit() {
    if (is_initialised) {
        free(snapshot_buf);
        is_initialised = false;
    }
}

bool ei_camera_capture(uint32_t img_width, uint32_t img_height, uint8_t *out_buf) {
    camera_fb_t * fb = esp_camera_fb_get();
    if (!fb) {
        Serial.println("Camera capture failed");
        return false;
    }

    // Convert to RGB888
    bool converted = fmt2rgb888(fb->buf, fb->len, fb->format, snapshot_buf);
    esp_camera_fb_return(fb);

    if(!converted){
        Serial.println("Conversion failed");
        return false;
    }

    // Resize if needed
    if ((img_width != EI_CAMERA_RAW_FRAME_BUFFER_COLS) || (img_height != EI_CAMERA_RAW_FRAME_BUFFER_ROWS)) {
        ei::image::processing::resize_image(
            snapshot_buf,
            EI_CAMERA_RAW_FRAME_BUFFER_COLS,
            EI_CAMERA_RAW_FRAME_BUFFER_ROWS,
            out_buf,
            img_width,
            img_height,
            3
        );
    } else {
        memcpy(out_buf, snapshot_buf, img_width * img_height * 3);
    }

    return true;
}

static int ei_camera_get_data(size_t offset, size_t length, float *out_ptr) {
    size_t pixel_ix = offset * 3;
    size_t pixels_left = length;
    size_t out_ptr_ix = 0;

    while (pixels_left != 0) {
        // Convert RGB to normalized float
        out_ptr[out_ptr_ix] = (snapshot_buf[pixel_ix] / 255.0f) - 0.5f;
        out_ptr_ix++;

        out_ptr[out_ptr_ix] = (snapshot_buf[pixel_ix + 1] / 255.0f) - 0.5f;
        out_ptr_ix++;

        out_ptr[out_ptr_ix] = (snapshot_buf[pixel_ix + 2] / 255.0f) - 0.5f;
        out_ptr_ix++;

        pixel_ix += 3;
        pixels_left--;
    }

    return 0;
}

// Image format conversion helper
bool fmt2rgb888(const uint8_t *src_buf, size_t src_len, pixformat_t src_format, uint8_t *dst_buf) {
    switch (src_format) {
        case PIXFORMAT_RGB565: {
            for (size_t i = 0; i < src_len; i += 2) {
                uint16_t pixel = (src_buf[i] << 8) | src_buf[i + 1];
                dst_buf[i * 3 / 2] = ((pixel >> 11) & 0x1F) << 3;
                dst_buf[i * 3 / 2 + 1] = ((pixel >> 5) & 0x3F) << 2;
                dst_buf[i * 3 / 2 + 2] = (pixel & 0x1F) << 3;
            }
            return true;
        }
        case PIXFORMAT_RGB888:
            memcpy(dst_buf, src_buf, src_len);
            return true;
        default:
            return false;
    }
}
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <base64.h>
#include <uECC.h>
#include "mbedtls/sha256.h"
#include "esp_camera.h"
#include "src/cs_6301_inferencing.h"  // Your Edge Impulse model
#include <Preferences.h>
#include "esp_system.h"
#include "esp_efuse.h"
#include "edge-impulse-sdk/porting/espressif/ESP-NN/include/esp_nn.h"

// WiFi credentials
const char* ssid = "mpsz";
const char* password = "9512372023";
const char* serverUrl = "https://192.168.4.37:5000/auth/verify";

// Camera pins for ESP32-CAM
#define PWDN_GPIO_NUM     32
#define RESET_GPIO_NUM    -1
#define XCLK_GPIO_NUM      0
#define SIOD_GPIO_NUM     26
#define SIOC_GPIO_NUM     27
#define Y9_GPIO_NUM       35
#define Y8_GPIO_NUM       34
#define Y7_GPIO_NUM       39
#define Y6_GPIO_NUM       36
#define Y5_GPIO_NUM       21
#define Y4_GPIO_NUM       19
#define Y3_GPIO_NUM       18
#define Y2_GPIO_NUM        5
#define VSYNC_GPIO_NUM    25
#define HREF_GPIO_NUM     23
#define PCLK_GPIO_NUM     22

// Camera configuration for Edge Impulse
#define EI_CAMERA_RAW_FRAME_BUFFER_COLS   96
#define EI_CAMERA_RAW_FRAME_BUFFER_ROWS   96
#define EI_CAMERA_FRAME_BYTE_SIZE         3
#define CONFIDENCE_THRESHOLD              0.75

// NVS namespace for secure storage
Preferences preferences;
const char* NVS_NAMESPACE = "auth_keys";

// Security parameters
#define KEY_DERIVATION_ITERATIONS 10000
#define SALT_SIZE 16

// Device info
char deviceId[32];
uint8_t privateKey[32];
uint8_t publicKey[64];

// Edge Impulse camera buffers
static uint8_t *ei_camera_capture_buffer = nullptr;
static uint8_t *ei_camera_frame_buffer = nullptr;

// Known users from Edge Impulse training
const char* knownUsers[] = {
    "john_doe",
    "jane_smith",
    "alice_wong"
};

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

    // Print model info
    Serial.println("\n=== Edge Impulse Model Info ===");
    Serial.printf("Model input size: %dx%d\n",
        EI_CLASSIFIER_INPUT_WIDTH,
        EI_CLASSIFIER_INPUT_HEIGHT);
    Serial.printf("Number of classes: %d\n", EI_CLASSIFIER_LABEL_COUNT);
    Serial.println("Classes:");
    for (int i = 0; i < EI_CLASSIFIER_LABEL_COUNT; i++) {
        Serial.printf("  - %s\n", ei_classifier_inferencing_categories[i]);
    }
    Serial.println("===============================\n");

    // Initialize camera
    if (!initCamera()) {
        Serial.println("Camera initialization failed!");
        return;
    }

    // Connect to WiFi
    connectWiFi();

    // Initialize Edge Impulse
    if (!ei_camera_init()) {
        Serial.println("Failed to initialize EI Camera!");
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

bool initCamera() {
    camera_config_t config;
    config.ledc_channel = LEDC_CHANNEL_0;
    config.ledc_timer = LEDC_TIMER_0;
    config.pin_d0 = Y2_GPIO_NUM;
    config.pin_d1 = Y3_GPIO_NUM;
    config.pin_d2 = Y4_GPIO_NUM;
    config.pin_d3 = Y5_GPIO_NUM;
    config.pin_d4 = Y6_GPIO_NUM;
    config.pin_d5 = Y7_GPIO_NUM;
    config.pin_d6 = Y8_GPIO_NUM;
    config.pin_d7 = Y9_GPIO_NUM;
    config.pin_xclk = XCLK_GPIO_NUM;
    config.pin_pclk = PCLK_GPIO_NUM;
    config.pin_vsync = VSYNC_GPIO_NUM;
    config.pin_href = HREF_GPIO_NUM;
    config.pin_sscb_sda = SIOD_GPIO_NUM;
    config.pin_sscb_scl = SIOC_GPIO_NUM;
    config.pin_pwdn = PWDN_GPIO_NUM;
    config.pin_reset = RESET_GPIO_NUM;
    config.xclk_freq_hz = 20000000;
    config.pixel_format = PIXFORMAT_JPEG;  // Use JPEG for better memory efficiency
    config.frame_size = FRAMESIZE_96X96;   // Match Edge Impulse model input
    config.jpeg_quality = 10;
    config.fb_count = 2;

    // Initialize with higher specs if PSRAM available
    if (psramFound()) {
        config.frame_size = FRAMESIZE_QVGA;
        config.jpeg_quality = 10;
        config.fb_count = 2;
    } else {
        config.frame_size = FRAMESIZE_96X96;
        config.jpeg_quality = 12;
        config.fb_count = 1;
    }

    esp_err_t err = esp_camera_init(&config);
    if (err != ESP_OK) {
        Serial.printf("Camera init failed with error 0x%x", err);
        return false;
    }

    sensor_t *s = esp_camera_sensor_get();
    s->set_vflip(s, 1);
    s->set_hmirror(s, 1);

    return true;
}

// Initialize Edge Impulse camera buffer
bool ei_camera_init() {
    if (ei_camera_capture_buffer != nullptr) {
        return true;
    }

    ei_camera_capture_buffer = (uint8_t*)heap_caps_malloc(
        EI_CAMERA_RAW_FRAME_BUFFER_COLS * EI_CAMERA_RAW_FRAME_BUFFER_ROWS * EI_CAMERA_FRAME_BYTE_SIZE,
        MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT
    );

    if (ei_camera_capture_buffer == nullptr) {
        Serial.println("Failed to allocate camera buffer in PSRAM");
        ei_camera_capture_buffer = (uint8_t*)malloc(
            EI_CAMERA_RAW_FRAME_BUFFER_COLS * EI_CAMERA_RAW_FRAME_BUFFER_ROWS * EI_CAMERA_FRAME_BYTE_SIZE
        );
    }

    if (ei_camera_capture_buffer == nullptr) {
        return false;
    }

    ei_camera_frame_buffer = (uint8_t*)heap_caps_malloc(
        EI_CAMERA_RAW_FRAME_BUFFER_COLS * EI_CAMERA_RAW_FRAME_BUFFER_ROWS * EI_CAMERA_FRAME_BYTE_SIZE,
        MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT
    );

    if (ei_camera_frame_buffer == nullptr) {
        ei_camera_frame_buffer = (uint8_t*)malloc(
            EI_CAMERA_RAW_FRAME_BUFFER_COLS * EI_CAMERA_RAW_FRAME_BUFFER_ROWS * EI_CAMERA_FRAME_BYTE_SIZE
        );
    }

    if (ei_camera_frame_buffer == nullptr) {
        free(ei_camera_capture_buffer);
        return false;
    }

    return true;
}

// Main loop
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

    // Capture image
    if (!ei_camera_capture(
        (size_t)EI_CLASSIFIER_INPUT_WIDTH,
        (size_t)EI_CLASSIFIER_INPUT_HEIGHT,
        ei_camera_frame_buffer)) {
        Serial.println("Failed to capture image");
        return false;
    }

    // Run Edge Impulse classifier
    ei_impulse_result_t result = {0};

    EI_IMPULSE_ERROR err = run_classifier(&signal, &result, false);
    if (err != EI_IMPULSE_OK) {
        Serial.printf("Failed to run classifier (%d)\n", err);
        return false;
    }

    // Print timing info
    Serial.printf("Predictions (DSP: %d ms, Classification: %d ms, Anomaly: %d ms)\n",
        result.timing.dsp, result.timing.classification, result.timing.anomaly);

    return processInferenceResults(&result);
}

bool processInferenceResults(ei_impulse_result_t* result) {
    float max_confidence = 0;
    size_t max_index = 0;

    // Find the highest confidence prediction
    for (size_t ix = 0; ix < EI_CLASSIFIER_LABEL_COUNT; ix++) {
        Serial.printf("    %s: %.5f\n",
            result->classification[ix].label,
            result->classification[ix].value);

        if (result->classification[ix].value > max_confidence) {
            max_confidence = result->classification[ix].value;
            max_index = ix;
        }
    }

    // Check if it's a known user with high confidence
    if (max_confidence >= CONFIDENCE_THRESHOLD &&
        strcmp(result->classification[max_index].label, "unknown") != 0) {

        Serial.printf("Authenticated user: %s (confidence: %.2f%%)\n",
            result->classification[max_index].label,
            max_confidence * 100);

        if (performLivenessCheck()) {
            sendSecureAuthToken(result->classification[max_index].label);
            return true;
        } else {
            Serial.println("Liveness check failed!");
        }
    } else {
        Serial.println("Unknown user or low confidence");
    }

    return false;
}

bool performLivenessCheck() {
    camera_fb_t * fb1 = esp_camera_fb_get();
    if (!fb1) return false;

    delay(500);

    camera_fb_t * fb2 = esp_camera_fb_get();
    if (!fb2) {
        esp_camera_fb_return(fb1);
        return false;
    }

    size_t pixelDiff = 0;
    size_t threshold = fb1->len * 0.05;

    for (size_t i = 0; i < min(fb1->len, fb2->len); i++) {
        if (abs(fb1->buf[i] - fb2->buf[i]) > 10) {
            pixelDiff++;
        }
    }

    esp_camera_fb_return(fb1);
    esp_camera_fb_return(fb2);

    return pixelDiff > threshold;
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

        if (httpCode == 200) {
            Serial.println("✓ Authentication successful!");
        }
    } else {
        Serial.printf("HTTPS POST failed, error: %s\n", https.errorToString(httpCode).c_str());
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

// Capture image for Edge Impulse
bool ei_camera_capture(uint32_t img_width, uint32_t img_height, uint8_t *out_buf) {
    camera_fb_t *fb = esp_camera_fb_get();
    if (!fb) {
        return false;
    }

    bool converted = false;

    if (fb->format == PIXFORMAT_JPEG) {
        // Decode JPEG to RGB888
        converted = jpg2rgb888(fb->buf, fb->len, out_buf, JPG_SCALE_NONE);
    } else if (fb->format == PIXFORMAT_RGB565) {
        converted = fmt2rgb888(fb->buf, fb->len, fb->format, out_buf);
    }

    esp_camera_fb_return(fb);

    if (!converted) {
        return false;
    }

    // Resize if needed
    if ((img_width != fb->width) || (img_height != fb->height)) {
        ei::image::processing::resize_image(
            out_buf,
            fb->width,
            fb->height,
            out_buf,
            img_width,
            img_height,
            3
        );
    }

    return true;
}

// Get data callback for Edge Impulse
static int ei_camera_get_data(size_t offset, size_t length, float *out_ptr) {
    size_t pixel_ix = offset * 3;
    size_t pixels_left = length;
    size_t out_ptr_ix = 0;

    while (pixels_left != 0) {
        // Normalize RGB values to [-1, 1] as expected by the model
        out_ptr[out_ptr_ix] = (ei_camera_frame_buffer[pixel_ix] / 127.5f) - 1.0f;
        out_ptr_ix++;
        out_ptr[out_ptr_ix] = (ei_camera_frame_buffer[pixel_ix + 1] / 127.5f) - 1.0f;
        out_ptr_ix++;
        out_ptr[out_ptr_ix] = (ei_camera_frame_buffer[pixel_ix + 2] / 127.5f) - 1.0f;
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

// JPEG to RGB888 decoder
bool jpg2rgb888(const uint8_t *src, size_t src_len, uint8_t *out, jpg_scale_t scale) {
    // This is a simplified version - in production use proper JPEG decoder
    // For ESP32-CAM, you might want to use the built-in JPEG decoder
    // or include a proper JPEG decoding library

    // Placeholder implementation
    return false;
}

// Cleanup function
void ei_camera_deinit() {
    if (ei_camera_capture_buffer) {
        free(ei_camera_capture_buffer);
        ei_camera_capture_buffer = nullptr;
    }
    if (ei_camera_frame_buffer) {
        free(ei_camera_frame_buffer);
        ei_camera_frame_buffer = nullptr;
    }
}
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <base64.h>
#include <uECC.h>
#include "mbedtls/sha256.h"
#include "esp_camera.h"
#include <face_recognition_inferencing.h>

// WiFi credentials
const char* ssid = "YOUR_WIFI_SSID";
const char* password = "YOUR_WIFI_PASSWORD";
const char* serverUrl = "https://YOUR_SERVER_IP:5000/auth/verify";

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

// Edge Impulse parameters
#define EI_CAMERA_RAW_FRAME_BUFFER_COLS           320
#define EI_CAMERA_RAW_FRAME_BUFFER_ROWS           240
#define EI_CAMERA_FRAME_BYTE_SIZE                 3
#define CONFIDENCE_THRESHOLD                       0.75

// Crypto keys
const char* deviceId = "device_001";

// ECDSA private key (32 bytes for secp256r1)
// In production, generate this securely and store in encrypted NVS
uint8_t privateKey[32] = {
    0x2d, 0xc5, 0x3f, 0xc4, 0xd1, 0x6e, 0x9a, 0x8b,
    0x5e, 0x7b, 0xc3, 0x4a, 0x9f, 0x2e, 0xd6, 0x1c,
    0xa7, 0x8d, 0x4b, 0xe2, 0x5f, 0x91, 0x3c, 0x7a,
    0xb8, 0x6d, 0x1a, 0xf3, 0x5e, 0x9c, 0x2b, 0x8f
};

// ECDSA public key (64 bytes: 32 bytes X + 32 bytes Y)
uint8_t publicKey[64] = {
    // X coordinate
    0x4e, 0x8a, 0x7f, 0x2c, 0x9d, 0x1e, 0x3b, 0x5a,
    0x6f, 0x8c, 0x2d, 0x4e, 0x9a, 0x1b, 0x7c, 0x5d,
    0x3e, 0x9f, 0x8a, 0x2b, 0x6c, 0x7d, 0x4e, 0x1f,
    0x8b, 0x3c, 0x5d, 0x9e, 0x2f, 0x6a, 0x1b, 0x8c,
    // Y coordinate
    0x7d, 0x3e, 0x9f, 0x1a, 0x2b, 0x8c, 0x4d, 0x5e,
    0x6f, 0x9a, 0x2b, 0x3c, 0x7d, 0x8e, 0x1f, 0x5a,
    0x9b, 0x2c, 0x6d, 0x3e, 0x4f, 0x8a, 0x1b, 0x5c,
    0x7d, 0x9e, 0x2f, 0x3a, 0x8b, 0x4c, 0x6d, 0x1e
};

// Known users mapping
const char* knownUsers[] = {
    "john_doe",
    "jane_smith",
    "alice_wong"
};

static uint8_t *snapshot_buf = nullptr;
static bool debug_nn = false;
static bool is_initialised = false;

// RNG function for uECC
static int RNG(uint8_t *dest, unsigned size) {
    while (size) {
        uint32_t val = esp_random();
        for (int i = 0; i < 4 && size > 0; i++) {
            *dest++ = val & 0xFF;
            val >>= 8;
            size--;
        }
    }
    return 1;
}

void setup() {
    Serial.begin(115200);
    Serial.println("Face Recognition Authentication System");

    // Initialize uECC
    uECC_set_rng(&RNG);

    // Initialize camera
    if (!initCamera()) {
        Serial.println("Camera initialization failed!");
        return;
    }

    // Connect to WiFi
    WiFi.begin(ssid, password);
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    Serial.println("\nWiFi connected");
    Serial.print("IP address: ");
    Serial.println(WiFi.localIP());

    // Initialize Edge Impulse
    if (ei_camera_init() == false) {
        Serial.println("Failed to initialize Camera!");
        return;
    }

    // Generate and display public key for server configuration
    displayPublicKey();
}

void displayPublicKey() {
    Serial.println("\n=== ECDSA Public Key (PEM format) ===");
    Serial.println("Add this to your server's DEVICE_KEYS:");
    Serial.println("-----BEGIN PUBLIC KEY-----");

    // Create DER encoded public key
    uint8_t der[91];
    size_t derLen = 0;

    // DER header for EC public key
    der[derLen++] = 0x30; // SEQUENCE
    der[derLen++] = 0x59; // length
    der[derLen++] = 0x30; // SEQUENCE
    der[derLen++] = 0x13; // length

    // Algorithm identifier
    der[derLen++] = 0x06; // OID
    der[derLen++] = 0x07; // length
    der[derLen++] = 0x2A; // 1.2.840.10045.2.1 (ecPublicKey)
    der[derLen++] = 0x86;
    der[derLen++] = 0x48;
    der[derLen++] = 0xCE;
    der[derLen++] = 0x3D;
    der[derLen++] = 0x02;
    der[derLen++] = 0x01;

    // Curve OID
    der[derLen++] = 0x06; // OID
    der[derLen++] = 0x08; // length
    der[derLen++] = 0x2A; // 1.2.840.10045.3.1.7 (prime256v1)
    der[derLen++] = 0x86;
    der[derLen++] = 0x48;
    der[derLen++] = 0xCE;
    der[derLen++] = 0x3D;
    der[derLen++] = 0x03;
    der[derLen++] = 0x01;
    der[derLen++] = 0x07;

    // Public key
    der[derLen++] = 0x03; // BIT STRING
    der[derLen++] = 0x42; // length
    der[derLen++] = 0x00; // padding
    der[derLen++] = 0x04; // uncompressed point

    // Copy public key
    memcpy(&der[derLen], publicKey, 64);
    derLen += 64;

    // Base64 encode
    String b64 = base64::encode(der, derLen);

    // Print with line breaks
    for (int i = 0; i < b64.length(); i += 64) {
        Serial.println(b64.substring(i, min(i + 64, (int)b64.length())));
    }

    Serial.println("-----END PUBLIC KEY-----");
    Serial.println("=====================================\n");
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
    config.pixel_format = PIXFORMAT_RGB565;
    config.frame_size = FRAMESIZE_QVGA;
    config.jpeg_quality = 12;
    config.fb_count = 2;

    esp_err_t err = esp_camera_init(&config);
    if (err != ESP_OK) {
        Serial.printf("Camera init failed with error 0x%x", err);
        return false;
    }

    sensor_t * s = esp_camera_sensor_get();
    s->set_vflip(s, 1);
    s->set_hmirror(s, 1);

    return true;
}

void loop() {
    ei::signal_t signal;
    signal.total_length = EI_CLASSIFIER_INPUT_WIDTH * EI_CLASSIFIER_INPUT_HEIGHT;
    signal.get_data = &ei_camera_get_data;

    if (ei_camera_capture((size_t)EI_CLASSIFIER_INPUT_WIDTH, (size_t)EI_CLASSIFIER_INPUT_HEIGHT, snapshot_buf) == false) {
        Serial.println("Failed to capture image");
        delay(1000);
        return;
    }

    ei_impulse_result_t result = { 0 };
    EI_IMPULSE_ERROR err = run_classifier(&signal, &result, debug_nn);
    if (err != EI_IMPULSE_OK) {
        Serial.printf("ERR: Failed to run classifier (%d)\n", err);
        delay(1000);
        return;
    }

    processInferenceResults(&result);
    delay(2000);
}

void processInferenceResults(ei_impulse_result_t* result) {
    Serial.println("Predictions:");

    int maxIndex = -1;
    float maxConfidence = 0;

    for (size_t ix = 0; ix < EI_CLASSIFIER_LABEL_COUNT; ix++) {
        Serial.printf("    %s: %.5f\n", result->classification[ix].label, result->classification[ix].value);

        if (result->classification[ix].value > maxConfidence) {
            maxConfidence = result->classification[ix].value;
            maxIndex = ix;
        }
    }

    if (maxConfidence >= CONFIDENCE_THRESHOLD && maxIndex >= 0 && maxIndex < sizeof(knownUsers)/sizeof(knownUsers[0])) {
        Serial.printf("Authenticated user: %s (confidence: %.2f%%)\n", knownUsers[maxIndex], maxConfidence * 100);

        if (performLivenessCheck()) {
            sendAuthToken(knownUsers[maxIndex]);
        } else {
            Serial.println("Liveness check failed - possible spoofing attempt");
        }
    } else {
        Serial.println("No match found or confidence too low");
    }
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

void sendAuthToken(const char* userId) {
    // Create token payload
    StaticJsonDocument<256> payload;
    payload["user_id"] = userId;
    payload["timestamp"] = getISO8601Time();
    payload["device_id"] = deviceId;
    payload["nonce"] = esp_random();

    String payloadStr;
    serializeJson(payload, payloadStr);

    // Sign payload with ECDSA
    uint8_t signature[64];
    if (!signPayload(payloadStr.c_str(), signature)) {
        Serial.println("Failed to sign payload!");
        return;
    }

    // Encode payload and signature
    String payloadB64 = base64::encode((uint8_t*)payloadStr.c_str(), payloadStr.length());
    String signatureB64 = base64::encode(signature, 64);

    // Send to server
    HTTPClient http;
    WiFiClientSecure client;
    client.setInsecure();

    http.begin(client, serverUrl);
    http.addHeader("Content-Type", "application/json");

    StaticJsonDocument<512> request;
    request["token"]["payload"] = payloadB64;
    request["token"]["signature"] = signatureB64;
    request["device_id"] = deviceId;

    String requestStr;
    serializeJson(request, requestStr);

    Serial.println("Sending authentication token...");
    int httpCode = http.POST(requestStr);

    if (httpCode > 0) {
        String response = http.getString();
        Serial.printf("Server response (%d): %s\n", httpCode, response.c_str());

        StaticJsonDocument<256> responseDoc;
        deserializeJson(responseDoc, response);

        if (responseDoc["status"] == "success") {
            Serial.println("✓ Authentication successful!");
        } else {
            Serial.println("✗ Authentication failed!");
        }
    } else {
        Serial.printf("HTTP request failed: %s\n", http.errorToString(httpCode).c_str());
    }

    http.end();
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
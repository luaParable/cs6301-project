#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <base64.h>
#include <micro_ecc.h>
#include "esp_camera.h"
#include <face_recognition_inferencing.h>  // Edge Impulse generated header

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
uint8_t privateKey[32] = {/* Your private key bytes */};

// Known users mapping (index to user ID)
const char* knownUsers[] = {
    "john_doe",
    "jane_smith",
    "alice_wong"
};

static uint8_t *snapshot_buf = nullptr;
static bool debug_nn = false;

void setup() {
    Serial.begin(115200);
    Serial.println("Face Recognition Authentication System");

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
    config.pixel_format = PIXFORMAT_RGB565;  // For Edge Impulse processing
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

    // Capture image and run inference
    if (ei_camera_capture((size_t)EI_CLASSIFIER_INPUT_WIDTH, (size_t)EI_CLASSIFIER_INPUT_HEIGHT, snapshot_buf) == false) {
        Serial.println("Failed to capture image");
        delay(1000);
        return;
    }

    // Run the classifier
    ei_impulse_result_t result = { 0 };
    EI_IMPULSE_ERROR err = run_classifier(&signal, &result, debug_nn);
    if (err != EI_IMPULSE_OK) {
        Serial.printf("ERR: Failed to run classifier (%d)\n", err);
        delay(1000);
        return;
    }

    // Process results
    processInferenceResults(&result);

    delay(2000); // Wait before next capture
}

void processInferenceResults(ei_impulse_result_t* result) {
    Serial.println("Predictions:");

    int maxIndex = -1;
    float maxConfidence = 0;

    // Find the class with highest confidence
    for (size_t ix = 0; ix < EI_CLASSIFIER_LABEL_COUNT; ix++) {
        Serial.printf("    %s: %.5f\n", result->classification[ix].label, result->classification[ix].value);

        if (result->classification[ix].value > maxConfidence) {
            maxConfidence = result->classification[ix].value;
            maxIndex = ix;
        }
    }

    // Check if confidence meets threshold
    if (maxConfidence >= CONFIDENCE_THRESHOLD && maxIndex >= 0 && maxIndex < sizeof(knownUsers)/sizeof(knownUsers[0])) {
        Serial.printf("Authenticated user: %s (confidence: %.2f%%)\n", knownUsers[maxIndex], maxConfidence * 100);

        // Add liveness check
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
    // Simple liveness detection: capture multiple frames and check for changes
    camera_fb_t * fb1 = esp_camera_fb_get();
    if (!fb1) return false;

    delay(500);

    camera_fb_t * fb2 = esp_camera_fb_get();
    if (!fb2) {
        esp_camera_fb_return(fb1);
        return false;
    }

    // Calculate pixel difference between frames
    size_t pixelDiff = 0;
    size_t threshold = fb1->len * 0.05; // 5% difference threshold

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
    // Generate timestamp
    unsigned long timestamp = millis();

    // Create token payload
    StaticJsonDocument<256> payload;
    payload["user_id"] = userId;
    payload["timestamp"] = getISO8601Time();
    payload["device_id"] = deviceId;
    payload["nonce"] = random(1000000);

    String payloadStr;
    serializeJson(payload, payloadStr);
    String payloadB64 = base64::encode((uint8_t*)payloadStr.c_str(), payloadStr.length());

    // Sign payload with ECDSA
    uint8_t signature[64];
    signPayload(payloadStr.c_str(), signature);

    // Send to server
    HTTPClient http;
    WiFiClientSecure client;
    client.setInsecure(); // For demo only - use proper certificates in production

    http.begin(client, serverUrl);
    http.addHeader("Content-Type", "application/json");

    StaticJsonDocument<512> request;
    request["token"]["payload"] = payloadB64;
    request["token"]["signature"] = base64::encode(signature, 64);
    request["device_id"] = deviceId;

    String requestStr;
    serializeJson(request, requestStr);

    Serial.println("Sending authentication token...");
    int httpCode = http.POST(requestStr);

    if (httpCode > 0) {
        String response = http.getString();
        Serial.printf("Server response (%d): %s\n", httpCode, response.c_str());

        // Parse response
        StaticJsonDocument<256> responseDoc;
        deserializeJson(responseDoc, response);

        if (responseDoc["status"] == "success") {
            Serial.println("✓ Authentication successful!");
            // Optional: LED indicator or buzzer feedback
        } else {
            Serial.println("✗ Authentication failed!");
        }
    } else {
        Serial.printf("HTTP request failed: %s\n", http.errorToString(httpCode).c_str());
    }

    http.end();
}

void signPayload(const char* payload, uint8_t* signature) {
    // Initialize micro-ecc
    const struct uECC_Curve_t * curve = uECC_secp256r1();

    // Hash the payload
    uint8_t hash[32];
    mbedtls_sha256((uint8_t*)payload, strlen(payload), hash, 0);

    // Sign the hash
    if (!uECC_sign(privateKey, hash, 32, signature, curve)) {
        Serial.println("Signing failed!");
    }
}

String getISO8601Time() {
    // Simplified timestamp - in production use NTP
    char timestamp[30];
    unsigned long epochTime = millis() / 1000 + 1609459200; // Approximate epoch time
    sprintf(timestamp, "2024-01-01T%02d:%02d:%02dZ",
            (int)((epochTime / 3600) % 24),
            (int)((epochTime / 60) % 60),
            (int)(epochTime % 60));
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

    // Convert and resize image for Edge Impulse model
    bool converted = fmt2rgb888(fb->buf, fb->len, fb->format, out_buf);

    esp_camera_fb_return(fb);

    if(!converted){
        Serial.println("Conversion failed");
        return false;
    }

    return true;
}

static int ei_camera_get_data(size_t offset, size_t length, float *out_ptr) {
    size_t pixel_ix = offset * 3;
    size_t pixels_left = length;
    size_t out_ptr_ix = 0;

    while (pixels_left != 0) {
        out_ptr[out_ptr_ix] = (snapshot_buf[pixel_ix] << 16) + (snapshot_buf[pixel_ix + 1] << 8) + snapshot_buf[pixel_ix + 2];

        // Convert to grayscale if needed by model
        out_ptr[out_ptr_ix] = ((float)snapshot_buf[pixel_ix] + (float)snapshot_buf[pixel_ix + 1] + (float)snapshot_buf[pixel_ix + 2]) / 3.0f / 255.0f;

        out_ptr_ix++;
        pixel_ix += 3;
        pixels_left--;
    }

    return 0;
}
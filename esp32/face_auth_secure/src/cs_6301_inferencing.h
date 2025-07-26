#ifndef _CS_6301_INFERENCING_H_
#define _CS_6301_INFERENCING_H_

// Include Edge Impulse SDK
#include "../edge-impulse-sdk/classifier/ei_run_classifier.h"
#include "../edge-impulse-sdk/dsp/numpy.hpp"

// Include model parameters
#include "../model-parameters/model_metadata.h"
#include "../model-parameters/model_variables.h"

// Include TFLite model
#include "../tflite-model/tflite_learn_5_compiled.h"

// Model constants from your Edge Impulse project
#define EI_CLASSIFIER_TFLITE_ENABLE_CMSIS_NN 1
#define EI_CLASSIFIER_TFLITE_ENABLE_ESP_NN 1
#define EI_CLASSIFIER_TFLITE_ENABLE_ESP_NN_S3 0

// Define your model input size based on Edge Impulse configuration
#define EI_CLASSIFIER_INPUT_WIDTH          96
#define EI_CLASSIFIER_INPUT_HEIGHT         96
#define EI_CLASSIFIER_INPUT_FRAMES         1
#define EI_CLASSIFIER_DSP_INPUT_FRAME_SIZE (EI_CLASSIFIER_INPUT_WIDTH * EI_CLASSIFIER_INPUT_HEIGHT)
#define EI_CLASSIFIER_LABEL_COUNT          4  // Adjust based on your classes

// Your trained class labels
const char* ei_classifier_inferencing_categories[] = {
    "john_doe",
    "jane_smith",
    "alice_wong",
    "unknown"
};

typedef struct {
    float *buffer;
    size_t total_length;
    size_t (*get_data)(size_t offset, size_t length, float *out_ptr);
} signal_t;

typedef struct {
    struct {
        const char *label;
        float value;
    } classification[EI_CLASSIFIER_LABEL_COUNT];
    float anomaly;
    ei_impulse_result_timing_t timing;
} ei_impulse_result_t;

// Function declarations
extern "C" EI_IMPULSE_ERROR run_classifier(
    signal_t *signal,
    ei_impulse_result_t *result,
    bool debug = false
);

extern "C" EI_IMPULSE_ERROR run_classifier_continuous(
    signal_t *signal,
    ei_impulse_result_t *result,
    bool debug = false
);

extern "C" void ei_classifier_smooth_init(
    ei_classifier_smooth_t *smooth,
    size_t n_predictions,
    uint8_t alpha_size,
    float correction_factor
);

#endif // _CS_6301_INFERENCING_H_
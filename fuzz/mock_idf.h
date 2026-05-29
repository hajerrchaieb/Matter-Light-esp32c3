/* fuzz/mock_idf.h
 * Minimal ESP-IDF stubs for compiling firmware code on a Linux host.
 */
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef int esp_err_t;
#define ESP_OK               0
#define ESP_FAIL            -1
#define ESP_ERR_NO_MEM       0x101
#define ESP_ERR_INVALID_ARG  0x102
#define ESP_ERR_INVALID_SIZE 0x103
#define ESP_ERR_NOT_FOUND    0x105

#define ESP_LOGI(tag, fmt, ...) do {} while(0)
#define ESP_LOGW(tag, fmt, ...) do {} while(0)
#define ESP_LOGE(tag, fmt, ...) do {} while(0)
#define ESP_LOGD(tag, fmt, ...) do {} while(0)

typedef int gpio_num_t;
typedef enum { GPIO_MODE_OUTPUT = 1, GPIO_MODE_INPUT = 2 } gpio_mode_t;
static inline esp_err_t gpio_set_direction(gpio_num_t p, gpio_mode_t m)
    { (void)p; (void)m; return ESP_OK; }
static inline esp_err_t gpio_set_level(gpio_num_t p, uint32_t v)
    { (void)p; (void)v; return ESP_OK; }

static inline size_t esp_get_free_heap_size(void) { return 300 * 1024; }
static inline void* heap_caps_malloc(size_t s, uint32_t c)
    { (void)c; return malloc(s); }

typedef void* TaskHandle_t;
typedef uint32_t TickType_t;
#define pdMS_TO_TICKS(x) (x)
#define portMAX_DELAY 0xFFFFFFFF
static inline void vTaskDelay(TickType_t t) { (void)t; }

typedef uint32_t nvs_handle_t;
#define NVS_READWRITE 2
static inline esp_err_t nvs_flash_init(void) { return ESP_OK; }
static inline esp_err_t nvs_open(const char* n, int m, nvs_handle_t* h)
    { (void)n; (void)m; *h = 1; return ESP_OK; }
static inline esp_err_t nvs_set_u8(nvs_handle_t h, const char* k, uint8_t v)
    { (void)h; (void)k; (void)v; return ESP_OK; }
static inline esp_err_t nvs_get_u8(nvs_handle_t h, const char* k, uint8_t* v)
    { (void)h; (void)k; *v = 0; return ESP_OK; }
static inline esp_err_t nvs_commit(nvs_handle_t h) { (void)h; return ESP_OK; }
static inline void      nvs_close(nvs_handle_t h)  { (void)h; }

typedef enum {
    ESP_MATTER_VAL_TYPE_INVALID      = 0,
    ESP_MATTER_VAL_TYPE_BOOLEAN      = 1,
    ESP_MATTER_VAL_TYPE_INTEGER      = 2,
    ESP_MATTER_VAL_TYPE_FLOAT        = 3,
    ESP_MATTER_VAL_TYPE_CHAR_STRING  = 4,
    ESP_MATTER_VAL_TYPE_OCTET_STRING = 5,
    ESP_MATTER_VAL_TYPE_ARRAY        = 6,
} esp_matter_val_type_t;

typedef union {
    bool    b;
    int32_t i;
    float   f;
    struct { uint8_t* b; uint16_t s; uint16_t n; uint8_t t; } a;
} esp_matter_val_t;

typedef struct {
    esp_matter_val_type_t type;
    esp_matter_val_t      val;
} esp_matter_attr_val_t;

typedef void* app_driver_handle_t;

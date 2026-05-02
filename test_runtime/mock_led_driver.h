/**
 * test_runtime/mock_led_driver.h
 * ==============================
 * Host-side stub for the LED driver functions referenced by the
 * generated Unity tests. No real LED is driven — the stubs simply
 * return ESP_OK so attribute-update tests can complete.
 */

#ifndef MOCK_LED_DRIVER_H
#define MOCK_LED_DRIVER_H

#include "mock_idf.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void *led_driver_handle_t;

static inline led_driver_handle_t led_driver_init(void *cfg) {
    (void)cfg; return (led_driver_handle_t)0x1;
}
static inline esp_err_t led_driver_set_power(led_driver_handle_t h, bool on)        { (void)h; (void)on;  return ESP_OK; }
static inline esp_err_t led_driver_set_brightness(led_driver_handle_t h, uint8_t v) { (void)h; (void)v;   return ESP_OK; }
static inline esp_err_t led_driver_set_hue(led_driver_handle_t h, uint16_t v)       { (void)h; (void)v;   return ESP_OK; }
static inline esp_err_t led_driver_set_saturation(led_driver_handle_t h, uint8_t v) { (void)h; (void)v;   return ESP_OK; }
static inline esp_err_t led_driver_set_temperature(led_driver_handle_t h, uint32_t v){ (void)h; (void)v;   return ESP_OK; }

#ifdef __cplusplus
}
#endif

#endif /* MOCK_LED_DRIVER_H */

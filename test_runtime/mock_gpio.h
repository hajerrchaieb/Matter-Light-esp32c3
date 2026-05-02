/**
 * test_runtime/mock_gpio.h
 * =========================
 * Host-side stub for ESP32 GPIO functions occasionally referenced
 * by the Unity tests. No real GPIO is driven on the host.
 */

#ifndef MOCK_GPIO_H
#define MOCK_GPIO_H

#include "mock_idf.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    GPIO_MODE_INPUT       = 1,
    GPIO_MODE_OUTPUT      = 2,
    GPIO_MODE_INPUT_OUTPUT= 3,
} gpio_mode_t;

static inline esp_err_t gpio_set_direction(int gpio, gpio_mode_t mode)  { (void)gpio; (void)mode;  return ESP_OK; }
static inline esp_err_t gpio_set_level    (int gpio, uint32_t level)    { (void)gpio; (void)level; return ESP_OK; }
static inline int       gpio_get_level    (int gpio)                    { (void)gpio;              return 0;      }

#ifdef __cplusplus
}
#endif

#endif /* MOCK_GPIO_H */

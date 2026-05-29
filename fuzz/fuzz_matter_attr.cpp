#include "mock_idf.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

static char g_device_name[32] = {0};
static int  g_brightness = 0;
static bool g_power = false;

static esp_err_t app_driver_attribute_update(
    app_driver_handle_t driver_handle,
    uint16_t endpoint_id,
    uint32_t cluster_id,
    esp_matter_attr_val_t *val)
{
    if (!val) return ESP_ERR_INVALID_ARG;
    if (val->type == ESP_MATTER_VAL_TYPE_INVALID) return ESP_ERR_INVALID_ARG;

    if (cluster_id == 0x0006) {
        if (val->type != ESP_MATTER_VAL_TYPE_BOOLEAN) return ESP_ERR_INVALID_ARG;
        g_power = val->val.b;
        return ESP_OK;
    }
    if (cluster_id == 0x0008) {
        if (val->type != ESP_MATTER_VAL_TYPE_INTEGER) return ESP_ERR_INVALID_ARG;
        g_brightness = val->val.i;
        return ESP_OK;
    }
    if (cluster_id == 0x0300) {
        if (val->type != ESP_MATTER_VAL_TYPE_FLOAT) return ESP_ERR_INVALID_ARG;
        return ESP_OK;
    }
    if (cluster_id == 0x0028) {
        if (val->type != ESP_MATTER_VAL_TYPE_CHAR_STRING) return ESP_ERR_INVALID_ARG;
        if (!val->val.a.b) return ESP_ERR_INVALID_ARG;
        if (val->val.a.s > 0 && val->val.a.s < sizeof(g_device_name)) {
            memcpy(g_device_name, val->val.a.b, val->val.a.s);
            g_device_name[val->val.a.s] = '\0';
        }
        return ESP_OK;
    }
    return ESP_ERR_NOT_FOUND;
}

static esp_err_t parse_tlv_length(const uint8_t* data, size_t size,
                                   uint16_t* out_len, const uint8_t** out_payload)
{
    if (!data || size < 2) return ESP_ERR_INVALID_SIZE;
    uint16_t declared_len = (uint16_t)(data[0] | (data[1] << 8));
    if (declared_len > (size - 2)) return ESP_ERR_INVALID_SIZE;
    *out_len     = declared_len;
    *out_payload = data + 2;
    return ESP_OK;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 7) return 0;

    uint8_t  target      = data[0] % 3;
    uint16_t endpoint_id = (uint16_t)(data[1] | (data[2] << 8));
    uint32_t cluster_id  = (uint32_t)(data[3] | (data[4] << 8)
                                    | (data[5] << 16) | (data[6] << 24));
    const uint8_t* payload      = data + 7;
    size_t         payload_size = size - 7;

    if (target == 0) {
        if (payload_size < 1) return 0;
        esp_matter_attr_val_t val;
        memset(&val, 0, sizeof(val));
        uint8_t type_byte = payload[0] % 7;
        val.type = (esp_matter_val_type_t)(type_byte);
        switch (val.type) {
            case ESP_MATTER_VAL_TYPE_BOOLEAN:
                val.val.b = (payload_size > 1) ? (payload[1] != 0) : false;
                break;
            case ESP_MATTER_VAL_TYPE_INTEGER:
                if (payload_size >= 5) memcpy(&val.val.i, payload + 1, 4);
                break;
            case ESP_MATTER_VAL_TYPE_FLOAT:
                if (payload_size >= 5) memcpy(&val.val.f, payload + 1, 4);
                break;
            case ESP_MATTER_VAL_TYPE_CHAR_STRING:
            case ESP_MATTER_VAL_TYPE_OCTET_STRING:
                if (payload_size > 1) {
                    val.val.a.b = (uint8_t*)(payload + 1);
                    val.val.a.s = (uint16_t)(payload_size - 1);
                    val.val.a.n = val.val.a.s;
                }
                break;
            default:
                break;
        }
        app_driver_attribute_update(NULL, endpoint_id, cluster_id, &val);
    }
    else if (target == 1) {
        app_driver_attribute_update(NULL, endpoint_id, cluster_id, NULL);
        esp_matter_attr_val_t val;
        memset(&val, 0, sizeof(val));
        val.type = ESP_MATTER_VAL_TYPE_INVALID;
        app_driver_attribute_update(NULL, endpoint_id, cluster_id, &val);
    }
    else {
        uint16_t       parsed_len = 0;
        const uint8_t* parsed_payload = nullptr;
        parse_tlv_length(payload, payload_size, &parsed_len, &parsed_payload);
    }
    return 0;
}

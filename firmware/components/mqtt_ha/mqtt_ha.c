#include "mqtt_ha.h"
#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mqtt_client.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"

#define NVS_NAMESPACE   "mqtt_cfg"
#define TOPIC_PREFIX    "matter_sniffer"
#define HA_DISCOVERY    "homeassistant"

static const char *TAG = "mqtt_ha";
static esp_mqtt_client_handle_t s_client = NULL;
static bool s_connected = false;

static const char *device_type_str(uint16_t dtype)
{
    switch (dtype) {
    case 0x0100: return "On/Off Light";
    case 0x0101: return "Dimmable Light";
    case 0x0103: return "Color Temperature Light";
    case 0x010C: return "Extended Color Light";
    case 0x0301: return "Thermostat";
    case 0x0015: return "Contact Sensor";
    case 0x0107: return "Occupancy Sensor";
    case 0x000A: return "Door Lock";
    case 0x0022: return "Window Covering";
    case 0x0203: return "Power Plug";
    default:     return "Matter Device";
    }
}

static void mqtt_event_handler(void *arg, esp_event_base_t base,
                                int32_t event_id, void *event_data)
{
    esp_mqtt_event_handle_t event = (esp_mqtt_event_handle_t)event_data;
    switch (event->event_id) {
    case MQTT_EVENT_CONNECTED:
        ESP_LOGI(TAG, "MQTT connected");
        s_connected = true;
        /* Publish online status for the sniffer itself */
        esp_mqtt_client_publish(s_client,
            TOPIC_PREFIX "/status", "online", 6, 1, true);
        break;
    case MQTT_EVENT_DISCONNECTED:
        ESP_LOGW(TAG, "MQTT disconnected");
        s_connected = false;
        break;
    case MQTT_EVENT_ERROR:
        ESP_LOGE(TAG, "MQTT error");
        break;
    default:
        break;
    }
}

static void do_init(const char *host, int port, const char *user, const char *pass)
{
    if (!host || host[0] == '\0') {
        ESP_LOGW(TAG, "no MQTT broker configured — skipping");
        return;
    }

    char uri[128];
    snprintf(uri, sizeof(uri), "mqtt://%s:%d", host, port);

    esp_mqtt_client_config_t cfg = {
        .broker.address.uri       = uri,
        .credentials.username     = (user && user[0]) ? user : NULL,
        .credentials.authentication.password = (pass && pass[0]) ? pass : NULL,
        .session.last_will.topic  = TOPIC_PREFIX "/status",
        .session.last_will.msg    = "offline",
        .session.last_will.msg_len = 7,
        .session.last_will.qos    = 1,
        .session.last_will.retain = true,
    };

    s_client = esp_mqtt_client_init(&cfg);
    esp_mqtt_client_register_event(s_client, ESP_EVENT_ANY_ID, mqtt_event_handler, NULL);
    esp_mqtt_client_start(s_client);

    ESP_LOGI(TAG, "connecting to MQTT broker %s:%d", host, port);
}

void mqtt_ha_init(const char *host, int port, const char *user, const char *pass)
{
    do_init(host, port, user, pass);
}

void mqtt_ha_init_from_nvs(void)
{
    nvs_handle_t h;
    char host[64] = {0}, user[64] = {0}, pass[64] = {0};
    int  port = 1883;

    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) == ESP_OK) {
        size_t len;
        len = sizeof(host); nvs_get_str(h, "host", host, &len);
        len = sizeof(user); nvs_get_str(h, "user", user, &len);
        len = sizeof(pass); nvs_get_str(h, "pass", pass, &len);
        int32_t p; if (nvs_get_i32(h, "port", &p) == ESP_OK) port = (int)p;
        nvs_close(h);
    }
    do_init(host, port, user, pass);
}

void mqtt_ha_set_broker(const char *host, int port, const char *user, const char *pass)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_str(h, "host", host);
        nvs_set_str(h, "user", user ? user : "");
        nvs_set_str(h, "pass", pass ? pass : "");
        nvs_set_i32(h, "port", port);
        nvs_commit(h);
        nvs_close(h);
    }
}

void mqtt_ha_publish_device(const device_info_t *dev, device_event_t event)
{
    if (!s_client || !s_connected || !dev) return;

    /* Unique ID: fabric + node (or name if no fabric) */
    char uid[64];
    if (dev->fabric_id[0] && dev->node_id[0]) {
        snprintf(uid, sizeof(uid), "%s_%s", dev->fabric_id, dev->node_id);
    } else {
        /* Sanitise name for use as ID */
        strncpy(uid, dev->name, sizeof(uid) - 1);
        for (char *p = uid; *p; p++) {
            if (*p == ' ' || *p == '.' || *p == '-') *p = '_';
        }
    }

    char topic[256];

    if (event == DEVICE_EVENT_DISCOVERED) {
        /* HA MQTT auto-discovery config message */
        char payload[1024];
        snprintf(payload, sizeof(payload),
            "{"
            "\"name\":\"%s\","
            "\"unique_id\":\"ms_%s\","
            "\"state_topic\":\"%s/%s/state\","
            "\"availability_topic\":\"%s/%s/availability\","
            "\"json_attributes_topic\":\"%s/%s/state\","
            "\"device\":{"
              "\"identifiers\":[\"ms_%s\"],"
              "\"name\":\"%s\","
              "\"model\":\"%s (VID:0x%04X PID:0x%04X)\","
              "\"manufacturer\":\"Matter\""
            "}"
            "}",
            dev->name,
            uid,
            TOPIC_PREFIX, uid,
            TOPIC_PREFIX, uid,
            TOPIC_PREFIX, uid,
            uid,
            dev->name,
            device_type_str(dev->device_type),
            dev->vendor_id, dev->product_id);

        snprintf(topic, sizeof(topic), "%s/sensor/matter_sniffer/%s/config",
                 HA_DISCOVERY, uid);
        esp_mqtt_client_publish(s_client, topic, payload, 0, 1, true);
    }

    /* Availability */
    snprintf(topic, sizeof(topic), "%s/%s/availability", TOPIC_PREFIX, uid);
    const char *avail = dev->is_online ? "online" : "offline";
    esp_mqtt_client_publish(s_client, topic, avail, 0, 1, true);

    if (dev->is_online) {
        /* State / attributes */
        char state[512];
        snprintf(state, sizeof(state),
            "{"
            "\"ip\":\"%s\","
            "\"mac\":\"%s\","
            "\"rssi\":%d,"
            "\"vendor_id\":\"0x%04X\","
            "\"product_id\":\"0x%04X\","
            "\"device_type\":\"%s\","
            "\"fabric_id\":\"%s\","
            "\"node_id\":\"%s\","
            "\"port\":%d"
            "}",
            dev->ip, dev->mac, dev->rssi,
            dev->vendor_id, dev->product_id,
            device_type_str(dev->device_type),
            dev->fabric_id, dev->node_id, dev->port);

        snprintf(topic, sizeof(topic), "%s/%s/state", TOPIC_PREFIX, uid);
        esp_mqtt_client_publish(s_client, topic, state, 0, 0, false);
    }
}

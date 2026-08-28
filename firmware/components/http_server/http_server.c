#include "http_server.h"
#include "device_registry.h"
#include "packet_sniffer.h"
#include "wifi_manager.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "nvs.h"

static const char *TAG = "http_srv";
static httpd_handle_t s_server = NULL;

/* Embedded web page */
extern const uint8_t index_html_start[] asm("_binary_index_html_start");
extern const uint8_t index_html_end[]   asm("_binary_index_html_end");

/* WebSocket client list (single client supported for simplicity) */
#define MAX_WS_CLIENTS 4
static int s_ws_fds[MAX_WS_CLIENTS];
static SemaphoreHandle_t s_ws_mutex;

static void ws_send_all(const char *json, int len)
{
    if (!s_server) return;
    if (xSemaphoreTake(s_ws_mutex, pdMS_TO_TICKS(50)) != pdTRUE) return;
    for (int i = 0; i < MAX_WS_CLIENTS; i++) {
        if (s_ws_fds[i] <= 0) continue;
        httpd_ws_frame_t ws_pkt = {
            .type    = HTTPD_WS_TYPE_TEXT,
            .payload = (uint8_t *)json,
            .len     = (size_t)len,
        };
        if (httpd_ws_send_frame_async(s_server, s_ws_fds[i], &ws_pkt) != ESP_OK) {
            s_ws_fds[i] = 0;  /* client disconnected */
        }
    }
    xSemaphoreGive(s_ws_mutex);
}

/* ---- Helpers ---- */

/* Escape a string for safe embedding in a JSON string literal.
 * Handles " and \ which would break JSON structure; strips C0 controls.
 * Returns number of bytes written to out (excluding NUL). */
static int json_escape(char *out, size_t out_len, const char *in)
{
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 3 < out_len; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"' || c == '\\') {
            out[j++] = '\\';
            out[j++] = (char)c;
        } else if (c >= 0x20) {
            out[j++] = (char)c;
        }
        /* strip control chars — they have no place in a device name */
    }
    out[j] = '\0';
    return (int)j;
}

/* ---- Handlers ---- */

static esp_err_t index_get_handler(httpd_req_t *req)
{
    size_t len = (size_t)(index_html_end - index_html_start);
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, (const char *)index_html_start, (ssize_t)len);
}

static esp_err_t api_devices_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr_chunk(req, "[");

    int idx = 0;
    const device_info_t *dev;
    bool first = true;
    while ((dev = device_registry_next(&idx)) != NULL) {
        char esc_name[DEVICE_NAME_LEN * 2];
        json_escape(esc_name, sizeof(esc_name), dev->name);
        char buf[512];
        int n = snprintf(buf, sizeof(buf),
            "%s{"
            "\"name\":\"%s\","
            "\"ip\":\"%s\","
            "\"mac\":\"%s\","
            "\"online\":%s,"
            "\"rssi\":%d,"
            "\"vendor_id\":\"0x%04X\","
            "\"product_id\":\"0x%04X\","
            "\"device_type\":\"0x%04X\","
            "\"fabric_id\":\"%s\","
            "\"node_id\":\"%s\","
            "\"port\":%d"
            "}",
            first ? "" : ",",
            esc_name, dev->ip, dev->mac,
            dev->is_online ? "true" : "false",
            dev->rssi,
            dev->vendor_id, dev->product_id, dev->device_type,
            dev->fabric_id, dev->node_id, dev->port);
        httpd_resp_send_chunk(req, buf, n);
        first = false;
    }
    httpd_resp_sendstr_chunk(req, "]");
    return httpd_resp_send_chunk(req, NULL, 0);
}

static esp_err_t api_stats_handler(httpd_req_t *req)
{
    sniffer_stats_t stats;
    packet_sniffer_get_stats(&stats);

    char buf[512];
    int n = snprintf(buf, sizeof(buf),
        "{"
        "\"total_devices\":%d,"
        "\"online_devices\":%d,"
        "\"channel\":%d,"
        "\"ip\":\"%s\","
        "\"uptime_s\":%lld,"
        "\"frames_total\":%lu,"
        "\"frames_mgmt\":%lu,"
        "\"frames_data\":%lu,"
        "\"frames_arp\":%lu,"
        "\"frames_matter_tcp\":%lu"
        "}",
        device_registry_count(),
        device_registry_online_count(),
        wifi_manager_get_channel(),
        wifi_manager_get_ip_str(),
        esp_timer_get_time() / 1000000,
        (unsigned long)stats.total_frames,
        (unsigned long)stats.mgmt_frames,
        (unsigned long)stats.data_frames,
        (unsigned long)stats.arp_frames,
        (unsigned long)stats.matter_tcp_frames);

    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, buf, n);
}

static esp_err_t ws_handler(httpd_req_t *req)
{
    if (req->method == HTTP_GET) {
        ESP_LOGI(TAG, "WS handshake from fd=%d", httpd_req_to_sockfd(req));
        xSemaphoreTake(s_ws_mutex, portMAX_DELAY);
        int fd = httpd_req_to_sockfd(req);
        for (int i = 0; i < MAX_WS_CLIENTS; i++) {
            if (s_ws_fds[i] <= 0) {
                s_ws_fds[i] = fd;
                break;
            }
        }
        xSemaphoreGive(s_ws_mutex);
        return ESP_OK;
    }

    /* Handle incoming text frames (ignored for now) */
    httpd_ws_frame_t ws_pkt = {0};
    ws_pkt.type = HTTPD_WS_TYPE_TEXT;
    uint8_t buf[128] = {0};
    ws_pkt.payload = buf;
    ws_pkt.len = sizeof(buf);
    httpd_ws_recv_frame(req, &ws_pkt, sizeof(buf));
    return ESP_OK;
}

/* ---- Config helpers ---- */

static void json_get_str_field(const char *json, const char *key, char *out, size_t out_len)
{
    *out = '\0';
    char search[72];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(json, search);
    if (!p) return;
    p += strlen(search);
    while (*p == ' ' || *p == '\t') p++;
    if (*p != ':') return;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '"') {
        p++;
        size_t i = 0;
        while (*p && *p != '"' && i < out_len - 1) {
            if (*p == '\\') {
                p++;
                if (*p == '"' || *p == '\\' || *p == '/') out[i++] = *p++;
                else if (*p == 'n') { out[i++] = '\n'; p++; }
                else if (*p == 't') { out[i++] = '\t'; p++; }
                else p++;
            } else {
                out[i++] = *p++;
            }
        }
        out[i] = '\0';
    } else {
        size_t i = 0;
        while (*p && *p != ',' && *p != '}' && *p != ' ' && i < out_len - 1) {
            out[i++] = *p++;
        }
        out[i] = '\0';
    }
}

static esp_err_t api_config_get_handler(httpd_req_t *req)
{
    char wifi_ssid[64] = {0};
    char mqtt_host[64] = {0};
    char mqtt_user[64] = {0};
    int32_t mqtt_port = 1883;
    bool has_wifi_pass = false;
    bool has_mqtt_pass = false;

    nvs_handle_t h;
    if (nvs_open("wifi_cfg", NVS_READONLY, &h) == ESP_OK) {
        size_t len = sizeof(wifi_ssid);
        nvs_get_str(h, "ssid", wifi_ssid, &len);
        char tmp[64] = {0}; len = sizeof(tmp);
        if (nvs_get_str(h, "pass", tmp, &len) == ESP_OK && tmp[0]) has_wifi_pass = true;
        nvs_close(h);
    }
    if (nvs_open("mqtt_cfg", NVS_READONLY, &h) == ESP_OK) {
        size_t len = sizeof(mqtt_host);
        nvs_get_str(h, "host", mqtt_host, &len);
        len = sizeof(mqtt_user);
        nvs_get_str(h, "user", mqtt_user, &len);
        nvs_get_i32(h, "port", &mqtt_port);
        char tmp[64] = {0}; len = sizeof(tmp);
        if (nvs_get_str(h, "pass", tmp, &len) == ESP_OK && tmp[0]) has_mqtt_pass = true;
        nvs_close(h);
    }

    char buf[512];
    int n = snprintf(buf, sizeof(buf),
        "{"
        "\"wifi_ssid\":\"%s\","
        "\"wifi_pass_set\":%s,"
        "\"mqtt_host\":\"%s\","
        "\"mqtt_port\":%d,"
        "\"mqtt_user\":\"%s\","
        "\"mqtt_pass_set\":%s"
        "}",
        wifi_ssid,
        has_wifi_pass ? "true" : "false",
        mqtt_host,
        (int)mqtt_port,
        mqtt_user,
        has_mqtt_pass ? "true" : "false");

    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, buf, n);
}

static void do_restart(void *arg) {
    vTaskDelay(pdMS_TO_TICKS(600));
    esp_restart();
}

static esp_err_t api_config_post_handler(httpd_req_t *req)
{
    int content_len = req->content_len;
    if (content_len <= 0 || content_len > 512) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad request");
        return ESP_FAIL;
    }

    char *body = malloc((size_t)content_len + 1);
    if (!body) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OOM");
        return ESP_FAIL;
    }

    int received = httpd_req_recv(req, body, content_len);
    if (received <= 0) {
        free(body);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "read error");
        return ESP_FAIL;
    }
    body[received] = '\0';

    char wifi_ssid[64] = {0}, wifi_pass[64] = {0};
    char mqtt_host[64] = {0}, mqtt_user[64] = {0}, mqtt_pass[64] = {0};
    char mqtt_port_str[8] = {0};

    json_get_str_field(body, "wifi_ssid",  wifi_ssid,     sizeof(wifi_ssid));
    json_get_str_field(body, "wifi_pass",  wifi_pass,     sizeof(wifi_pass));
    json_get_str_field(body, "mqtt_host",  mqtt_host,     sizeof(mqtt_host));
    json_get_str_field(body, "mqtt_port",  mqtt_port_str, sizeof(mqtt_port_str));
    json_get_str_field(body, "mqtt_user",  mqtt_user,     sizeof(mqtt_user));
    json_get_str_field(body, "mqtt_pass",  mqtt_pass,     sizeof(mqtt_pass));
    free(body);

    int mqtt_port = mqtt_port_str[0] ? atoi(mqtt_port_str) : 1883;
    if (mqtt_port <= 0 || mqtt_port > 65535) mqtt_port = 1883;

    nvs_handle_t h;
    if (wifi_ssid[0] && nvs_open("wifi_cfg", NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_str(h, "ssid", wifi_ssid);
        if (wifi_pass[0]) nvs_set_str(h, "pass", wifi_pass);
        nvs_commit(h);
        nvs_close(h);
        ESP_LOGI(TAG, "WiFi config saved: ssid=%s", wifi_ssid);
    }
    if (mqtt_host[0] && nvs_open("mqtt_cfg", NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_str(h, "host", mqtt_host);
        nvs_set_str(h, "user", mqtt_user);
        if (mqtt_pass[0]) nvs_set_str(h, "pass", mqtt_pass);
        nvs_set_i32(h, "port", (int32_t)mqtt_port);
        nvs_commit(h);
        nvs_close(h);
        ESP_LOGI(TAG, "MQTT config saved: host=%s:%d user=%s", mqtt_host, mqtt_port, mqtt_user);
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"status\":\"ok\",\"restarting\":true}");

    xTaskCreate(do_restart, "restart", 1024, NULL, 1, NULL);
    return ESP_OK;
}

/* ---- Public API ---- */

void http_server_notify_device(const device_info_t *dev, device_event_t event)
{
    char esc_name[DEVICE_NAME_LEN * 2];
    json_escape(esc_name, sizeof(esc_name), dev->name);
    char json[512];
    int n = snprintf(json, sizeof(json),
        "{"
        "\"event\":\"%s\","
        "\"name\":\"%s\","
        "\"ip\":\"%s\","
        "\"mac\":\"%s\","
        "\"online\":%s,"
        "\"rssi\":%d,"
        "\"vendor_id\":\"0x%04X\","
        "\"product_id\":\"0x%04X\","
        "\"device_type\":\"0x%04X\","
        "\"fabric_id\":\"%s\","
        "\"node_id\":\"%s\""
        "}",
        event == DEVICE_EVENT_DISCOVERED ? "discovered" :
        event == DEVICE_EVENT_ONLINE ? "online" :
        event == DEVICE_EVENT_OFFLINE ? "offline" : "updated",
        esc_name, dev->ip, dev->mac,
        dev->is_online ? "true" : "false",
        dev->rssi,
        dev->vendor_id, dev->product_id, dev->device_type,
        dev->fabric_id, dev->node_id);

    ws_send_all(json, n);
}

void http_server_init(void)
{
    s_ws_mutex = xSemaphoreCreateMutex();
    memset(s_ws_fds, 0, sizeof(s_ws_fds));

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = 80;
    config.max_open_sockets = 4;  /* lwIP default allows 10 sockets; httpd uses 3 internally */

    if (httpd_start(&s_server, &config) != ESP_OK) {
        ESP_LOGE(TAG, "failed to start HTTP server");
        return;
    }

    static const httpd_uri_t uri_index = {
        .uri     = "/",
        .method  = HTTP_GET,
        .handler = index_get_handler,
    };
    static const httpd_uri_t uri_devices = {
        .uri     = "/api/devices",
        .method  = HTTP_GET,
        .handler = api_devices_handler,
    };
    static const httpd_uri_t uri_stats = {
        .uri     = "/api/stats",
        .method  = HTTP_GET,
        .handler = api_stats_handler,
    };
    static const httpd_uri_t uri_ws = {
        .uri         = "/ws",
        .method      = HTTP_GET,
        .handler     = ws_handler,
        .is_websocket = true,
    };
    static const httpd_uri_t uri_config_get = {
        .uri     = "/api/config",
        .method  = HTTP_GET,
        .handler = api_config_get_handler,
    };
    static const httpd_uri_t uri_config_post = {
        .uri     = "/api/config",
        .method  = HTTP_POST,
        .handler = api_config_post_handler,
    };

    httpd_register_uri_handler(s_server, &uri_index);
    httpd_register_uri_handler(s_server, &uri_devices);
    httpd_register_uri_handler(s_server, &uri_stats);
    httpd_register_uri_handler(s_server, &uri_ws);
    httpd_register_uri_handler(s_server, &uri_config_get);
    httpd_register_uri_handler(s_server, &uri_config_post);

    ESP_LOGI(TAG, "HTTP server running on port 80");
}

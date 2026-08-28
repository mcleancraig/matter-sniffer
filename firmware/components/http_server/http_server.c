#include "http_server.h"
#include "device_registry.h"
#include "packet_sniffer.h"
#include "wifi_manager.h"

#include <string.h>
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_timer.h"

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
    xSemaphoreTake(s_ws_mutex, pdMS_TO_TICKS(50));
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
            dev->name, dev->ip, dev->mac,
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

/* ---- Public API ---- */

void http_server_notify_device(const device_info_t *dev, device_event_t event)
{
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
        dev->name, dev->ip, dev->mac,
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

    httpd_register_uri_handler(s_server, &uri_index);
    httpd_register_uri_handler(s_server, &uri_devices);
    httpd_register_uri_handler(s_server, &uri_stats);
    httpd_register_uri_handler(s_server, &uri_ws);

    ESP_LOGI(TAG, "HTTP server running on port 80");
}

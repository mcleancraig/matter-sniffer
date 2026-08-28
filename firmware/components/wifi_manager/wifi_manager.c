#include "wifi_manager.h"
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "nvs_flash.h"
#include "nvs.h"

#define WIFI_CONNECTED_BIT  BIT0
#define WIFI_FAIL_BIT       BIT1
#define MAX_RETRY           10
#define NVS_NAMESPACE       "wifi_cfg"

static const char *TAG = "wifi_mgr";
static EventGroupHandle_t s_wifi_event_group;
static esp_netif_t *s_netif = NULL;
static int s_retry_count = 0;
static char s_ip_str[16] = "0.0.0.0";
static uint8_t s_channel = 1;

static void load_credentials(char *ssid, size_t ssid_len, char *pass, size_t pass_len)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) == ESP_OK) {
        nvs_get_str(h, "ssid", ssid, &ssid_len);
        nvs_get_str(h, "pass", pass, &pass_len);
        nvs_close(h);
    }
    /* Fall back to Kconfig if NVS is empty */
    if (ssid[0] == '\0') {
        strncpy(ssid, CONFIG_MATTER_SNIFFER_WIFI_SSID, ssid_len - 1);
        strncpy(pass, CONFIG_MATTER_SNIFFER_WIFI_PASSWORD, pass_len - 1);
    }
}

static void event_handler(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_retry_count < MAX_RETRY) {
            esp_wifi_connect();
            s_retry_count++;
            ESP_LOGW(TAG, "retrying connection (%d/%d)", s_retry_count, MAX_RETRY);
        } else {
            /* Signal the boot-path waiter that initial connection failed,
             * then reset the counter so future disconnect events (e.g. after
             * a transient network outage) will retry rather than staying down. */
            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
            s_retry_count = 0;
            ESP_LOGE(TAG, "connection failed — check credentials or AP availability");
        }
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)data;
        snprintf(s_ip_str, sizeof(s_ip_str), IPSTR, IP2STR(&event->ip_info.ip));
        ESP_LOGI(TAG, "connected, IP: %s", s_ip_str);
        s_retry_count = 0;

        wifi_ap_record_t ap;
        if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
            s_channel = ap.primary;
        }

        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

void wifi_manager_init(void)
{
    s_wifi_event_group = xEventGroupCreate();
    s_netif = esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL, NULL));

    char ssid[64] = {0};
    char pass[64] = {0};
    load_credentials(ssid, sizeof(ssid), pass, sizeof(pass));

    if (ssid[0] == '\0') {
        ESP_LOGW(TAG, "no WiFi credentials configured — set via: CONFIG ssid:pass:mqtt_host");
        return;
    }

    wifi_config_t wifi_cfg = {0};
    strncpy((char *)wifi_cfg.sta.ssid, ssid, sizeof(wifi_cfg.sta.ssid) - 1);
    strncpy((char *)wifi_cfg.sta.password, pass, sizeof(wifi_cfg.sta.password) - 1);
    wifi_cfg.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "connecting to %s ...", ssid);
}

void wifi_manager_wait_connected(void)
{
    if (s_wifi_event_group == NULL) return;
    EventBits_t bits = xEventGroupWaitBits(
        s_wifi_event_group,
        WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
        pdFALSE, pdFALSE,
        portMAX_DELAY);
    if (bits & WIFI_FAIL_BIT) {
        ESP_LOGE(TAG, "WiFi connection failed — check credentials");
    }
}

void wifi_manager_set_credentials(const char *ssid, const char *password)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_str(h, "ssid", ssid);
        nvs_set_str(h, "pass", password);
        nvs_commit(h);
        nvs_close(h);
        ESP_LOGI(TAG, "credentials saved to NVS");
    }
}

uint8_t wifi_manager_get_channel(void)
{
    return s_channel;
}

const char *wifi_manager_get_ip_str(void)
{
    return s_ip_str;
}

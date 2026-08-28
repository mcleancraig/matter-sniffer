#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_event.h"
#include "esp_netif.h"

#include "wifi_manager.h"
#include "packet_sniffer.h"
#include "mdns_scanner.h"
#include "device_registry.h"
#include "pcap_streamer.h"
#include "mqtt_ha.h"
#include "http_server.h"

static const char *TAG = "main";

static void on_device_changed(const device_info_t *dev, device_event_t event)
{
    mqtt_ha_publish_device(dev, event);
    http_server_notify_device(dev, event);
}

static void handle_serial_commands(void *arg)
{
    char buf[64];
    int pos = 0;

    while (1) {
        int c = fgetc(stdin);
        if (c == EOF) {
            vTaskDelay(pdMS_TO_TICKS(10));
            continue;
        }
        if (c == '\r' || c == '\n') {
            if (pos > 0) {
                buf[pos] = '\0';
                if (strcmp(buf, "pcap on") == 0) {
                    pcap_streamer_set_enabled(true);
                    printf("pcap: enabled\n");
                } else if (strcmp(buf, "pcap off") == 0) {
                    pcap_streamer_set_enabled(false);
                    printf("pcap: disabled\n");
                } else if (strcmp(buf, "pcap mdns") == 0) {
                    pcap_streamer_set_filter(PCAP_FILTER_MDNS);
                    printf("pcap: mDNS only\n");
                } else if (strcmp(buf, "pcap all") == 0) {
                    pcap_streamer_set_filter(PCAP_FILTER_ALL);
                    printf("pcap: all frames\n");
                } else if (strcmp(buf, "devices") == 0) {
                    device_registry_dump();
                } else if (strncmp(buf, "CONFIG ", 7) == 0) {
                    /* FORMAT: CONFIG ssid:pass:mqtt_host */
                    char *p = buf + 7;
                    char *ssid = strsep(&p, ":");
                    char *pass = strsep(&p, ":");
                    char *mqtt = p;
                    if (ssid && pass && mqtt) {
                        wifi_manager_set_credentials(ssid, pass);
                        mqtt_ha_set_broker(mqtt, 1883, "", "");
                        printf("Config saved, restarting...\n");
                        vTaskDelay(pdMS_TO_TICKS(500));
                        esp_restart();
                    } else {
                        printf("Usage: CONFIG ssid:password:mqtt_host\n");
                    }
                } else if (strcmp(buf, "restart") == 0) {
                    esp_restart();
                } else if (strlen(buf) > 0) {
                    printf("Commands: pcap on/off/mdns/all | devices | CONFIG s:p:h | restart\n");
                }
                pos = 0;
            }
        } else if (pos < (int)sizeof(buf) - 1) {
            buf[pos++] = (char)c;
        }
    }
}

void app_main(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(esp_netif_init());

    ESP_LOGI(TAG, "Matter Sniffer starting");

    device_registry_init(on_device_changed);
    pcap_streamer_init();

#ifdef CONFIG_MATTER_SNIFFER_PCAP_ENABLED
    pcap_streamer_set_enabled(true);
#endif

    /* Start serial command handler */
    xTaskCreate(handle_serial_commands, "serial_cmd", 4096, NULL, 1, NULL);

    /* Start WiFi — blocks until connected, then initialises the rest */
    wifi_manager_init();
    wifi_manager_wait_connected();

    ESP_LOGI(TAG, "WiFi connected, starting services");

    packet_sniffer_init();
    mdns_scanner_init();

    if (strlen(CONFIG_MATTER_SNIFFER_MQTT_HOST) > 0) {
        mqtt_ha_init(CONFIG_MATTER_SNIFFER_MQTT_HOST,
                     CONFIG_MATTER_SNIFFER_MQTT_PORT,
                     CONFIG_MATTER_SNIFFER_MQTT_USER,
                     CONFIG_MATTER_SNIFFER_MQTT_PASS);
    } else {
        /* Try NVS */
        mqtt_ha_init_from_nvs();
    }

    http_server_init();

    ESP_LOGI(TAG, "All services started. IP: %s", wifi_manager_get_ip_str());
    ESP_LOGI(TAG, "Web UI: http://%s/", wifi_manager_get_ip_str());
    ESP_LOGI(TAG, "Serial commands: pcap on/off | devices | CONFIG s:p:h");
}

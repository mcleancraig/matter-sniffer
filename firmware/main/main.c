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
#include "led_strip.h"

#define LED_GPIO   48
#define LED_BRIGHT 3    /* near WS2812 minimum threshold */

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
            putchar('\n');
            fflush(stdout);
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
                    /* FORMAT: CONFIG ssid:pass:mqtt_host[:mqtt_user:mqtt_pass] */
                    char *p = buf + 7;
                    char *ssid      = strsep(&p, ":");
                    char *pass      = strsep(&p, ":");
                    char *mqtt_host = strsep(&p, ":");
                    char *mqtt_user = p ? strsep(&p, ":") : NULL;
                    char *mqtt_pass = p;  /* remainder, may be NULL */
                    if (ssid && pass && mqtt_host) {
                        wifi_manager_set_credentials(ssid, pass);
                        mqtt_ha_set_broker(mqtt_host, 1883,
                                           mqtt_user ? mqtt_user : "",
                                           mqtt_pass ? mqtt_pass : "");
                        printf("Config saved, restarting...\n");
                        vTaskDelay(pdMS_TO_TICKS(500));
                        esp_restart();
                    } else {
                        printf("Usage: CONFIG ssid:pass:mqtt_host[:mqtt_user:mqtt_pass]\n");
                    }
                } else if (strcmp(buf, "restart") == 0) {
                    esp_restart();
                } else if (strlen(buf) > 0) {
                    printf("Commands: pcap on/off/mdns/all | devices | CONFIG s:p:h | restart\n");
                }
                pos = 0;
            }
        } else if (c == 127 || c == 8) {
            /* backspace / delete */
            if (pos > 0) {
                pos--;
                printf("\b \b");
                fflush(stdout);
            }
        } else if (pos < (int)sizeof(buf) - 1) {
            buf[pos++] = (char)c;
            putchar(c);
            fflush(stdout);
        }
    }
}

static void led_init(void)
{
    led_strip_config_t cfg = {
        .strip_gpio_num = LED_GPIO,
        .max_leds       = 1,
        .led_model      = LED_MODEL_WS2812,
        .color_component_format = LED_STRIP_COLOR_COMPONENT_FMT_GRB,
    };
    led_strip_rmt_config_t rmt_cfg = {
        .resolution_hz = 10 * 1000 * 1000,  /* 10 MHz */
    };
    led_strip_handle_t strip;
    if (led_strip_new_rmt_device(&cfg, &rmt_cfg, &strip) == ESP_OK) {
        led_strip_clear(strip);
        led_strip_refresh(strip);
    }
}

void app_main(void)
{
    led_init();

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

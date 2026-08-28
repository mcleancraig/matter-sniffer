#pragma once
#include <stdint.h>
#include "esp_err.h"

void     wifi_manager_init(void);
void     wifi_manager_wait_connected(void);
void     wifi_manager_set_credentials(const char *ssid, const char *password);
uint8_t  wifi_manager_get_channel(void);
const char *wifi_manager_get_ip_str(void);

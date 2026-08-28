#pragma once
#include "device_registry.h"

void mqtt_ha_init(const char *host, int port, const char *user, const char *pass);
void mqtt_ha_init_from_nvs(void);
void mqtt_ha_set_broker(const char *host, int port, const char *user, const char *pass);
void mqtt_ha_publish_device(const device_info_t *dev, device_event_t event);

#pragma once
#include "device_registry.h"

void http_server_init(void);
void http_server_notify_device(const device_info_t *dev, device_event_t event);

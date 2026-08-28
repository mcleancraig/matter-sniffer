#include "device_registry.h"
#include <string.h>
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_timer.h"

#define OFFLINE_TIMEOUT_MS  300000LL   /* 5 minutes */

static const char *TAG = "dev_reg";
static device_info_t s_devices[DEVICE_MAX];
static SemaphoreHandle_t s_mutex;
static device_change_cb_t s_cb = NULL;

void device_registry_init(device_change_cb_t cb)
{
    memset(s_devices, 0, sizeof(s_devices));
    s_mutex = xSemaphoreCreateMutex();
    s_cb = cb;
}

static device_info_t *find_by_node_id(const char *fabric, const char *node)
{
    for (int i = 0; i < DEVICE_MAX; i++) {
        if (s_devices[i].in_use &&
            strcmp(s_devices[i].fabric_id, fabric) == 0 &&
            strcmp(s_devices[i].node_id, node) == 0) {
            return &s_devices[i];
        }
    }
    return NULL;
}

static device_info_t *find_by_name(const char *name)
{
    for (int i = 0; i < DEVICE_MAX; i++) {
        if (s_devices[i].in_use && strcmp(s_devices[i].name, name) == 0) {
            return &s_devices[i];
        }
    }
    return NULL;
}

static device_info_t *find_free(void)
{
    for (int i = 0; i < DEVICE_MAX; i++) {
        if (!s_devices[i].in_use) return &s_devices[i];
    }
    return NULL;
}

const device_info_t *device_registry_update(const device_info_t *info)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);

    device_info_t *entry = NULL;
    bool is_new = false;

    if (info->fabric_id[0] && info->node_id[0]) {
        entry = find_by_node_id(info->fabric_id, info->node_id);
    }
    if (!entry && info->name[0]) {
        entry = find_by_name(info->name);
    }
    if (!entry) {
        entry = find_free();
        if (!entry) {
            ESP_LOGE(TAG, "device table full");
            xSemaphoreGive(s_mutex);
            return NULL;
        }
        is_new = true;
        entry->in_use = true;
        entry->first_seen_ms = esp_timer_get_time() / 1000;
    }

    bool was_offline = !entry->is_online;

    /* Merge incoming data — don't overwrite good data with empty strings */
#define COPY_IF_NONEMPTY(dst, src, len) \
    if ((src)[0]) strncpy(dst, src, (len) - 1)

    COPY_IF_NONEMPTY(entry->name, info->name, DEVICE_NAME_LEN);
    COPY_IF_NONEMPTY(entry->ip, info->ip, DEVICE_IP_LEN);
    COPY_IF_NONEMPTY(entry->mac, info->mac, DEVICE_MAC_LEN);
    COPY_IF_NONEMPTY(entry->fabric_id, info->fabric_id, 17);
    COPY_IF_NONEMPTY(entry->node_id, info->node_id, 17);
#undef COPY_IF_NONEMPTY

    if (info->vendor_id)  entry->vendor_id  = info->vendor_id;
    if (info->product_id) entry->product_id = info->product_id;
    if (info->device_type) entry->device_type = info->device_type;
    if (info->port)       entry->port       = info->port;
    if (info->rssi)       entry->rssi       = info->rssi;

    entry->is_online    = true;
    entry->last_seen_ms = esp_timer_get_time() / 1000;

    device_event_t event = is_new ? DEVICE_EVENT_DISCOVERED :
                           was_offline ? DEVICE_EVENT_ONLINE :
                           DEVICE_EVENT_UPDATED;

    if (s_cb) s_cb(entry, event);

    xSemaphoreGive(s_mutex);
    return entry;
}

void device_registry_update_rssi(const char *mac, int8_t rssi)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    for (int i = 0; i < DEVICE_MAX; i++) {
        if (s_devices[i].in_use && strcmp(s_devices[i].mac, mac) == 0) {
            s_devices[i].rssi = rssi;
            break;
        }
    }
    xSemaphoreGive(s_mutex);
}

void device_registry_check_availability(void)
{
    int64_t now_ms = esp_timer_get_time() / 1000;
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    for (int i = 0; i < DEVICE_MAX; i++) {
        if (!s_devices[i].in_use || !s_devices[i].is_online) continue;
        if (now_ms - s_devices[i].last_seen_ms > OFFLINE_TIMEOUT_MS) {
            s_devices[i].is_online = false;
            ESP_LOGW(TAG, "device offline: %s", s_devices[i].name);
            if (s_cb) s_cb(&s_devices[i], DEVICE_EVENT_OFFLINE);
        }
    }
    xSemaphoreGive(s_mutex);
}

void device_registry_dump(void)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    printf("\n--- Matter Device Registry ---\n");
    int count = 0;
    for (int i = 0; i < DEVICE_MAX; i++) {
        if (!s_devices[i].in_use) continue;
        device_info_t *d = &s_devices[i];
        printf("[%s] %s\n"
               "  IP: %s  MAC: %s  RSSI: %ddBm\n"
               "  VID: 0x%04X  PID: 0x%04X  Type: 0x%04X\n"
               "  Fabric: %s  Node: %s\n\n",
               d->is_online ? "ONLINE " : "OFFLINE",
               d->name,
               d->ip, d->mac, d->rssi,
               d->vendor_id, d->product_id, d->device_type,
               d->fabric_id, d->node_id);
        count++;
    }
    printf("Total: %d devices\n", count);
    xSemaphoreGive(s_mutex);
}

const device_info_t *device_registry_next(int *idx)
{
    while (*idx < DEVICE_MAX) {
        device_info_t *d = &s_devices[(*idx)++];
        if (d->in_use) return d;
    }
    return NULL;
}

int device_registry_count(void)
{
    int n = 0;
    for (int i = 0; i < DEVICE_MAX; i++) {
        if (s_devices[i].in_use) n++;
    }
    return n;
}

int device_registry_online_count(void)
{
    int n = 0;
    for (int i = 0; i < DEVICE_MAX; i++) {
        if (s_devices[i].in_use && s_devices[i].is_online) n++;
    }
    return n;
}

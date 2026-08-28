#pragma once
#include <stdint.h>
#include <stdbool.h>

#define DEVICE_MAX          256
#define DEVICE_NAME_LEN     64
#define DEVICE_IP_LEN       40    /* enough for IPv6 */
#define DEVICE_MAC_LEN      18    /* "aa:bb:cc:dd:ee:ff" */

/* Matter device types (subset) */
#define MATTER_DTYPE_ON_OFF_LIGHT       0x0100
#define MATTER_DTYPE_DIMMABLE_LIGHT     0x0101
#define MATTER_DTYPE_THERMOSTAT         0x0301
#define MATTER_DTYPE_CONTACT_SENSOR     0x0015
#define MATTER_DTYPE_OCCUPANCY_SENSOR   0x0107
#define MATTER_DTYPE_DOOR_LOCK          0x000A

typedef struct {
    char     name[DEVICE_NAME_LEN];      /* mDNS service instance name */
    char     hostname[DEVICE_NAME_LEN];  /* mDNS hostname from SRV target, or reverse-DNS result */
    char     ip[DEVICE_IP_LEN];
    char     mac[DEVICE_MAC_LEN];
    uint16_t vendor_id;
    uint16_t product_id;
    uint16_t device_type;
    char     fabric_id[17];              /* 16 hex chars + NUL */
    char     node_id[17];
    uint16_t port;
    int8_t   rssi;
    bool     is_online;
    int64_t  last_seen_ms;
    int64_t  first_seen_ms;
    bool     in_use;
} device_info_t;

typedef enum {
    DEVICE_EVENT_DISCOVERED,
    DEVICE_EVENT_UPDATED,
    DEVICE_EVENT_ONLINE,
    DEVICE_EVENT_OFFLINE,
} device_event_t;

typedef void (*device_change_cb_t)(const device_info_t *dev, device_event_t event);

void device_registry_init(device_change_cb_t cb);

/* Update or add a device. Returns pointer to the entry (read-only). */
const device_info_t *device_registry_update(const device_info_t *info);

/* Update RSSI for a known IP or MAC */
void device_registry_update_rssi(const char *mac, int8_t rssi);

/* Mark stale devices offline (call periodically) */
void device_registry_check_availability(void);

/* Print all devices to console */
void device_registry_dump(void);

/* Iterate: returns NULL when done. idx starts at 0. */
const device_info_t *device_registry_next(int *idx);

int device_registry_count(void);
int device_registry_online_count(void);

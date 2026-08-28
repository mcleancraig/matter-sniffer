#include "pcap_streamer.h"
#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "esp_log.h"
#include "esp_timer.h"

/* Frame is framed over stdout with a simple envelope so the host tool
 * can distinguish pcap binary data from log text:
 *
 *   0xFE 0xFE <len_hi> <len_lo> <pcap_record_bytes...>
 *
 * The host tool (tools/pcap_capture.py) scans for 0xFE 0xFE and
 * extracts the binary pcap records, reassembling them into a .pcap file.
 */

#define MAGIC_0     0xFE
#define MAGIC_1     0xFE
#define MAX_FRAME   2304    /* max 802.11 frame size */
#define QUEUE_DEPTH 8

static const char *TAG = "pcap";

/* libpcap link types */
#define LINKTYPE_IEEE802_11_RADIOTAP  127
#define LINKTYPE_RAW                  101

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;          /* 0xa1b2c3d4 */
    uint16_t ver_major;      /* 2 */
    uint16_t ver_minor;      /* 4 */
    int32_t  thiszone;       /* 0 */
    uint32_t sigfigs;        /* 0 */
    uint32_t snaplen;        /* max frame length */
    uint32_t link_type;
} pcap_global_hdr_t;

typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcap_rec_hdr_t;

typedef struct {
    uint8_t  it_version;     /* 0 */
    uint8_t  it_pad;         /* 0 */
    uint16_t it_len;         /* length of entire radiotap header */
    uint32_t it_present;     /* bitmask of present fields */
    int8_t   dbm_signal;     /* RSSI — bit 5 of it_present */
    uint8_t  _pad[3];        /* align to 4 bytes */
} radiotap_hdr_t;
#pragma pack(pop)

typedef struct {
    uint8_t  data[MAX_FRAME + sizeof(radiotap_hdr_t)];
    int      len;
    int8_t   rssi;
    bool     is_raw_wifi;    /* true=802.11+radiotap, false=raw IP */
} frame_entry_t;

static QueueHandle_t s_queue;
static bool s_enabled = false;
static bool s_header_written = false;
static pcap_filter_t s_filter = PCAP_FILTER_MDNS;

/* Write global pcap header first time */
static void write_global_header(void)
{
    pcap_global_hdr_t hdr = {
        .magic      = 0xa1b2c3d4,
        .ver_major  = 2,
        .ver_minor  = 4,
        .thiszone   = 0,
        .sigfigs    = 0,
        .snaplen    = MAX_FRAME,
        .link_type  = LINKTYPE_IEEE802_11_RADIOTAP,
    };
    uint16_t total_len = (uint16_t)sizeof(hdr);
    putchar(MAGIC_0); putchar(MAGIC_1);
    putchar(total_len >> 8); putchar(total_len & 0xFF);
    fwrite(&hdr, 1, sizeof(hdr), stdout);
    fflush(stdout);
    s_header_written = true;
}

static void write_record(const uint8_t *payload, int payload_len, int8_t rssi, bool with_radiotap)
{
    if (!s_header_written) write_global_header();

    int64_t now_us = esp_timer_get_time();
    uint32_t ts_sec  = (uint32_t)(now_us / 1000000);
    uint32_t ts_usec = (uint32_t)(now_us % 1000000);

    uint8_t buf[sizeof(pcap_rec_hdr_t) + sizeof(radiotap_hdr_t) + MAX_FRAME];
    int out_len = 0;

    pcap_rec_hdr_t *rec = (pcap_rec_hdr_t *)buf;

    if (with_radiotap) {
        radiotap_hdr_t rth = {
            .it_version = 0,
            .it_pad     = 0,
            .it_len     = sizeof(radiotap_hdr_t),
            .it_present = (1u << 5),  /* DBM_ANTSIGNAL present */
            .dbm_signal = rssi,
        };
        int frame_with_rth = (int)sizeof(rth) + payload_len;
        rec->ts_sec  = ts_sec;
        rec->ts_usec = ts_usec;
        rec->incl_len = (uint32_t)frame_with_rth;
        rec->orig_len = (uint32_t)frame_with_rth;
        memcpy(buf + sizeof(pcap_rec_hdr_t), &rth, sizeof(rth));
        int copy = payload_len < MAX_FRAME ? payload_len : MAX_FRAME;
        memcpy(buf + sizeof(pcap_rec_hdr_t) + sizeof(rth), payload, copy);
        out_len = (int)sizeof(pcap_rec_hdr_t) + (int)sizeof(rth) + copy;
    } else {
        rec->ts_sec  = ts_sec;
        rec->ts_usec = ts_usec;
        rec->incl_len = (uint32_t)payload_len;
        rec->orig_len = (uint32_t)payload_len;
        int copy = payload_len < MAX_FRAME ? payload_len : MAX_FRAME;
        memcpy(buf + sizeof(pcap_rec_hdr_t), payload, copy);
        out_len = (int)sizeof(pcap_rec_hdr_t) + copy;
    }

    uint16_t total = (uint16_t)out_len;
    putchar(MAGIC_0); putchar(MAGIC_1);
    putchar(total >> 8); putchar(total & 0xFF);
    fwrite(buf, 1, out_len, stdout);
    fflush(stdout);
}

static void pcap_task(void *arg)
{
    frame_entry_t *entry = malloc(sizeof(frame_entry_t));
    if (!entry) {
        ESP_LOGE(TAG, "out of memory");
        vTaskDelete(NULL);
        return;
    }
    while (1) {
        if (xQueueReceive(s_queue, entry, pdMS_TO_TICKS(1000)) == pdTRUE) {
            if (s_enabled) {
                write_record(entry->data, entry->len, entry->rssi, entry->is_raw_wifi);
            }
        }
    }
}

void pcap_streamer_init(void)
{
    s_queue = xQueueCreate(QUEUE_DEPTH, sizeof(frame_entry_t));
    xTaskCreate(pcap_task, "pcap", 4096, NULL, 3, NULL);
    ESP_LOGI(TAG, "pcap streamer ready (disabled by default)");
    ESP_LOGI(TAG, "Enable with serial command: pcap on");
}

void pcap_streamer_set_enabled(bool enabled)
{
    s_enabled = enabled;
    if (enabled && !s_header_written) {
        write_global_header();
    }
    ESP_LOGI(TAG, "pcap output: %s", enabled ? "ON" : "OFF");
}

void pcap_streamer_set_filter(pcap_filter_t filter)
{
    s_filter = filter;
}

void pcap_streamer_write_frame(const uint8_t *frame, int len, int8_t rssi)
{
    if (!s_enabled || len <= 0 || len > MAX_FRAME) return;
    if (s_queue == NULL) return;

    frame_entry_t entry;
    entry.len = len;
    entry.rssi = rssi;
    entry.is_raw_wifi = true;
    memcpy(entry.data, frame, len);

    xQueueSend(s_queue, &entry, 0);  /* drop if full — non-blocking from ISR context */
}

void pcap_streamer_write_ip_frame(const uint8_t *ip_payload, int len)
{
    if (!s_enabled || len <= 0 || len > MAX_FRAME) return;
    if (s_queue == NULL) return;

    frame_entry_t entry;
    entry.len = len;
    entry.rssi = 0;
    entry.is_raw_wifi = false;
    memcpy(entry.data, ip_payload, len);

    xQueueSend(s_queue, &entry, 0);
}

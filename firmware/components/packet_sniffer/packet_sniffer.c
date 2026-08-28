#include "packet_sniffer.h"
#include "pcap_streamer.h"
#include "device_registry.h"

#include <string.h>
#include <stdint.h>
#include "esp_wifi.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "sniffer";

static sniffer_stats_t s_stats;

/* 802.11 frame control field bits */
#define FC_TYPE_MASK        0x000C
#define FC_TYPE_MGMT        0x0000
#define FC_TYPE_CTRL        0x0004
#define FC_TYPE_DATA        0x0008
#define FC_SUBTYPE_MASK     0x00F0
#define FC_TODS             0x0100
#define FC_FROMDS           0x0200
#define FC_QOS_DATA         0x0080  /* subtype bit indicating QoS */

/* LLC/SNAP constants */
#define LLC_DSAP_SNAP   0xAA
#define ETHERTYPE_ARP   0x0806
#define ETHERTYPE_IPv4  0x0800
#define ETHERTYPE_IPv6  0x86DD

#define MATTER_PORT     5540

static inline uint16_t be16(const uint8_t *p) {
    return (uint16_t)(p[0] << 8 | p[1]);
}
static inline uint16_t le16(const uint8_t *p) {
    return (uint16_t)(p[0] | p[1] << 8);
}

/* Returns pointer to LLC/SNAP field within a data frame payload, or NULL.
 * Handles the variable 802.11 MAC header length. */
static const uint8_t *find_llc(const uint8_t *frame, int len)
{
    if (len < 26) return NULL;  /* minimum data frame */

    uint16_t fc = le16(frame);
    uint16_t type = fc & FC_TYPE_MASK;
    if (type != FC_TYPE_DATA) return NULL;

    int hdr_len = 24;  /* base MAC header */
    uint16_t sub = (fc & FC_SUBTYPE_MASK) >> 4;
    if (sub & 0x08) hdr_len += 2;  /* QoS field */
    if ((fc & FC_TODS) && (fc & FC_FROMDS)) hdr_len += 6;  /* Addr4 */

    if (len < hdr_len + 8) return NULL;

    const uint8_t *llc = frame + hdr_len;
    if (llc[0] != LLC_DSAP_SNAP || llc[1] != LLC_DSAP_SNAP || llc[2] != 0x03) {
        return NULL;
    }
    return llc;
}

static void update_mac_rssi(const uint8_t *frame, int8_t rssi)
{
    /* Addr2 = transmitter address (bytes 10-15 for most data frames) */
    if (frame == NULL || rssi == 0) return;
    char mac_str[DEVICE_MAC_LEN];
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             frame[10], frame[11], frame[12], frame[13], frame[14], frame[15]);
    device_registry_update_rssi(mac_str, rssi);
}

static void promiscuous_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    int len = pkt->rx_ctrl.sig_len;
    if (len <= 0) return;

    s_stats.total_frames++;

    uint16_t fc = le16(pkt->payload);
    uint16_t frame_type = fc & FC_TYPE_MASK;

    if (frame_type == FC_TYPE_MGMT) {
        s_stats.mgmt_frames++;
        /* Management frames are never encrypted — forward all to pcap */
        pcap_streamer_write_frame(pkt->payload, len, pkt->rx_ctrl.rssi);
        return;
    }

    if (frame_type != FC_TYPE_DATA) return;

    s_stats.data_frames++;
    update_mac_rssi(pkt->payload, pkt->rx_ctrl.rssi);

    /* Try to parse the LLC/SNAP to identify frame type.
     * Note: in WPA2 networks, data frame payloads are encrypted.
     * We can only parse plaintext (e.g. broadcast frames with GTK
     * when our chip's WiFi stack has decrypted them) — or we just
     * use the raw frame for pcap and let Wireshark handle it. */
    const uint8_t *llc = find_llc(pkt->payload, len);
    if (llc) {
        uint16_t ethertype = be16(llc + 6);
        if (ethertype == ETHERTYPE_ARP) {
            s_stats.arp_frames++;
        } else if (ethertype == ETHERTYPE_IPv4) {
            const uint8_t *ip = llc + 8;
            if (ip[9] == 6) {  /* TCP */
                int ihl = (ip[0] & 0x0F) * 4;
                uint16_t dport = be16(ip + ihl + 2);
                uint16_t sport = be16(ip + ihl);
                if (dport == MATTER_PORT || sport == MATTER_PORT) {
                    s_stats.matter_tcp_frames++;
                }
            }
        }
    }

    /* Forward data frames to pcap — pcap_streamer decides whether to output */
    pcap_streamer_write_frame(pkt->payload, len, pkt->rx_ctrl.rssi);
}

static void availability_check_task(void *arg)
{
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(60000));
        device_registry_check_availability();
    }
}

void packet_sniffer_init(void)
{
    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA
    };
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(promiscuous_cb));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));

    ESP_LOGI(TAG, "promiscuous mode enabled");

    xTaskCreate(availability_check_task, "avail_check", 2048, NULL, 2, NULL);
}

void packet_sniffer_get_stats(sniffer_stats_t *out)
{
    *out = s_stats;
}

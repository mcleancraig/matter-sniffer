#pragma once
#include <stdint.h>
#include <stdbool.h>

typedef enum {
    PCAP_FILTER_MDNS  = 0,   /* mDNS + ARP only (default) */
    PCAP_FILTER_ALL   = 1,   /* all frames */
    PCAP_FILTER_MATTER = 2,  /* TCP port 5540 + mDNS only */
} pcap_filter_t;

void pcap_streamer_init(void);
void pcap_streamer_set_enabled(bool enabled);
void pcap_streamer_set_filter(pcap_filter_t filter);

/* Called from promiscuous callback or mdns scanner.
 * frame: raw 802.11 frame bytes
 * len:   frame length
 * rssi:  signal strength (used in radiotap header) */
void pcap_streamer_write_frame(const uint8_t *frame, int len, int8_t rssi);

/* For mDNS/IP layer frames captured via lwIP socket */
void pcap_streamer_write_ip_frame(const uint8_t *ip_payload, int len);

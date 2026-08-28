#pragma once
#include <stdint.h>

typedef struct {
    uint32_t total_frames;
    uint32_t mgmt_frames;
    uint32_t data_frames;
    uint32_t arp_frames;
    uint32_t matter_tcp_frames;
} sniffer_stats_t;

void packet_sniffer_init(void);
void packet_sniffer_get_stats(sniffer_stats_t *out);

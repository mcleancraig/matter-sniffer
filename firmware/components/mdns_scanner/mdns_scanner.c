#include "mdns_scanner.h"
#include "device_registry.h"
#include "pcap_streamer.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "lwip/igmp.h"
#include "esp_log.h"

#define MDNS_PORT       5353
#define MDNS_GROUP      "224.0.0.251"
#define RECV_BUF_SIZE   1500

/* Matter mDNS service types */
#define MATTER_TCP_SVC  "_matter._tcp.local"
#define MATTER_UDP_SVC  "_matterc._udp.local"
#define MESHCOP_SVC     "_meshcop._udp.local"

static const char *TAG = "mdns_scan";

/* ---- Minimal DNS packet parser ---- */

typedef struct {
    const uint8_t *pkt;
    int            pkt_len;
    int            pos;
} dns_cursor_t;

/* Expand a DNS name (with compression) into buf[buf_len].
 * Returns number of bytes consumed in the packet at current cursor pos,
 * or -1 on error. Does NOT advance cursor. */
static int dns_name_expand(const uint8_t *pkt, int pkt_len, int start,
                            char *buf, int buf_len)
{
    int pos = start;
    int buf_pos = 0;
    int followed_ptr = 0;
    int consumed = -1;  /* bytes consumed at original position */

    while (pos < pkt_len) {
        uint8_t len = pkt[pos];
        if (len == 0) {
            if (!followed_ptr) consumed = pos - start + 1;
            if (buf_pos > 0 && buf[buf_pos - 1] == '.') buf_pos--;  /* trim trailing dot */
            buf[buf_pos] = '\0';
            return consumed;
        }
        if ((len & 0xC0) == 0xC0) {
            /* Pointer */
            if (pos + 1 >= pkt_len) return -1;
            if (!followed_ptr) consumed = pos - start + 2;
            pos = ((len & 0x3F) << 8) | pkt[pos + 1];
            followed_ptr = 1;
            continue;
        }
        pos++;
        if (pos + len > pkt_len) return -1;
        if (buf_pos + len + 1 < buf_len) {
            memcpy(buf + buf_pos, pkt + pos, len);
            buf_pos += len;
            buf[buf_pos++] = '.';
        }
        pos += len;
    }
    return -1;
}

/* Skip a DNS name at cursor, return bytes consumed or -1 */
static int dns_name_skip(const uint8_t *pkt, int pkt_len, int pos)
{
    char tmp[256];
    return dns_name_expand(pkt, pkt_len, pos, tmp, sizeof(tmp));
}

/* Parse TXT record value pairs for Matter attributes */
static void parse_matter_txt(const uint8_t *rdata, int rdata_len,
                              device_info_t *dev)
{
    int i = 0;
    while (i < rdata_len) {
        uint8_t slen = rdata[i++];
        if (i + slen > rdata_len) break;

        char kv[128];
        int copy = slen < (int)sizeof(kv) - 1 ? slen : (int)sizeof(kv) - 1;
        memcpy(kv, rdata + i, copy);
        kv[copy] = '\0';
        i += slen;

        char *eq = strchr(kv, '=');
        if (!eq) continue;
        *eq = '\0';
        char *val = eq + 1;

        if (strcmp(kv, "D") == 0) {
            dev->device_type = (uint16_t)strtoul(val, NULL, 10);
        } else if (strcmp(kv, "VP") == 0) {
            /* VP=<vid>+<pid> */
            char *plus = strchr(val, '+');
            if (plus) {
                *plus = '\0';
                dev->vendor_id  = (uint16_t)strtoul(val, NULL, 10);
                dev->product_id = (uint16_t)strtoul(plus + 1, NULL, 10);
            }
        } else if (strcmp(kv, "DN") == 0) {
            strncpy(dev->name, val, DEVICE_NAME_LEN - 1);
        }
    }
}

/* Parse a single resource record starting at *pos, advancing it.
 * Returns false on parse error. */
static bool parse_rr(const uint8_t *pkt, int pkt_len, int *pos,
                      device_info_t *dev_out)
{
    char name[256];
    int n = dns_name_expand(pkt, pkt_len, *pos, name, sizeof(name));
    if (n < 0) return false;
    *pos += n;

    if (*pos + 10 > pkt_len) return false;
    uint16_t rtype  = (uint16_t)(pkt[*pos] << 8 | pkt[*pos+1]);
    /* uint16_t rclass = pkt[*pos+2] << 8 | pkt[*pos+3]; */
    /* uint32_t ttl   = ... */
    uint16_t rdlen  = (uint16_t)(pkt[*pos+8] << 8 | pkt[*pos+9]);
    *pos += 10;

    if (*pos + rdlen > pkt_len) return false;
    const uint8_t *rdata = pkt + *pos;
    *pos += rdlen;

    switch (rtype) {
    case 1:  /* A record */
        if (rdlen == 4) {
            snprintf(dev_out->ip, DEVICE_IP_LEN, "%d.%d.%d.%d",
                     rdata[0], rdata[1], rdata[2], rdata[3]);
        }
        break;
    case 28: /* AAAA record */
        if (rdlen == 16) {
            snprintf(dev_out->ip, DEVICE_IP_LEN,
                     "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                     "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                     rdata[0],rdata[1],rdata[2],rdata[3],
                     rdata[4],rdata[5],rdata[6],rdata[7],
                     rdata[8],rdata[9],rdata[10],rdata[11],
                     rdata[12],rdata[13],rdata[14],rdata[15]);
        }
        break;
    case 16: /* TXT record */
        parse_matter_txt(rdata, rdlen, dev_out);
        break;
    case 33: /* SRV record */
        if (rdlen >= 7) {
            dev_out->port = (uint16_t)(rdata[4] << 8 | rdata[5]);
        }
        break;
    case 12: /* PTR record */
        /* The PTR name is the instance name — extract fabric/node IDs */
        {
            char ptr_name[256] = {0};
            dns_name_expand(pkt, pkt_len, (int)(rdata - pkt), ptr_name, sizeof(ptr_name));
            /* Instance name: <fabric_id>-<node_id>._matter._tcp.local */
            char *dash = strchr(ptr_name, '-');
            if (dash && (size_t)(dash - ptr_name) == 16) {
                strncpy(dev_out->fabric_id, ptr_name, 16);
                dev_out->fabric_id[16] = '\0';
                strncpy(dev_out->node_id, dash + 1, 16);
                dev_out->node_id[16] = '\0';
                if (dev_out->name[0] == '\0') {
                    strncpy(dev_out->name, ptr_name, DEVICE_NAME_LEN - 1);
                }
            }
        }
        break;
    default:
        break;
    }

    return true;
}

static bool is_matter_packet(const uint8_t *pkt, int pkt_len)
{
    if (pkt_len < 12) return false;
    /* Check answers or additional records reference Matter services */
    int pos = 12;
    uint16_t qdcount = (uint16_t)(pkt[4] << 8 | pkt[5]);
    uint16_t ancount = (uint16_t)(pkt[6] << 8 | pkt[7]);
    uint16_t nscount = (uint16_t)(pkt[8] << 8 | pkt[9]);
    uint16_t arcount = (uint16_t)(pkt[10] << 8 | pkt[11]);
    int total_rr = ancount + nscount + arcount;

    /* Skip questions */
    for (int q = 0; q < qdcount && pos < pkt_len; q++) {
        int n = dns_name_skip(pkt, pkt_len, pos);
        if (n < 0) return false;
        pos += n + 4;
    }

    /* Check first few RRs for Matter service name */
    char name[256];
    for (int r = 0; r < total_rr && r < 8 && pos < pkt_len; r++) {
        int n = dns_name_expand(pkt, pkt_len, pos, name, sizeof(name));
        if (n < 0) return false;
        if (strstr(name, "_matter._tcp") || strstr(name, "_matterc._udp") ||
            strstr(name, "_meshcop._udp")) {
            return true;
        }
        pos += n;
        if (pos + 10 > pkt_len) return false;
        uint16_t rdlen = (uint16_t)(pkt[pos+8] << 8 | pkt[pos+9]);
        pos += 10 + rdlen;
    }
    return false;
}

static void parse_mdns_packet(const uint8_t *pkt, int pkt_len)
{
    if (pkt_len < 12) return;

    /* Only process responses (QR bit set) */
    uint16_t flags = (uint16_t)(pkt[2] << 8 | pkt[3]);
    if (!(flags & 0x8000)) {
        /* It's a query — still check if it contains Matter service types */
    }

    uint16_t qdcount = (uint16_t)(pkt[4] << 8 | pkt[5]);
    uint16_t ancount = (uint16_t)(pkt[6] << 8 | pkt[7]);
    uint16_t nscount = (uint16_t)(pkt[8] << 8 | pkt[9]);
    uint16_t arcount = (uint16_t)(pkt[10] << 8 | pkt[11]);

    int pos = 12;

    /* Skip questions */
    for (int q = 0; q < qdcount && pos < pkt_len; q++) {
        int n = dns_name_skip(pkt, pkt_len, pos);
        if (n < 0) return;
        pos += n + 4;  /* skip QTYPE + QCLASS */
    }

    device_info_t dev = {0};
    int rr_total = ancount + nscount + arcount;

    for (int r = 0; r < rr_total && pos < pkt_len; r++) {
        if (!parse_rr(pkt, pkt_len, &pos, &dev)) break;
    }

    /* Only register if we got enough identifying info */
    if (dev.name[0] || (dev.fabric_id[0] && dev.node_id[0]) || dev.ip[0]) {
        if (dev.name[0] == '\0') {
            if (dev.fabric_id[0] && dev.node_id[0]) {
                snprintf(dev.name, DEVICE_NAME_LEN, "%s-%s", dev.fabric_id, dev.node_id);
            } else if (dev.ip[0]) {
                snprintf(dev.name, DEVICE_NAME_LEN, "matter@%s", dev.ip);
            }
        }
        const device_info_t *stored = device_registry_update(&dev);
        if (stored) {
            ESP_LOGI(TAG, "device: %s  IP: %s  VID:0x%04X PID:0x%04X Type:0x%04X",
                     stored->name, stored->ip,
                     stored->vendor_id, stored->product_id, stored->device_type);
        }
    }
}

/* Build a minimal mDNS query for a given service type */
static int build_mdns_query(uint8_t *buf, int buf_size, const char *service)
{
    /* Transaction ID, flags (query), 1 question, 0 answers */
    uint8_t hdr[] = {0x00,0x00, 0x00,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00};
    if (buf_size < 12) return -1;
    memcpy(buf, hdr, 12);
    int pos = 12;

    /* Encode service name labels */
    char tmp[256];
    strncpy(tmp, service, sizeof(tmp) - 1);
    char *p = tmp;
    while (*p) {
        char *dot = strchr(p, '.');
        int label_len = dot ? (int)(dot - p) : (int)strlen(p);
        if (pos + 1 + label_len + 5 > buf_size) return -1;
        buf[pos++] = (uint8_t)label_len;
        memcpy(buf + pos, p, label_len);
        pos += label_len;
        if (!dot) break;
        p = dot + 1;
    }
    buf[pos++] = 0x00;  /* end of name */

    /* QTYPE=PTR (12), QCLASS=IN (1) */
    buf[pos++] = 0x00; buf[pos++] = 0x0C;
    buf[pos++] = 0x00; buf[pos++] = 0x01;
    return pos;
}

static void mdns_listen_task(void *arg)
{
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        ESP_LOGE(TAG, "socket failed");
        vTaskDelete(NULL);
        return;
    }

    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in local = {
        .sin_family      = AF_INET,
        .sin_port        = htons(MDNS_PORT),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    if (bind(sock, (struct sockaddr *)&local, sizeof(local)) < 0) {
        ESP_LOGE(TAG, "bind failed");
        close(sock);
        vTaskDelete(NULL);
        return;
    }

    /* Join mDNS multicast group */
    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(MDNS_GROUP);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        ESP_LOGW(TAG, "multicast join failed — mDNS passive listening may be limited");
    }

    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    ESP_LOGI(TAG, "listening on mDNS port 5353");

    uint8_t *buf = malloc(RECV_BUF_SIZE);
    if (!buf) {
        ESP_LOGE(TAG, "out of memory");
        close(sock);
        vTaskDelete(NULL);
        return;
    }

    /* Active query socket (sent to 224.0.0.251:5353) */
    struct sockaddr_in mdns_dst = {
        .sin_family      = AF_INET,
        .sin_port        = htons(MDNS_PORT),
        .sin_addr.s_addr = inet_addr(MDNS_GROUP),
    };

    TickType_t last_query = xTaskGetTickCount();

    while (1) {
        /* Send periodic active queries */
        if ((xTaskGetTickCount() - last_query) > pdMS_TO_TICKS(60000)) {
            uint8_t qbuf[128];
            const char *services[] = {
                "_matter._tcp.local",
                "_matterc._udp.local",
                "_meshcop._udp.local",
            };
            for (int s = 0; s < 3; s++) {
                int qlen = build_mdns_query(qbuf, sizeof(qbuf), services[s]);
                if (qlen > 0) {
                    sendto(sock, qbuf, qlen, 0,
                           (struct sockaddr *)&mdns_dst, sizeof(mdns_dst));
                }
                vTaskDelay(pdMS_TO_TICKS(100));
            }
            ESP_LOGD(TAG, "sent mDNS queries");
            last_query = xTaskGetTickCount();
        }

        struct sockaddr_in sender;
        socklen_t sender_len = sizeof(sender);
        int len = recvfrom(sock, buf, RECV_BUF_SIZE, 0,
                           (struct sockaddr *)&sender, &sender_len);
        if (len <= 0) continue;

        /* Forward to pcap output */
        pcap_streamer_write_ip_frame(buf, len);

        /* Check if this looks like a Matter mDNS packet before expensive parsing */
        if (is_matter_packet(buf, len)) {
            parse_mdns_packet(buf, len);
        }
    }
}

void mdns_scanner_init(void)
{
    xTaskCreate(mdns_listen_task, "mdns_listen", 8192, NULL, 4, NULL);
    ESP_LOGI(TAG, "mDNS scanner started");
}

idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES
        wifi_manager
        packet_sniffer
        mdns_scanner
        device_registry
        pcap_streamer
        mqtt_ha
        http_server
        nvs_flash
        esp_event
        esp_netif
)

idf_component_register(
    SRCS "packet_sniffer.c"
    INCLUDE_DIRS "."
    REQUIRES esp_wifi log freertos pcap_streamer device_registry
)

idf_component_register(
    SRCS "mdns_scanner.c"
    INCLUDE_DIRS "."
    REQUIRES log freertos lwip device_registry pcap_streamer
)

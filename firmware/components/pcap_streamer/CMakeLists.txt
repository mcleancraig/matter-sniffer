idf_component_register(
    SRCS "pcap_streamer.c"
    INCLUDE_DIRS "."
    REQUIRES log freertos esp_timer
)

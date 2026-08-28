idf_component_register(
    SRCS "http_server.c"
    INCLUDE_DIRS "."
    REQUIRES
        esp_http_server
        log
        freertos
        device_registry
        packet_sniffer
        wifi_manager
        esp_timer
        nvs_flash
        esp_system
    EMBED_FILES
        www/index.html
)

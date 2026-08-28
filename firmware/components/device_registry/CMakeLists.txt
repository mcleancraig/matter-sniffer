idf_component_register(
    SRCS "device_registry.c"
    INCLUDE_DIRS "."
    REQUIRES log freertos nvs_flash esp_timer
)

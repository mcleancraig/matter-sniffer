idf_component_register(
    SRCS "mqtt_ha.c"
    INCLUDE_DIRS "."
    REQUIRES espressif__mqtt log freertos nvs_flash device_registry
)

idf_component_register(
    SRCS "st_server.c"
    INCLUDE_DIRS "."
    REQUIRES wifi esp_https_server mdns nvs_flash certificates
)

target_add_binary_data(${COMPONENT_LIB} "index.html" TEXT)

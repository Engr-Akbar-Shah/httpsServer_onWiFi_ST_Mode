# Define source files
set(SOURCES "wifi.c")

# Define include directories
set(INCLUDE_DIRS ".")

# Define required components
set(REQUIRES_COMPONENTS
    esp_wifi
    esp_netif
    nvs_flash
)

# Register the component
idf_component_register(
    SRCS ${SOURCES}
    INCLUDE_DIRS ${INCLUDE_DIRS}
    REQUIRES ${REQUIRES_COMPONENTS}
)

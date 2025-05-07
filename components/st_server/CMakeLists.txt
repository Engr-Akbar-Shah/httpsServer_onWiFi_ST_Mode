# Define source files
set(SOURCES "st_server.c")

# Define include directories
set(INCLUDE_DIRS ".")

# Define required components
set(REQUIRES_COMPONENTS
    wifi
    esp_https_server
    mdns
    nvs_flash
    certificates
)

# Define binary data to embed
set(BINARY_DATA
    "index.html"
)

# Register the component with the specified sources, includes, and requirements
idf_component_register(
    SRCS ${SOURCES}
    INCLUDE_DIRS ${INCLUDE_DIRS}
    REQUIRES ${REQUIRES_COMPONENTS}
)

# Embed binary data into the component
foreach(file ${BINARY_DATA})
    target_add_binary_data(${COMPONENT_LIB} "${file}" TEXT)
endforeach()

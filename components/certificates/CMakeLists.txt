# Define source files
set(SOURCES
    "certificates.c"
)

# Define required components
set(REQUIRES_LIST
    nvs_flash
)

# Define include directories
set(INCLUDE_DIRS
    "."
)

# Register the component
idf_component_register(
    SRCS ${SOURCES}
    INCLUDE_DIRS ${INCLUDE_DIRS}
    REQUIRES ${REQUIRES_LIST}
)

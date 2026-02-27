cmake_minimum_required(VERSION 3.14)
project(hdds_c_sdk LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# --- Find the hdds-c shared library ---
# HDDS_C_LIB_DIR can be set to point at the directory containing libhdds_c.so
# Defaults to the Cargo release output directory.
if(NOT HDDS_C_LIB_DIR)
    set(HDDS_C_LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../target/release")
endif()

find_library(HDDS_C_LIB
    NAMES hdds_c
    HINTS ${HDDS_C_LIB_DIR}
)

if(NOT HDDS_C_LIB)
    message(WARNING "libhdds_c not found in ${HDDS_C_LIB_DIR}. "
                    "Build with: cargo build -p hdds-c --release")
endif()

# Header search path
set(HDDS_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")

# Convenience interface library so sub-directories can just link hdds::c
add_library(hdds_c_iface INTERFACE)
target_include_directories(hdds_c_iface INTERFACE ${HDDS_INCLUDE_DIR})
if(HDDS_C_LIB)
    target_link_libraries(hdds_c_iface INTERFACE ${HDDS_C_LIB})
endif()
add_library(hdds::c ALIAS hdds_c_iface)

# --- Sub-directories ---
add_subdirectory(examples)

enable_testing()
add_subdirectory(tests)

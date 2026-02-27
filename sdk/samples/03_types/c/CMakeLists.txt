# HDDS Samples - 03_types (C)

cmake_minimum_required(VERSION 3.16)
project(hdds_samples_types_c C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Find HDDS C library
set(HDDS_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../.." CACHE PATH "Path to HDDS root")
set(HDDS_C_INCLUDE "${HDDS_ROOT}/sdk/c/include" CACHE PATH "Path to hdds.h")
set(HDDS_C_LIB "${HDDS_ROOT}/target/release" CACHE PATH "Path to libhdds_c")

# Samples
set(SAMPLES
    primitives
    strings
    sequences
    arrays
    maps
    enums
    unions
    nested_structs
    bitsets_bitmasks
    optional_fields
)

foreach(SAMPLE ${SAMPLES})
    add_executable(${SAMPLE} ${SAMPLE}.c)
    target_include_directories(${SAMPLE} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/generated
        ${HDDS_C_INCLUDE}
    )
    target_link_directories(${SAMPLE} PRIVATE ${HDDS_C_LIB})
    target_link_libraries(${SAMPLE} PRIVATE hdds_c pthread dl m)
endforeach()

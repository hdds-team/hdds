# HDDS Samples - 01_basics (C)

cmake_minimum_required(VERSION 3.16)
project(hdds_samples_basics_c C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Find HDDS C library
set(HDDS_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../.." CACHE PATH "Path to HDDS root")
set(HDDS_C_INCLUDE "${HDDS_ROOT}/sdk/c/include" CACHE PATH "Path to hdds.h")
set(HDDS_C_LIB "${HDDS_ROOT}/target/release" CACHE PATH "Path to libhdds_c")

# Samples
set(SAMPLES
    hello_world
    multi_participant
    multi_topic
    instance_keys
    transport_select
)

foreach(SAMPLE ${SAMPLES})
    add_executable(${SAMPLE} ${SAMPLE}.c)
    target_include_directories(${SAMPLE} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${HDDS_C_INCLUDE}
    )
    target_link_directories(${SAMPLE} PRIVATE ${HDDS_C_LIB})
    target_link_libraries(${SAMPLE} PRIVATE hdds_c pthread dl m)
endforeach()

# HDDS Samples - 02_qos (C)

cmake_minimum_required(VERSION 3.16)
project(hdds_samples_qos_c C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Find HDDS C library
set(HDDS_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../.." CACHE PATH "Path to HDDS root")
set(HDDS_C_INCLUDE "${HDDS_ROOT}/sdk/c/include" CACHE PATH "Path to hdds.h")
set(HDDS_C_LIB "${HDDS_ROOT}/target/release" CACHE PATH "Path to libhdds_c")

# Include generated types from 01_basics
set(GENERATED_INCLUDE "${CMAKE_CURRENT_SOURCE_DIR}/../../01_basics/c")

# Samples
set(SAMPLES
    reliable_delivery
    best_effort
    transient_local
    deadline_monitor
    liveliness_auto
    liveliness_manual
    partition_filter
    ownership_exclusive
    history_keep_last
    xml_loading
    lifespan
    latency_budget
    time_based_filter
    transport_priority
    resource_limits
)

foreach(SAMPLE ${SAMPLES})
    add_executable(${SAMPLE} ${SAMPLE}.c)
    target_include_directories(${SAMPLE} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${GENERATED_INCLUDE}
        ${HDDS_C_INCLUDE}
    )
    target_link_directories(${SAMPLE} PRIVATE ${HDDS_C_LIB})
    target_link_libraries(${SAMPLE} PRIVATE hdds_c pthread dl m)
endforeach()

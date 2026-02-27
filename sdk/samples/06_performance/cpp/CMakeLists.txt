# HDDS Samples - 06_performance (C++)

cmake_minimum_required(VERSION 3.16)
if(POLICY CMP0144)
    cmake_policy(SET CMP0144 NEW)
endif()
project(hdds_samples_06_performance CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- Option A: find_package (recommended) ---
# cmake -DCMAKE_PREFIX_PATH=/path/to/hdds/sdk/cmake ..
find_package(hdds QUIET)

if(NOT hdds_FOUND)
    # --- Option B: manual paths (fallback) ---
    message(STATUS "hdds package not found, using manual paths")
    set(HDDS_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../.." CACHE PATH "Path to HDDS root")
    set(HDDS_C_INCLUDE "${HDDS_ROOT}/sdk/c/include" CACHE PATH "Path to hdds.h")
    set(HDDS_CXX_INCLUDE "${HDDS_ROOT}/sdk/cxx/include" CACHE PATH "Path to hdds.hpp")
    set(HDDS_LIB_DIR "${HDDS_ROOT}/target/release" CACHE PATH "Path to HDDS libraries")
    set(HDDS_CXX_LIB_DIR "${HDDS_ROOT}/sdk/cxx/build" CACHE PATH "Path to libhdds_cxx")
endif()

# Performance samples
set(SAMPLES
    latency
    throughput
    batching
    zero_copy
)

foreach(SAMPLE ${SAMPLES})
    add_executable(${SAMPLE} ${SAMPLE}.cpp)

    if(hdds_FOUND)
        target_include_directories(${SAMPLE} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
        target_link_libraries(${SAMPLE} PRIVATE hdds::hdds)
    else()
        target_include_directories(${SAMPLE} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}
            ${HDDS_CXX_INCLUDE}
            ${HDDS_C_INCLUDE}
        )
        target_link_directories(${SAMPLE} PRIVATE ${HDDS_CXX_LIB_DIR} ${HDDS_LIB_DIR})
        target_link_libraries(${SAMPLE} PRIVATE hdds_cxx hdds_c pthread dl m)
    endif()
endforeach()

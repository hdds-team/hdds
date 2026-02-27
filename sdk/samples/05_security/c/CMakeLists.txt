cmake_minimum_required(VERSION 3.14)
project(hdds_samples_05_security C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Find HDDS library
find_package(hdds QUIET)
if(NOT hdds_FOUND)
    # For development: use relative path
    set(HDDS_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../../include")
    set(HDDS_LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../../target/release")
endif()

# Find OpenSSL for crypto operations
find_package(OpenSSL QUIET)

# Security samples
set(SAMPLES
    authentication
    access_control
    encryption
    secure_discovery
)

foreach(sample ${SAMPLES})
    add_executable(${sample} ${sample}.c)
    target_include_directories(${sample} PRIVATE ${HDDS_INCLUDE_DIR})
    target_link_directories(${sample} PRIVATE ${HDDS_LIB_DIR})
    target_link_libraries(${sample} PRIVATE hdds pthread)
    if(OpenSSL_FOUND)
        target_link_libraries(${sample} PRIVATE OpenSSL::SSL OpenSSL::Crypto)
        target_compile_definitions(${sample} PRIVATE HAVE_OPENSSL)
    endif()
endforeach()

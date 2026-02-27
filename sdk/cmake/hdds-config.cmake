# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

# hdds-config.cmake
# CMake find_package() config for HDDS C/C++ SDKs
#
# Works in two modes (auto-detected):
#   Source tree: cmake -DCMAKE_PREFIX_PATH=/path/to/hdds/sdk/cmake ..
#   Installed:   cmake -DCMAKE_PREFIX_PATH=/usr/local ..
#
# Imported targets:
#   hdds::hdds_c    - C FFI library (libhdds_c)
#   hdds::hdds_cxx  - C++ RAII wrappers (libhdds_cxx)
#   hdds::hdds      - Convenience alias for hdds::hdds_cxx
#

cmake_minimum_required(VERSION 3.16)

if(POLICY CMP0144)
    cmake_policy(SET CMP0144 NEW)
endif()

if(TARGET hdds::hdds)
    return()
endif()

# --- Auto-detect source tree vs installed layout ---
#
# Source tree:  <ROOT>/sdk/cmake/hdds-config.cmake
#   headers at  <ROOT>/sdk/c/include, <ROOT>/sdk/cxx/include
#   libs at     <ROOT>/target/release, <ROOT>/sdk/cxx/build
#
# Installed:    <PREFIX>/lib/cmake/hdds/hdds-config.cmake
#   headers at  <PREFIX>/include
#   libs at     <PREFIX>/lib

get_filename_component(_HDDS_CMAKE_DIR "${CMAKE_CURRENT_LIST_FILE}" DIRECTORY)

if(EXISTS "${_HDDS_CMAKE_DIR}/../c/include/hdds.h")
    # --- Source tree mode ---
    get_filename_component(_HDDS_SDK_DIR "${_HDDS_CMAKE_DIR}/.." ABSOLUTE)
    get_filename_component(HDDS_ROOT "${_HDDS_SDK_DIR}/.." ABSOLUTE)

    set(_HDDS_C_INCLUDE "${_HDDS_SDK_DIR}/c/include")
    set(_HDDS_CXX_INCLUDE "${_HDDS_SDK_DIR}/cxx/include")
    set(_HDDS_C_LIB_DIR "${HDDS_ROOT}/target/release")
    set(_HDDS_CXX_LIB_DIR "${_HDDS_SDK_DIR}/cxx/build")
    set(_HDDS_MODE "source tree")
else()
    # --- Installed mode (PREFIX/lib/cmake/hdds/) ---
    get_filename_component(_HDDS_PREFIX "${_HDDS_CMAKE_DIR}/../../.." ABSOLUTE)
    set(HDDS_ROOT "${_HDDS_PREFIX}")

    set(_HDDS_C_INCLUDE "${_HDDS_PREFIX}/include")
    set(_HDDS_CXX_INCLUDE "${_HDDS_PREFIX}/include")
    set(_HDDS_C_LIB_DIR "${_HDDS_PREFIX}/lib")
    set(_HDDS_CXX_LIB_DIR "${_HDDS_PREFIX}/lib")
    set(_HDDS_MODE "installed")
endif()

# --- Validate paths ---

if(NOT EXISTS "${_HDDS_C_INCLUDE}/hdds.h")
    message(FATAL_ERROR
        "hdds: Cannot find hdds.h at ${_HDDS_C_INCLUDE}/hdds.h\n"
        "Build HDDS first: make sdk-cxx")
endif()

if(NOT EXISTS "${_HDDS_CXX_INCLUDE}/hdds.hpp")
    message(FATAL_ERROR
        "hdds: Cannot find hdds.hpp at ${_HDDS_CXX_INCLUDE}/hdds.hpp\n"
        "Build HDDS first: make sdk-cxx")
endif()

# --- Find libraries (static archives only -- no .so to avoid LD_LIBRARY_PATH issues) ---

set(HDDS_C_LIBRARY "${_HDDS_C_LIB_DIR}/libhdds_c.a")
set(HDDS_CXX_LIBRARY "${_HDDS_CXX_LIB_DIR}/libhdds_cxx.a")

if(NOT EXISTS "${HDDS_C_LIBRARY}")
    message(FATAL_ERROR
        "hdds: Cannot find ${HDDS_C_LIBRARY}\n\n"
        "Build HDDS first: make sdk-cxx")
endif()

if(NOT EXISTS "${HDDS_CXX_LIBRARY}")
    message(FATAL_ERROR
        "hdds: Cannot find ${HDDS_CXX_LIBRARY}\n\n"
        "Build HDDS first: make sdk-cxx")
endif()

# --- Platform link dependencies ---

set(_HDDS_PLATFORM_LIBS "")
if(UNIX AND NOT APPLE)
    set(_HDDS_PLATFORM_LIBS pthread dl m)
elseif(APPLE)
    set(_HDDS_PLATFORM_LIBS pthread dl)
elseif(WIN32)
    set(_HDDS_PLATFORM_LIBS ws2_32 userenv bcrypt ntdll)
endif()

# --- Imported target: hdds::hdds_c ---

add_library(hdds::hdds_c STATIC IMPORTED)
set_target_properties(hdds::hdds_c PROPERTIES
    IMPORTED_LOCATION "${HDDS_C_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${_HDDS_C_INCLUDE}"
    INTERFACE_LINK_LIBRARIES "${_HDDS_PLATFORM_LIBS}"
)

# --- Imported target: hdds::hdds_cxx ---

add_library(hdds::hdds_cxx STATIC IMPORTED)
set_target_properties(hdds::hdds_cxx PROPERTIES
    IMPORTED_LOCATION "${HDDS_CXX_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${_HDDS_CXX_INCLUDE};${_HDDS_C_INCLUDE}"
    INTERFACE_LINK_LIBRARIES "hdds::hdds_c"
)

# --- Convenience alias: hdds::hdds ---

add_library(hdds::hdds INTERFACE IMPORTED)
set_target_properties(hdds::hdds PROPERTIES
    INTERFACE_LINK_LIBRARIES "hdds::hdds_cxx"
)

# --- Status message ---

message(STATUS "Found HDDS: ${HDDS_ROOT} (${_HDDS_MODE})")
message(STATUS "  hdds::hdds_c   -> ${HDDS_C_LIBRARY}")
message(STATUS "  hdds::hdds_cxx -> ${HDDS_CXX_LIBRARY}")

# Cleanup internal variables
unset(_HDDS_CMAKE_DIR)
unset(_HDDS_SDK_DIR)
unset(_HDDS_C_INCLUDE)
unset(_HDDS_CXX_INCLUDE)
unset(_HDDS_C_LIB_DIR)
unset(_HDDS_CXX_LIB_DIR)
unset(_HDDS_PLATFORM_LIBS)
unset(_HDDS_MODE)

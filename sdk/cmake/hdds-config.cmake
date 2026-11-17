# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

# hdds-config.cmake
# CMake find_package() config for HDDS C/C++ SDKs
#
# Works in two modes (auto-detected):
#   Source tree: cmake -DCMAKE_PREFIX_PATH=/path/to/hdds/sdk/cmake ..
#   Installed:   cmake -DCMAKE_PREFIX_PATH=/usr/local ..
#
# Components:
#   c    - the C API only:  find_package(hdds REQUIRED COMPONENTS c)
#          needs hdds.h and libhdds_c.a (cargo build --release -p hdds-c,
#          or make install-c); the C++ SDK does not have to be built.
#   cxx  - the C++ SDK (implies c).
#   No COMPONENTS means both, as before: find_package(hdds REQUIRED)
#
# Where libhdds_c.a is searched (first hit wins):
#   1. -DHDDS_LIB_DIR=<dir>                  (explicit, both modes)
#   2. $ENV{CARGO_TARGET_DIR}/release        (source tree only)
#   3. <root>/target/release                 (source tree)
#      <prefix>/lib                          (installed)
#
# Imported targets:
#   hdds::hdds_c    - C FFI library (libhdds_c)
#   hdds::hdds_cxx  - C++ RAII wrappers (libhdds_cxx)      [component cxx]
#   hdds::hdds      - Convenience alias for hdds::hdds_cxx [component cxx]
#

cmake_minimum_required(VERSION 3.16)

if(POLICY CMP0144)
    cmake_policy(SET CMP0144 NEW)
endif()

# --- Requested components ---
set(_HDDS_WANT_CXX TRUE)
if(hdds_FIND_COMPONENTS)
    set(_HDDS_WANT_CXX FALSE)
    foreach(_hdds_comp IN LISTS hdds_FIND_COMPONENTS)
        if(_hdds_comp STREQUAL "cxx")
            set(_HDDS_WANT_CXX TRUE)
        elseif(NOT _hdds_comp STREQUAL "c")
            message(FATAL_ERROR "hdds: unknown component '${_hdds_comp}' (known: c, cxx)")
        endif()
    endforeach()
    unset(_hdds_comp)
endif()

if(TARGET hdds::hdds_c AND (TARGET hdds::hdds_cxx OR NOT _HDDS_WANT_CXX))
    unset(_HDDS_WANT_CXX)
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
    set(_HDDS_CXX_LIB_DIR "${_HDDS_SDK_DIR}/cxx/build")
    set(_HDDS_MODE "source tree")
else()
    # --- Installed mode (PREFIX/lib/cmake/hdds/) ---
    get_filename_component(_HDDS_PREFIX "${_HDDS_CMAKE_DIR}/../../.." ABSOLUTE)
    set(HDDS_ROOT "${_HDDS_PREFIX}")

    set(_HDDS_C_INCLUDE "${_HDDS_PREFIX}/include")
    set(_HDDS_CXX_INCLUDE "${_HDDS_PREFIX}/include")
    set(_HDDS_CXX_LIB_DIR "${_HDDS_PREFIX}/lib")
    set(_HDDS_MODE "installed")
endif()

# --- Validate paths ---

if(NOT EXISTS "${_HDDS_C_INCLUDE}/hdds.h")
    message(FATAL_ERROR
        "hdds: Cannot find hdds.h at ${_HDDS_C_INCLUDE}/hdds.h\n"
        "Build HDDS first: make sdk-cxx")
endif()

if(_HDDS_WANT_CXX AND NOT EXISTS "${_HDDS_CXX_INCLUDE}/hdds.hpp")
    message(FATAL_ERROR
        "hdds: Cannot find hdds.hpp at ${_HDDS_CXX_INCLUDE}/hdds.hpp\n"
        "Build HDDS first: make sdk-cxx (or ask for the C API only: COMPONENTS c)")
endif()

# --- Find libraries (static archives only -- no .so to avoid LD_LIBRARY_PATH issues) ---

# Probe one candidate directory for libhdds_c.a. The first hit goes to
# HDDS_C_LIBRARY; every probed location is appended to _HDDS_C_LIB_TRIED
# (both returned to the caller's scope).
function(_hdds_probe_lib_dir why dir)
    if("${dir}" STREQUAL "")
        return()
    endif()
    get_filename_component(_hdds_probe "${dir}" ABSOLUTE BASE_DIR "${HDDS_ROOT}")
    set(_HDDS_C_LIB_TRIED "${_HDDS_C_LIB_TRIED}\n  ${why}: ${_hdds_probe}" PARENT_SCOPE)
    if(NOT HDDS_C_LIBRARY AND EXISTS "${_hdds_probe}/libhdds_c.a")
        set(HDDS_C_LIBRARY "${_hdds_probe}/libhdds_c.a" PARENT_SCOPE)
    endif()
endfunction()

set(HDDS_C_LIBRARY "")
set(_HDDS_C_LIB_TRIED "")

_hdds_probe_lib_dir("HDDS_LIB_DIR" "${HDDS_LIB_DIR}")
if(_HDDS_MODE STREQUAL "source tree")
    if(NOT "$ENV{CARGO_TARGET_DIR}" STREQUAL "")
        _hdds_probe_lib_dir("CARGO_TARGET_DIR/release" "$ENV{CARGO_TARGET_DIR}/release")
    endif()
    _hdds_probe_lib_dir("<root>/target/release" "${HDDS_ROOT}/target/release")
else()
    _hdds_probe_lib_dir("<prefix>/lib" "${_HDDS_PREFIX}/lib")
endif()

if(NOT HDDS_C_LIBRARY)
    message(FATAL_ERROR
        "hdds: Cannot find libhdds_c.a. Searched:${_HDDS_C_LIB_TRIED}\n"
        "Build it: cargo build --release -p hdds-c (or make sdk-c), "
        "which honours CARGO_TARGET_DIR.\n"
        "Or name the directory holding libhdds_c.a: "
        "cmake -DHDDS_LIB_DIR=/path/to/dir ...")
endif()

set(HDDS_CXX_LIBRARY "${_HDDS_CXX_LIB_DIR}/libhdds_cxx.a")

if(_HDDS_WANT_CXX AND NOT EXISTS "${HDDS_CXX_LIBRARY}")
    message(FATAL_ERROR
        "hdds: Cannot find ${HDDS_CXX_LIBRARY}\n\n"
        "Build HDDS first: make sdk-cxx (or ask for the C API only: COMPONENTS c)")
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

if(NOT TARGET hdds::hdds_c)
    add_library(hdds::hdds_c STATIC IMPORTED)
    set_target_properties(hdds::hdds_c PROPERTIES
        IMPORTED_LOCATION "${HDDS_C_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${_HDDS_C_INCLUDE}"
        INTERFACE_LINK_LIBRARIES "${_HDDS_PLATFORM_LIBS}"
    )
endif()

if(_HDDS_WANT_CXX)
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
endif()

set(hdds_c_FOUND TRUE)
set(hdds_cxx_FOUND ${_HDDS_WANT_CXX})

# --- Status message ---

message(STATUS "Found HDDS: ${HDDS_ROOT} (${_HDDS_MODE})")
message(STATUS "  hdds::hdds_c   -> ${HDDS_C_LIBRARY}")
if(_HDDS_WANT_CXX)
    message(STATUS "  hdds::hdds_cxx -> ${HDDS_CXX_LIBRARY}")
endif()

# Cleanup internal variables
unset(_HDDS_CMAKE_DIR)
unset(_HDDS_SDK_DIR)
unset(_HDDS_C_INCLUDE)
unset(_HDDS_CXX_INCLUDE)
unset(_HDDS_CXX_LIB_DIR)
unset(_HDDS_C_LIB_TRIED)
unset(_HDDS_PLATFORM_LIBS)
unset(_HDDS_MODE)
unset(_HDDS_WANT_CXX)

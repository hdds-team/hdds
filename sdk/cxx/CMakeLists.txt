cmake_minimum_required(VERSION 3.16)
project(hdds_cxx VERSION 0.8.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

option(BUILD_SHARED_LIBS "Build static or shared library" OFF)
option(BUILD_EXAMPLES "Build examples" OFF)
option(BUILD_TESTS "Build tests" OFF)

# Find thread library
find_package(Threads REQUIRED)

# Library
set(HDDS_CXX_HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/include/hdds_listener.hpp
                     ${CMAKE_CURRENT_SOURCE_DIR}/include/hdds.hpp
)
set(HDDS_CXX_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/logging.cpp    
                     ${CMAKE_CURRENT_SOURCE_DIR}/src/participant.cpp
                     ${CMAKE_CURRENT_SOURCE_DIR}/src/pubsub.cpp
                     ${CMAKE_CURRENT_SOURCE_DIR}/src/qos.cpp
                     ${CMAKE_CURRENT_SOURCE_DIR}/src/reader.cpp
                     ${CMAKE_CURRENT_SOURCE_DIR}/src/telemetry.cpp
                     ${CMAKE_CURRENT_SOURCE_DIR}/src/waitset.cpp
                     ${CMAKE_CURRENT_SOURCE_DIR}/src/writer.cpp
)

add_library(hdds_cxx ${HDDS_CXX_HEADERS} ${HDDS_CXX_SOURCES})
add_library(hdds::hdds_cxx ALIAS hdds_cxx)

target_include_directories(hdds_cxx
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(hdds_cxx PUBLIC hdds::hdds_c PRIVATE Threads::Threads ${CMAKE_DL_LIBS})

# Examples
if(BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# Tests
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

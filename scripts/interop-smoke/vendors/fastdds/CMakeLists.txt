cmake_minimum_required(VERSION 3.20)
project(fastdds_interop_app CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

find_package(fastcdr REQUIRED)
find_package(fastdds REQUIRED)

# GENERATED_DIR is passed in by the Dockerfile; it holds the fastddsgen
# output produced from InteropPing.idl at build time.
if(NOT DEFINED GENERATED_DIR)
    set(GENERATED_DIR "${CMAKE_CURRENT_SOURCE_DIR}/generated")
endif()

add_executable(fastdds_app
    src/fastdds_app.cpp
    "${GENERATED_DIR}/InteropPingPubSubTypes.cxx"
    "${GENERATED_DIR}/InteropPingTypeObjectSupport.cxx"
)

target_include_directories(fastdds_app PRIVATE "${GENERATED_DIR}")
target_link_libraries(fastdds_app fastcdr fastdds)

install(TARGETS fastdds_app RUNTIME DESTINATION bin)

cmake_minimum_required(VERSION 3.16)
project(hdds_cxx VERSION 0.8.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find hdds-c library
set(HDDS_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." CACHE PATH "Path to HDDS root")
set(HDDS_C_INCLUDE "${CMAKE_CURRENT_SOURCE_DIR}/../c/include" CACHE PATH "Path to hdds-c headers")
set(HDDS_C_LIB "${HDDS_ROOT}/target/release" CACHE PATH "Path to hdds-c library")

# Library
add_library(hdds_cxx STATIC
    src/participant.cpp
    src/writer.cpp
    src/reader.cpp
    src/qos.cpp
    src/waitset.cpp
    src/logging.cpp
    src/telemetry.cpp
    src/pubsub.cpp
)

target_include_directories(hdds_cxx
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${HDDS_C_INCLUDE}
)

target_link_directories(hdds_cxx PRIVATE ${HDDS_C_LIB})
target_link_libraries(hdds_cxx PRIVATE hdds_c pthread dl m)

# Install
install(TARGETS hdds_cxx
    EXPORT hdds_cxx-targets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(DIRECTORY include/ DESTINATION include)

install(EXPORT hdds_cxx-targets
    FILE hdds_cxxTargets.cmake
    NAMESPACE hdds::
    DESTINATION lib/cmake/hdds_cxx
)

# Examples
option(BUILD_EXAMPLES "Build examples" ON)
if(BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# Tests
option(BUILD_TESTS "Build tests" ON)
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

cmake_minimum_required(VERSION 3.5)
project(rmw_hdds VERSION 0.8.0 LANGUAGES C CXX)

# Compiler settings
if(NOT CMAKE_C_STANDARD)
  set(CMAKE_C_STANDARD 11)
endif()

if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Find ROS 2 dependencies
find_package(ament_cmake REQUIRED)
find_package(rmw REQUIRED)
find_package(rcutils REQUIRED)
find_package(rosidl_runtime_c REQUIRED)
find_package(rosidl_typesupport_interface REQUIRED)
find_package(rosidl_typesupport_introspection_c REQUIRED)
find_package(rcl_interfaces REQUIRED)
find_package(rosgraph_msgs QUIET)
find_package(rmw_implementation_cmake REQUIRED)

# ==============================================================================
# Configuration Options
# ==============================================================================

# Build options
option(RMW_HDDS_ENABLE_LINT "Run ament lint checks for rmw_hdds" OFF)
option(RMW_HDDS_WITH_SECURITY "Build with DDS Security support (requires OpenSSL)" OFF)
option(RMW_HDDS_WITH_SHM "Build with shared memory transport (Linux only)" ON)
option(RMW_HDDS_WITH_LOGGING "Build with extended logging support" OFF)
option(RMW_HDDS_WITH_TRACING "Build with tracing/telemetry support" OFF)

# Runtime configuration defaults (can be overridden by environment variables)
set(RMW_HDDS_DEFAULT_DOMAIN_ID "0" CACHE STRING "Default DDS domain ID (0-232)")
set(RMW_HDDS_DEFAULT_LOG_LEVEL "info" CACHE STRING "Default log level (trace/debug/info/warn/error)")

# Pass options to Cargo build
set(HDDS_CARGO_FEATURES "")
if(RMW_HDDS_WITH_SECURITY)
  list(APPEND HDDS_CARGO_FEATURES "--features" "security")
  message(STATUS "rmw_hdds: DDS Security enabled")
endif()
if(RMW_HDDS_WITH_LOGGING)
  list(APPEND HDDS_CARGO_FEATURES "--features" "logging")
  message(STATUS "rmw_hdds: Extended logging enabled")
endif()
if(RMW_HDDS_WITH_TRACING)
  list(APPEND HDDS_CARGO_FEATURES "--features" "telemetry")
  message(STATUS "rmw_hdds: Tracing/telemetry enabled")
endif()
if(RMW_HDDS_WITH_SHM AND UNIX AND NOT APPLE)
  list(APPEND HDDS_CARGO_FEATURES "--features" "shm")
  message(STATUS "rmw_hdds: Shared memory transport enabled")
endif()

message(STATUS "rmw_hdds: Default domain ID = ${RMW_HDDS_DEFAULT_DOMAIN_ID}")
message(STATUS "rmw_hdds: Default log level = ${RMW_HDDS_DEFAULT_LOG_LEVEL}")

# Library: rmw_hdds implementation
add_library(${PROJECT_NAME} SHARED
  src/rmw_init.c
  src/rmw_node.c
  src/rmw_publisher.c
  src/rmw_subscription.c
  src/rmw_wait.c
  src/rmw_guard_condition.c
  src/rmw_qos.c
  src/rmw_stubs.c
  src/codec_parameter_event.cpp
  src/cpp/bridge.cpp
)

target_include_directories(${PROJECT_NAME}
  PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/include/hdds_cpp
  SYSTEM PRIVATE
    ${PROJECT_SOURCE_DIR}/../crates/hdds-c
)

target_compile_definitions(${PROJECT_NAME} PRIVATE HDDS_WITH_ROS2)

# Link ROS 2 dependencies
ament_target_dependencies(${PROJECT_NAME}
  rmw
  rcutils
  rosidl_runtime_c
  rosidl_typesupport_interface
  rosidl_typesupport_introspection_c
  rcl_interfaces
)

# Temporarily disable fast rosout codec to avoid header dependency issues.
# The fast codec will be re-enabled once rosgraph_msgs is guaranteed available.
message(STATUS "Building without fast rosout codec (temporarily disabled)")

# Build and link the HDDS C shim produced by Cargo
if(DEFINED ENV{HDDS_PROJECT_ROOT})
  set(HDDS_PROJECT_ROOT $ENV{HDDS_PROJECT_ROOT})
else()
  set(HDDS_PROJECT_ROOT ${PROJECT_SOURCE_DIR}/..)
endif()
get_filename_component(HDDS_PROJECT_ROOT "${HDDS_PROJECT_ROOT}" REALPATH)

set(HDDS_RUST_PROFILE release)
set(HDDS_CARGO_FLAGS --release)
if(CMAKE_BUILD_TYPE AND CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(HDDS_RUST_PROFILE debug)
  set(HDDS_CARGO_FLAGS "")
endif()

set(HDDS_CARGO_TARGET_DIR ${HDDS_PROJECT_ROOT}/target/${HDDS_RUST_PROFILE})
set(HDDS_RUST_LIB ${HDDS_CARGO_TARGET_DIR}/librmw_hdds.a)
set(HDDS_C_LIB ${HDDS_CARGO_TARGET_DIR}/libhdds_c.a)

add_custom_command(
  OUTPUT ${HDDS_RUST_LIB}
  BYPRODUCTS ${HDDS_C_LIB}
  COMMAND cargo build --manifest-path ${HDDS_PROJECT_ROOT}/Cargo.toml -p rmw-hdds ${HDDS_CARGO_FLAGS} ${HDDS_CARGO_FEATURES}
  WORKING_DIRECTORY ${HDDS_PROJECT_ROOT}
  COMMENT "Building rmw-hdds (${HDDS_RUST_PROFILE}) via Cargo"
  VERBATIM
)

add_custom_target(rmw_hdds_rust_build ALL DEPENDS ${HDDS_RUST_LIB})

add_library(rmw_hdds_rust STATIC IMPORTED GLOBAL)
set_target_properties(rmw_hdds_rust PROPERTIES IMPORTED_LOCATION ${HDDS_RUST_LIB})
add_dependencies(rmw_hdds_rust rmw_hdds_rust_build)

add_library(hdds_c STATIC IMPORTED GLOBAL)
set_target_properties(hdds_c PROPERTIES IMPORTED_LOCATION ${HDDS_C_LIB})
add_dependencies(hdds_c rmw_hdds_rust_build)

target_link_libraries(${PROJECT_NAME}
  "$<LINK_LIBRARY:WHOLE_ARCHIVE,rmw_hdds_rust>"
  hdds_c
  rcl_interfaces::rcl_interfaces__rosidl_generator_c
  rosidl_runtime_c::rosidl_runtime_c
)

if(UNIX)
  target_link_libraries(${PROJECT_NAME} gcc_s util rt pthread m dl)
endif()
add_dependencies(${PROJECT_NAME} rmw_hdds_rust_build)

# Install library
install(TARGETS ${PROJECT_NAME}
  ARCHIVE DESTINATION lib
  LIBRARY DESTINATION lib
  RUNTIME DESTINATION bin
)

# Install headers
install(DIRECTORY include/
  DESTINATION include
)

# Export package
ament_export_include_directories(include)
ament_export_libraries(${PROJECT_NAME})
ament_export_dependencies(
  rmw
  rcutils
  rosidl_runtime_c
)

# Linting
if(BUILD_TESTING AND RMW_HDDS_ENABLE_LINT)
  find_package(ament_lint_auto REQUIRED)
  ament_lint_auto_find_test_dependencies()
endif()

# Register as RMW implementation
register_rmw_implementation(
  "c:rosidl_typesupport_c:rosidl_typesupport_introspection_c"
  "cpp:rosidl_typesupport_cpp:rosidl_typesupport_introspection_cpp"
)

ament_package()

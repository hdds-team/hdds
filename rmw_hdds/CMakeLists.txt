cmake_minimum_required(VERSION 3.16)
project(rmw_hdds VERSION 1.5.0 LANGUAGES C CXX)

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

# Pass options to Cargo build.
#
# The old list named the features bare - "security", "logging", "telemetry",
# "shm" - and rmw-hdds declares none of them, so `cargo build -p rmw-hdds
# --features shm` failed outright and took the whole CMake build with it. Three
# of the four exist, on the crates rmw-hdds depends on, and are named as such
# here. "shm" is the one with nothing behind it: the shared-memory shim is
# unconditional on Linux and cfg-gated off elsewhere
# (crates/hdds-c/src/rmw.rs), so RMW_HDDS_WITH_SHM is informational.
set(HDDS_CARGO_FEATURES "")
if(RMW_HDDS_WITH_SECURITY)
  list(APPEND HDDS_CARGO_FEATURES "--features" "hdds-c/security")
  message(STATUS "rmw_hdds: DDS Security enabled")
endif()
if(RMW_HDDS_WITH_LOGGING)
  # crates/hdds/Cargo.toml:17. `hdds/trace` sits on top of it for the
  # per-function trace points.
  list(APPEND HDDS_CARGO_FEATURES "--features" "hdds/logging")
  message(STATUS "rmw_hdds: extended logging enabled (hdds/logging)")
endif()
if(RMW_HDDS_WITH_TRACING)
  # crates/hdds/Cargo.toml:15.
  list(APPEND HDDS_CARGO_FEATURES "--features" "hdds/telemetry")
  message(STATUS "rmw_hdds: telemetry enabled (hdds/telemetry)")
endif()
if(RMW_HDDS_WITH_SHM AND UNIX AND NOT APPLE)
  message(STATUS "rmw_hdds: shared memory shim built in (Linux)")
endif()

# Reproducible, network-free Cargo runs for the gate: the tree may be mounted
# read only, so the lockfile must not be refreshed, and every crate must
# already be in CARGO_HOME (the gate runs `cargo fetch` at image-prep time).
option(RMW_HDDS_CARGO_LOCKED "Pass --locked to cargo" ON)
option(RMW_HDDS_CARGO_OFFLINE "Pass --offline to cargo" OFF)
set(HDDS_CARGO_NET_FLAGS "")
if(RMW_HDDS_CARGO_LOCKED)
  list(APPEND HDDS_CARGO_NET_FLAGS --locked)
endif()
if(RMW_HDDS_CARGO_OFFLINE)
  list(APPEND HDDS_CARGO_NET_FLAGS --offline)
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

# Fast rosout codec. It decodes rcl_interfaces::msg::Log, which is a REQUIRED
# dependency of this package, so it always builds. It used to be excluded with
# the comment "temporarily disabled ... header dependency issues": the real
# reason was that codec_log.cpp included <rosgraph_msgs/msg/log.hpp>, and
# rosgraph_msgs carries Clock, not Log. rmw_subscription.c still guards its
# call site with HDDS_HAVE_ROSLOG_FAST.
target_sources(${PROJECT_NAME} PRIVATE src/codec_log.cpp)
target_compile_definitions(${PROJECT_NAME} PRIVATE HDDS_HAVE_ROSLOG_FAST)
message(STATUS "rmw_hdds: fast rosout codec enabled (rcl_interfaces::msg::Log)")

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

# Where Cargo puts its artefacts. ${HDDS_PROJECT_ROOT}/target is unwritable
# whenever the tree is bind-mounted read only (which is exactly how the gate
# runs), so honour -DHDDS_CARGO_TARGET_ROOT first, then the CARGO_TARGET_DIR
# environment variable Cargo itself reads, and only then fall back to the tree.
if(NOT HDDS_CARGO_TARGET_ROOT)
  if(DEFINED ENV{CARGO_TARGET_DIR})
    set(HDDS_CARGO_TARGET_ROOT $ENV{CARGO_TARGET_DIR})
  else()
    set(HDDS_CARGO_TARGET_ROOT ${HDDS_PROJECT_ROOT}/target)
  endif()
endif()
message(STATUS "rmw_hdds: cargo target root = ${HDDS_CARGO_TARGET_ROOT}")

set(HDDS_CARGO_TARGET_DIR ${HDDS_CARGO_TARGET_ROOT}/${HDDS_RUST_PROFILE})
set(HDDS_RUST_LIB ${HDDS_CARGO_TARGET_DIR}/librmw_hdds.a)
set(HDDS_C_LIB ${HDDS_CARGO_TARGET_DIR}/libhdds_c.a)

add_custom_command(
  OUTPUT ${HDDS_RUST_LIB}
  BYPRODUCTS ${HDDS_C_LIB}
  COMMAND ${CMAKE_COMMAND} -E env CARGO_TARGET_DIR=${HDDS_CARGO_TARGET_ROOT}
          cargo build --manifest-path ${HDDS_PROJECT_ROOT}/Cargo.toml -p rmw-hdds
          ${HDDS_CARGO_FLAGS} ${HDDS_CARGO_NET_FLAGS} ${HDDS_CARGO_FEATURES}
  WORKING_DIRECTORY ${HDDS_PROJECT_ROOT}
  COMMENT "Building rmw-hdds (${HDDS_RUST_PROFILE}) via Cargo into ${HDDS_CARGO_TARGET_ROOT}"
  VERBATIM
)

add_custom_target(rmw_hdds_rust_build ALL DEPENDS ${HDDS_RUST_LIB})

add_library(rmw_hdds_rust STATIC IMPORTED GLOBAL)
set_target_properties(rmw_hdds_rust PROPERTIES IMPORTED_LOCATION ${HDDS_RUST_LIB})
add_dependencies(rmw_hdds_rust rmw_hdds_rust_build)

add_library(hdds_c STATIC IMPORTED GLOBAL)
set_target_properties(hdds_c PROPERTIES IMPORTED_LOCATION ${HDDS_C_LIB})
add_dependencies(hdds_c rmw_hdds_rust_build)

# Every rmw_* entry point of the Rust static library must survive the link:
# rmw_implementation dlopen()s this .so and looks the symbols up by name, so a
# symbol nothing in this package references would otherwise be dropped.
# $<LINK_LIBRARY:WHOLE_ARCHIVE,...> is CMake >= 3.24 and the Humble and Iron
# images ship cmake 3.22.1, so fall back to the linker flags directly.
if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.24")
  set(HDDS_RUST_WHOLE_ARCHIVE "$<LINK_LIBRARY:WHOLE_ARCHIVE,rmw_hdds_rust>")
else()
  set(HDDS_RUST_WHOLE_ARCHIVE
    -Wl,--whole-archive ${HDDS_RUST_LIB} -Wl,--no-whole-archive)
endif()

target_link_libraries(${PROJECT_NAME}
  ${HDDS_RUST_WHOLE_ARCHIVE}
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

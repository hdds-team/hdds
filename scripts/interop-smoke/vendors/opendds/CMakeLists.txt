cmake_minimum_required(VERSION 3.16)
project(opendds_interop_app CXX)

# find_package(OpenDDS) resolves against the source tree via the
# ACE_ROOT/TAO_ROOT/DDS_ROOT/PATH environment set by sourcing the
# generated setenv.sh (see the Dockerfile), per OpenDDS's own CMake
# integration docs (docs/devguide/building/cmake.rst).
find_package(OpenDDS REQUIRED)

# IDL TypeSupport library, same pattern as OpenDDS's own Messenger
# devguide example. InteropPing.idl has no @topic annotation (the
# canonical IDL is shared across all three vendors and kept annotation-
# minimal), and OpenDDS treats all types as nested by default, so
# --no-default-nested makes the keyed struct a usable topic type without
# needing a vendor-specific edit to the shared IDL file.
add_library(interop_idl)
opendds_target_sources(interop_idl
    PUBLIC
        "idl/InteropPing.idl"
    OPENDDS_IDL_OPTIONS
        --no-default-nested
    TAO_IDL_OPTIONS
        --idl-version 4
)
target_link_libraries(interop_idl PUBLIC OpenDDS::Dcps)

add_executable(opendds_app src/opendds_app.cpp)
target_link_libraries(opendds_app
    OpenDDS::Dcps
    OpenDDS::Rtps
    OpenDDS::Rtps_Udp
    interop_idl
)

install(TARGETS opendds_app DESTINATION bin)

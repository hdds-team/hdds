cmake_minimum_required(VERSION 3.16)
project(cyclonedds_interop_smoke C)

list(APPEND CMAKE_PREFIX_PATH "/opt/cyclonedds")
find_package(CycloneDDS REQUIRED)

idlc_generate(TARGET InteropPing_lib FILES idl/InteropPing.idl WARNINGS no-implicit-extensibility)

add_executable(cyclonedds_app src/interop_app.c)
target_link_libraries(cyclonedds_app PRIVATE CycloneDDS::ddsc InteropPing_lib)

install(TARGETS cyclonedds_app DESTINATION bin)

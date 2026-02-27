# sdk/c/examples/CMakeLists.txt
# Builds all HDDS C SDK examples.

set(EXAMPLES
    version_info
    hello_world
    qos_demo
    waitset_demo
    telemetry_demo
)

foreach(example ${EXAMPLES})
    add_executable(${example} ${example}.c)
    target_link_libraries(${example} PRIVATE hdds::c)
endforeach()
